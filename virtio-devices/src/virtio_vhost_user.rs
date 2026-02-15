// Copyright (c) 2020 Ant Financial
// Copyright (c) 2026 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implements a vhost-user device backend.  Documentation can be found at:
// https://stefanha.github.io/virtio/vhost-user-slave.html

use std::collections::VecDeque;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::{io, result};

use anyhow::anyhow;
use epoll::{ControlOptions, Event};
use event_monitor::event;
use hypervisor::IoEventAddress;
use log::{error, info, trace, warn};
use seccompiler::SeccompAction;
use vhost::vhost_user::{self, Error};
use virtio_vhost_user::{
    BackendRequestQueuePair, Direction, FrontendRequestQueuePair, IoEventFds, Mapping, QueuePair,
    Region, Translate, VM, VirtioVhostUserQueuePair,
};
use vm_allocator::AddressAllocator;
use vm_memory::{ByteValued, GuestAddress, Le32};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::{
    ActivateResult, ActivationContext, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterrupt, VirtioInterruptType,
};

#[allow(unused)]
/// Not a valid device backend type.
const VIRTIO_DEVICE_BACKEND_TYPE_INVALID: u32 = 0;

/// vhost-user device backend
const VIRTIO_DEVICE_BACKEND_TYPE_VHOST_USER: u32 = 1;

/// Backend is not yet ready.
const VIRTIO_DEVICE_BACKEND_STATUS_DOWN: u32 = 0;

/// Backend is ready.
const VIRTIO_DEVICE_BACKEND_STATUS_UP: u32 = 1;

/// Common virtio-device-backend configuration space fields.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VirtioDeviceBackendConfigCommon {
    /// The type of the device.  Must be 1 for a vhost-user device.
    pub device_type: Le32,
    /// The status of the device.  Always 0 at startup.  Set to 1 when ready.
    pub status: Le32,
    /// A UUID for the backend.
    pub uuid: [u8; 16],
}

// Le32 should be #[repr(transparent)] but isn't.  However,
// it has a single field, and that field is a u32.  Furthermore,
// it has exactly 2^32 valid values.  Therefore, there is no way
// that this can be represented as anything other than a u32 by the
// Pidgeonhole Principle.  Otherwise field access won't work.
const _: () = assert!(size_of::<Le32>() == size_of::<u32>());
const _: () = assert!(
    size_of::<VirtioDeviceBackendConfigCommon>() == size_of::<Le32>() * 2 + size_of::<[u8; 16]>()
);

/// Configuration space fields that are specific to vhost-user device backends.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct VirtioDeviceBackendConfigVhostUser {
    /// The maximum number of vhost-user queues that are supported.
    pub max_queues: Le32,
}

const _: () = assert!(size_of::<VirtioDeviceBackendConfigVhostUser>() == size_of::<Le32>());

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VirtioDeviceBackendConfig {
    pub common: VirtioDeviceBackendConfigCommon,
    pub vhost_user: VirtioDeviceBackendConfigVhostUser,
}

const _: () = assert!(
    size_of::<VirtioDeviceBackendConfig>()
        == size_of::<VirtioDeviceBackendConfigCommon>()
            + size_of::<VirtioDeviceBackendConfigVhostUser>()
);

// SAFETY: The above static assertions check that the size
// is exactly the minimum needed to hold all possible values.
// Therefore, there cannot be any padding or invalid values.
unsafe impl ByteValued for VirtioDeviceBackendConfig {}

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 6;

const F2B_REQUEST_QUEUE_SPACE_AVAIL: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::QueueIn as u16;
const B2F_REPLY_AVAILABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::QueueOut as u16;
const F2B_REQUEST_READABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::SocketIn as u16;
const B2F_REPLY_SENDABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::SocketOut as u16;

const F2B_REPLY_QUEUE_SPACE_AVAIL: u16 = F2B_REQUEST_QUEUE_SPACE_AVAIL + Events::Total as u16;
const B2F_REQUEST_AVAILABLE: u16 = B2F_REPLY_AVAILABLE + Events::Total as u16;
const F2B_REPLY_READABLE: u16 = F2B_REQUEST_READABLE + Events::Total as u16;
const B2F_REQUEST_SENDABLE: u16 = B2F_REPLY_SENDABLE + Events::Total as u16;

const INBOUND_MIGRATION_QUEUE_EVT: u16 = F2B_REQUEST_QUEUE_SPACE_AVAIL + (Events::Total as u16 * 2);
const OUTBOUND_MIGRATION_QUEUE_EVT: u16 = B2F_REPLY_AVAILABLE + (Events::Total as u16 * 2);
const INBOUND_MIGRATION_DATA_READABLE: u16 = F2B_REQUEST_READABLE + (Events::Total as u16 * 2);
const OUTBOUND_MIGRATION_DATA_WRITEABLE: u16 = B2F_REPLY_SENDABLE + (Events::Total as u16 * 2);

// The most complex part of this struct is the threading model.
// Implementations should use one thread per queue, rather than
// being single-threaded.
pub struct Backend {}

struct InternalAllocator(AddressAllocator);
impl virtio_vhost_user::Allocator for InternalAllocator {
    fn new(base: vm_memory::GuestAddress, size: u64) -> Self {
        Self(AddressAllocator::new(base, size).unwrap())
    }

    fn allocate(&mut self, size: u64) -> Option<vm_memory::GuestAddress> {
        self.0.allocate(None, size, None)
    }

    fn base(&self) -> vm_memory::GuestAddress {
        self.0.base()
    }
}

struct InternalVM {
    vm: Arc<dyn hypervisor::Vm>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    backend_socket: Option<UnixStream>,
    inbound_migration_fd: Option<OwnedFd>,
    outbound_migration_fd: Option<OwnedFd>,
    epoll_fd: Option<BorrowedFd<'static>>,
}

impl VM for InternalVM {
    fn register_ioevent(&mut self, fd: &EventFd, offset: u64) {
        self.vm
            .register_ioevent(fd, &IoEventAddress::Mmio(offset), None)
            .expect("TODO");
    }

    fn unregister_ioevent(&mut self, fd: EventFd, offset: u64) {
        self.vm
            .unregister_ioevent(&fd, &IoEventAddress::Mmio(offset))
            .expect("TODO");
    }

    fn register_vring_kick(&mut self, fd: Option<EventFd>, queue: u8) {
        self.interrupt_cb
            .set_notifier(u32::from(queue) + 4, fd, &*self.vm)
            .map_err(|e| {
                error!("Cannot set vring kick notifier: {e}");
                vhost_user::Error::BackendInternalError
            })
            .expect("TODO: handle error");
    }

    fn backend_request_socket(&mut self, socket: UnixStream) {
        self.backend_socket = Some(socket);
    }

    fn set_inbound_migration_fd(&mut self, fd: OwnedFd) -> Result<(), io::Error> {
        if self.inbound_migration_fd.is_some() {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Inbound migration FD already set",
            ))
        } else {
            epoll::ctl(
                self.epoll_fd.unwrap().as_raw_fd(),
                ControlOptions::EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                epoll::Event {
                    events: libc::EPOLLIN as _,
                    data: INBOUND_MIGRATION_DATA_READABLE as _,
                },
            )?;
            self.inbound_migration_fd = Some(fd);
            Ok(())
        }
    }

    fn set_outbound_migration_fd(&mut self, fd: OwnedFd) -> io::Result<()> {
        if self.outbound_migration_fd.is_some() {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Outbound migration FD already set",
            ))
        } else {
            epoll::ctl(
                self.epoll_fd.unwrap().as_raw_fd(),
                ControlOptions::EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                epoll::Event {
                    events: libc::EPOLLOUT as _,
                    data: OUTBOUND_MIGRATION_DATA_WRITEABLE as _,
                },
            )?;
            self.outbound_migration_fd = Some(fd);
            Ok(())
        }
    }
}

fn register_socket(helper: &mut EpollHelper, socket: &UnixStream) -> Result<(), io::Error> {
    fn conv(e: EpollHelperError) -> Error {
        match e {
            EpollHelperError::Ctl(e) => Error::ReqHandlerError(e),
            _ => unreachable!(),
        }
    }
    helper
        .add_event(socket.as_raw_fd(), F2B_REPLY_READABLE)
        .map_err(conv)?;
    helper
        .add_event_custom(
            socket.as_raw_fd(),
            B2F_REQUEST_SENDABLE,
            epoll::Events::EPOLLOUT,
        )
        .map_err(conv)?;
    Ok(())
}

struct VdbEpollHandler {
    frontend_request_queue_pair: FrontendRequestQueuePair<InternalAllocator, InternalVM>,
    backend_requests: BackendRequestQueuePair,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Box<dyn AccessPlatform>>,
    needs_reset: bool,
    #[expect(dead_code, reason = "not yet used")]
    outbound_migration_queue: virtio_queue::Queue,
    inbound_migration_queue_evt: EventFd,
    #[expect(dead_code, reason = "not yet used")]
    inbound_migration_queue: virtio_queue::Queue,
    outbound_migration_queue_evt: EventFd,
}

#[repr(u16)]
enum Events {
    QueueIn = 0,
    QueueOut = 1,
    SocketIn = 2,
    SocketOut = 3,
    Total = 4,
}

fn register_epoll_events(
    helper: &mut EpollHelper,
    fds: &virtio_vhost_user::Fds,
    base: u16,
) -> Result<(), EpollHelperError> {
    helper.add_event(fds.queue_in.as_raw_fd(), base + Events::QueueIn as u16)?;
    helper.add_event(fds.queue_out.as_raw_fd(), base + Events::QueueOut as u16)?;
    if let Some(socket) = &fds.socket {
        helper.add_event(socket.as_raw_fd(), base + Events::SocketIn as u16)?;
        helper.add_event_custom(
            socket.as_raw_fd(),
            base + Events::SocketOut as u16,
            epoll::Events::EPOLLOUT,
        )?;
    }
    Ok(())
}

impl VdbEpollHandler {
    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        // TODO: register inbound and outbound migration queues
        register_epoll_events(
            &mut helper,
            &self.frontend_request_queue_pair.fds(),
            F2B_REQUEST_QUEUE_SPACE_AVAIL,
        )?;
        register_epoll_events(
            &mut helper,
            &self.backend_requests.fds(),
            F2B_REPLY_QUEUE_SPACE_AVAIL,
        )?;
        helper.add_event_custom(
            self.inbound_migration_queue_evt.as_raw_fd(),
            INBOUND_MIGRATION_QUEUE_EVT,
            epoll::Events::EPOLLIN,
        )?;
        helper.add_event_custom(
            self.outbound_migration_queue_evt.as_raw_fd(),
            OUTBOUND_MIGRATION_QUEUE_EVT,
            epoll::Events::EPOLLIN,
        )?;
        // SAFETY: The 'static lifetime on the returned FD is a lie. However,
        // we have a unique reference to self so nobody else can access the fd
        // through this reference. Furthermore, the FD will stay alive until
        // after self.fd is set to None, which happens even in the event of
        // a panic. So no code can observe the FD after it is dropped.
        self.frontend_request_queue_pair.vm_mut().epoll_fd =
            Some(unsafe { BorrowedFd::borrow_raw(helper.as_raw_fd()) });
        let p = panic::catch_unwind(AssertUnwindSafe(|| helper.run(paused, paused_sync, self)));
        self.frontend_request_queue_pair.vm_mut().epoll_fd = None;
        match p {
            Ok(good) => good,
            Err(panicked) => panic::resume_unwind(panicked),
        }
    }

    fn process_event(
        &mut self,
        ev_type: u16,
        helper: &mut EpollHelper,
    ) -> Result<(), EpollHelperError> {
        // Avoid Option::map here.  The compiler can't figure out the types
        // and produces confusing errors.
        let translate: Option<Translate> = match self.access_platform.as_deref() {
            None => None,
            Some(a) => Some(&|base, size| {
                a.translate_gva(base.0, size.try_into().unwrap())
                    .map(GuestAddress)
            }),
        };

        // TODO: inline work queue
        let mut queue = VecDeque::with_capacity(6);
        queue.push_back(ev_type);
        let epoll_fd = self
            .frontend_request_queue_pair
            .vm()
            .epoll_fd
            .expect("has fd")
            .as_raw_fd();
        while let Some(ev_type) = queue.pop_front() {
            let mut process = |direction,
                               backend_request_queue_pair: &mut dyn QueuePair,
                               ev_type: u16,
                               offset| {
                let queue: &mut VecDeque<u16> = &mut queue;
                let (fd, produced_something) = backend_request_queue_pair
                    .process(translate, direction, 50)
                    .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
                if let Some((fd, direction)) = fd {
                    // SAFETY: FD is valid
                    let borrowed_fd = fd.as_raw_fd();
                    let events = match direction {
                        Direction::Inbound => epoll::Events::EPOLLIN,
                        Direction::Outbound => epoll::Events::EPOLLOUT,
                    };
                    epoll::ctl(
                        epoll_fd,
                        ControlOptions::EPOLL_CTL_ADD,
                        borrowed_fd,
                        Event::new(epoll::Events::EPOLLET | events, ev_type.into()),
                    )
                    .expect("epoll_ctl failed");
                } else {
                    queue.push_back(ev_type);
                }
                Ok(if produced_something {
                    Some(offset)
                } else {
                    None
                })
            };
            let res = match ev_type {
                // Frontend has sent requests, or backend has read them.
                F2B_REQUEST_QUEUE_SPACE_AVAIL | F2B_REQUEST_READABLE => process(
                    Direction::Inbound,
                    &mut self.frontend_request_queue_pair,
                    ev_type,
                    1,
                )?,
                // Backend has sent replies, or frontend has read them.
                B2F_REPLY_AVAILABLE | B2F_REPLY_SENDABLE => process(
                    Direction::Outbound,
                    &mut self.frontend_request_queue_pair,
                    ev_type,
                    2,
                )?,
                // Frontend has sent replies, or backend has read them.
                F2B_REPLY_QUEUE_SPACE_AVAIL | F2B_REPLY_READABLE => {
                    process(Direction::Inbound, &mut self.backend_requests, ev_type, 3)?
                }
                // Backend has sent requests, or frontend has read them.
                B2F_REQUEST_AVAILABLE | B2F_REQUEST_SENDABLE => {
                    process(Direction::Outbound, &mut self.backend_requests, ev_type, 4)?
                }
                OUTBOUND_MIGRATION_QUEUE_EVT
                | OUTBOUND_MIGRATION_DATA_WRITEABLE
                | INBOUND_MIGRATION_DATA_READABLE
                | INBOUND_MIGRATION_QUEUE_EVT => {
                    error!("NOT IMPLEMENTED: migration data handling");
                    return Ok(());
                }
                _ => {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unknown event for virtio-vdb"
                    )));
                }
            };
            if let Some(queue) = res {
                self.frontend_request_queue_pair
                    .vm_mut()
                    .interrupt_cb
                    .trigger(VirtioInterruptType::Queue(queue))
                    .map_err(|e| {
                        error!("Error triggering interrupt: {e}");
                        EpollHelperError::HandleEvent(anyhow!(e))
                    })?;
            }
            if let Some(socket) = self
                .frontend_request_queue_pair
                .vm_mut()
                .backend_socket
                .take()
            {
                register_socket(helper, &socket)
                    .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
                self.backend_requests
                    .set_socket(socket)
                    .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
            }
        }
        Ok(())
    }
}

impl EpollHelperHandler for VdbEpollHandler {
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        if self.needs_reset {
            return Err(EpollHelperError::HandleEvent(anyhow!(
                "Needs reset, cannot handle events"
            )));
        }
        self.process_event(ev_type, helper)
            .inspect_err(|_| self.needs_reset = true)
    }
}

#[derive(Copy, Clone)]
#[repr(packed, C)]
pub struct VirtioVhostUserState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioDeviceBackendConfig,
}

const _: () = assert!(
    size_of::<VirtioVhostUserState>()
        == size_of::<u64>() * 2 + size_of::<VirtioDeviceBackendConfig>()
);

// SAFETY: VdbState has no padding and all values are valid.
unsafe impl ByteValued for VirtioVhostUserState {}

// Virtio device backend
pub struct VirtioVhostUser {
    common: VirtioCommon,
    id: String,
    config: VirtioDeviceBackendConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    max_queues: u8,
    region: Region,
    listener: Option<UnixStream>,
    msix_fds: [Option<OwnedFd>; MSIX_ARRAY_SIZE],
    statuses: [bool; MSIX_ARRAY_SIZE],
    ioeventfds: Arc<Mutex<IoEventFds>>,
    vm: Option<Arc<dyn hypervisor::Vm>>,
    access_platform: Option<Box<dyn AccessPlatform>>,
}

impl VirtioVhostUser {
    // Create a new virtio-vdb.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VirtioVhostUserState>,
        max_queues: u32,
        uuid: [u8; 16],
        listener: UnixStream,
        vm: Arc<dyn hypervisor::Vm>,
        region: Region,
        access_platform: Option<Box<dyn AccessPlatform>>,
    ) -> io::Result<Self> {
        if max_queues > 255 {
            warn!("Cannot support {max_queues} queues, limit is 255");
            todo!()
        }
        let queue_sizes = vec![QUEUE_SIZE; NUM_QUEUES];
        let num_fds = (max_queues * 2 + 1) as usize;
        let mut ioeventfds = Vec::with_capacity(num_fds);
        for _ in 0..num_fds {
            ioeventfds.push(None);
        }
        let ioeventfds = Arc::new(Mutex::new(IoEventFds {
            offset: 0,
            fds: ioeventfds,
        }));

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-vhost-user {id}");
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let v = VirtioDeviceBackendConfig {
                common: VirtioDeviceBackendConfigCommon {
                    device_type: Le32::from(VIRTIO_DEVICE_BACKEND_TYPE_VHOST_USER),
                    status: Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_DOWN),
                    uuid,
                },
                vhost_user: VirtioDeviceBackendConfigVhostUser {
                    max_queues: Le32::from(max_queues),
                },
            };
            (1u64 << VIRTIO_F_VERSION_1, 0, v, false)
        };
        Ok(VirtioVhostUser {
            common: VirtioCommon {
                device_type: VirtioDeviceType::VhostUser as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes,
                min_queues: NUM_QUEUES as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            max_queues: max_queues as _,
            listener: Some(listener),
            statuses: [false; MSIX_ARRAY_SIZE],
            msix_fds: [const { None }; MSIX_ARRAY_SIZE],
            region,
            vm: Some(vm),
            ioeventfds,
            access_platform,
        })
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for VirtioVhostUser {
    fn drop(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

const MSIX_ARRAY_OFFSET: usize = 512;
const MSIX_ARRAY_SIZE: usize = 256;

impl VirtioDevice for VirtioVhostUser {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn doorbells_max(&self) -> u16 {
        u16::from(self.max_queues) * 2 + 1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if offset == 4
            && let Ok(v) = data.try_into().map(u32::from_le_bytes)
        {
            match v {
                1 => self.config.common.status = Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_UP),
                0 => self.config.common.status = Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_DOWN),
                _ => warn!("Invalid value {v} for VDB device status"),
            }
            return;
        }
        if offset & 1 == 0
            && let Ok(offset) = usize::try_from(offset)
            && (MSIX_ARRAY_OFFSET..MSIX_ARRAY_OFFSET + MSIX_ARRAY_SIZE * 2).contains(&offset)
            && let Ok(value) = data.try_into().map(u16::from_le_bytes)
        {
            let offset = (offset - MSIX_ARRAY_OFFSET) >> 1;
            let fd = &self.msix_fds[offset];
            let status = self.statuses[offset];
            trace!(
                "VDB driver wrote {value} to index {offset} in MSI-X activity array. Status: {}. FD {}.",
                if status { "enabled" } else { "disabled" },
                if fd.is_some() { "present" } else { "absent" }
            );
        }
    }

    fn activate(
        &mut self,
        ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        }: crate::ActivationContext,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;

        let (_, frontend_request_queue, frontend_request_queue_evt) = queues.remove(0);
        let (_, frontend_reply_queue, frontend_reply_queue_evt) = queues.remove(0);
        let (_, backend_reply_queue, backend_reply_queue_evt) = queues.remove(0);
        let (_, backend_request_queue, backend_request_queue_evt) = queues.remove(0);
        let (_, inbound_migration_queue, inbound_migration_queue_evt) = queues.remove(0);
        let (_, outbound_migration_queue, outbound_migration_queue_evt) = queues.remove(0);
        let queue_pair = VirtioVhostUserQueuePair::new(
            frontend_request_queue,
            backend_reply_queue,
            frontend_request_queue_evt,
            backend_reply_queue_evt,
            Some(self.listener.take().expect("double activate")),
            mem.clone(),
        );
        let backend_request_queue_pair = VirtioVhostUserQueuePair::new(
            backend_request_queue,
            frontend_reply_queue,
            backend_request_queue_evt,
            frontend_reply_queue_evt,
            None,
            mem.clone(),
        );
        let mapping = Mapping::new(self.region.clone());
        let vm = InternalVM {
            vm: self.vm.take().expect("double activate"),
            interrupt_cb: interrupt_cb.clone(),
            backend_socket: None,
            inbound_migration_fd: None,
            outbound_migration_fd: None,
            epoll_fd: None,
        };
        let mut handler = VdbEpollHandler {
            kill_evt,
            pause_evt,
            frontend_request_queue_pair: FrontendRequestQueuePair::new(
                queue_pair,
                mapping,
                self.ioeventfds.clone(),
                self.max_queues,
                vm,
            ),
            backend_requests: BackendRequestQueuePair::new(backend_request_queue_pair),
            needs_reset: false,
            access_platform: self.access_platform.take(),
            inbound_migration_queue,
            inbound_migration_queue_evt,
            outbound_migration_queue,
            outbound_migration_queue_evt,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        self.common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostUser,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
    }
}
