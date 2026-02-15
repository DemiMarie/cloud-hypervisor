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
use std::io::ErrorKind;
use std::mem::{MaybeUninit, offset_of};
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
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
use vhost::vhost_user::Error;
use vhost_guest::{
    BackendRequestQueuePair, Direction, FrontendRequestQueuePair, IoEventFds, Mapping, QueuePair,
    Region, Translate, VM, VirtioVhostGuestQueuePair,
};
use vm_allocator::AddressAllocator;
use vm_memory::{ByteValued, GuestAddress, Le16, Le32};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::{
    ActivateResult, ActivationContext, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterrupt, VirtioInterruptType,
};

/// Backend is ready.
const VHOST_GUEST_BACKEND_STATUS_UP: u16 = 1;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VirtioVhostGuestConfig {
    /// The maximum number of vhost-user queues that are supported.
    pub max_queues: Le32,
    /// The maximum vhost-user message size supported.
    pub max_message_size: Le32,
    /// The maximum size of a message on a migration queue, or 0 if
    /// migration queues are not supported.
    pub max_migration_message_size: Le32,
    /// The maximum number of chained Rx descriptors.
    pub max_chained_rx_descriptors: Le16,
    /// The maximum number of changed Tx descriptors.
    pub max_chained_tx_descriptors: Le16,
    /// The device ID.
    pub uuid: [u8; 16],
    /// The type of the implemented device.
    pub device_type: Le16,
    /// Status
    pub status: Le16,
}

const _: () = assert!(
    size_of::<VirtioVhostGuestConfig>() == size_of::<u32>() * 3 + size_of::<u16>() * 4 + 16
);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_queues) == 0);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_message_size) == 4);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_migration_message_size) == 8);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_chained_rx_descriptors) == 12);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_chained_tx_descriptors) == 14);
const _: () = assert!(offset_of!(VirtioVhostGuestConfig, max_chained_tx_descriptors) == 14);

// SAFETY: The above static assertions check that the size
// is exactly the minimum needed to hold all possible values.
// Therefore, there cannot be any padding or invalid values.
unsafe impl ByteValued for VirtioVhostGuestConfig {}

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

const INCOMING_CONNECTION_FROM_FRONTEND: u16 = 30;
const BACKEND_UP: u16 = 31;
const MIN_KICK_EVENT: u16 = 32;

// The most complex part of this struct is the threading model.
// Implementations should use one thread per queue, rather than
// being single-threaded.
pub struct Backend {}

struct InternalAllocator(AddressAllocator);
impl vhost_guest::Allocator for InternalAllocator {
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
    epoll_fd: Option<BorrowedFd<'static>>,
    drv_aux_notification_eventfds: [Option<EventFd>; 256],
}

impl Drop for InternalVM {
    fn drop(&mut self) {
        let borrowed_fd = self.epoll_fd.unwrap();
        for fd in self
            .drv_aux_notification_eventfds
            .iter()
            .filter_map(Option::as_ref)
        {
            epoll_del(borrowed_fd, fd);
        }
    }
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

    fn register_vring_kick(&mut self, fd: Option<EventFd>, queue: u8) -> io::Result<()> {
        let &borrowed_fd = self.epoll_fd.as_ref().unwrap();
        if let Some(old_kick_fd) = self.drv_aux_notification_eventfds[usize::from(queue)].take() {
            // The API is unsound.
            #[allow(unused_unsafe)]
            // SAFETY: FDs are valid.
            epoll_del(borrowed_fd, &old_kick_fd);
        }
        if let Some(new_kick_fd) = fd.as_ref() {
            // Most errors can't happen, as the FD must be an eventfd.
            // This is checked by the wrapper code.
            epoll_add(
                borrowed_fd,
                new_kick_fd,
                u64::from(queue) + u64::from(MIN_KICK_EVENT),
            )?;
            self.drv_aux_notification_eventfds[usize::from(queue)] = fd;
        }
        Ok(())
    }

    fn backend_request_socket(&mut self, socket: UnixStream) {
        self.backend_socket = Some(socket);
    }
}

fn epoll_del(epoll_fd: BorrowedFd<'_>, fd_to_del: &EventFd) {
    // The API is unsound.
    #[allow(unused_unsafe)]
    // SAFETY: FDs are valid.
    unsafe {
        epoll::ctl(
            epoll_fd.as_raw_fd(),
            ControlOptions::EPOLL_CTL_DEL,
            fd_to_del.as_raw_fd(),
            epoll::Event::new(epoll::Events::empty(), 0),
        )
    }
    .expect("caller passes valid and registered FD");
}

fn epoll_add(epoll_fd: BorrowedFd<'_>, fd_to_add: &EventFd, event: u64) -> Result<(), io::Error> {
    epoll::ctl(
        epoll_fd.as_raw_fd(),
        ControlOptions::EPOLL_CTL_ADD,
        fd_to_add.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN | epoll::Events::EPOLLRDHUP, event),
    )
}

#[derive(Clone, Copy)]
enum RequestSender {
    Frontend,
    Backend,
}

fn register_socket(
    helper: &mut EpollHelper,
    socket: &UnixStream,
    direction: RequestSender,
    needs_reset: &mut bool,
) -> Result<(), io::Error> {
    let (inbound, outbound) = match direction {
        RequestSender::Backend => (F2B_REPLY_READABLE, B2F_REQUEST_SENDABLE),
        RequestSender::Frontend => (F2B_REQUEST_READABLE, B2F_REPLY_SENDABLE),
    };
    let mut conv = move |e| {
        *needs_reset = true;
        match e {
            EpollHelperError::Ctl(e) => Error::ReqHandlerError(e),
            _ => unreachable!(),
        }
    };
    helper
        .add_event(socket.as_raw_fd(), inbound)
        .map_err(&mut conv)?;
    helper
        .add_event_custom(socket.as_raw_fd(), outbound, epoll::Events::EPOLLOUT)
        .map_err(&mut conv)?;
    Ok(())
}

struct VhostGuestEpollHandler {
    frontend_requests: FrontendRequestQueuePair<InternalAllocator, InternalVM>,
    backend_requests: BackendRequestQueuePair,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Box<dyn AccessPlatform>>,
    needs_reset: bool,
    seen_listener: bool,
    seen_accept: bool,
    accept_evt: Arc<(EventFd, UnixListener)>,
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
    fds: &vhost_guest::Fds,
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

impl VhostGuestEpollHandler {
    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event_custom(
            self.accept_evt.0.as_raw_fd(),
            BACKEND_UP,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLONESHOT,
        )?;
        helper.add_event_custom(
            self.accept_evt.1.as_raw_fd(),
            INCOMING_CONNECTION_FROM_FRONTEND,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLONESHOT,
        )?;
        register_epoll_events(
            &mut helper,
            &self.frontend_requests.fds(),
            F2B_REQUEST_QUEUE_SPACE_AVAIL,
        )?;
        register_epoll_events(
            &mut helper,
            &self.backend_requests.fds(),
            F2B_REPLY_QUEUE_SPACE_AVAIL,
        )?;
        // SAFETY: The 'static lifetime on the returned FD is a lie. However,
        // we have a unique reference to self so nobody else can access the fd
        // through this reference. Furthermore, the FD will stay alive until
        // after self.fd is set to None, which happens even in the event of
        // a panic. So no code can observe the FD after it is dropped.
        self.frontend_requests.vm_mut().epoll_fd =
            Some(unsafe { BorrowedFd::borrow_raw(helper.as_raw_fd()) });
        let p = panic::catch_unwind(AssertUnwindSafe(|| helper.run(paused, paused_sync, self)));
        self.frontend_requests.vm_mut().epoll_fd = None;
        match p {
            Ok(good) => good,
            Err(panicked) => panic::resume_unwind(panicked),
        }
    }
    fn check_accept(&mut self, helper: &mut EpollHelper) -> Result<(), EpollHelperError> {
        match self.accept_evt.1.accept() {
            Ok((sock, _)) => {
                register_socket(
                    helper,
                    &sock,
                    RequestSender::Frontend,
                    &mut self.needs_reset,
                )
                .map_err(EpollHelperError::IoError)?;
                assert!(self.frontend_requests.set_fd(sock));
                Ok(())
            }
            // Oneshot, rearm
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock) => helper
                .add_event_custom(
                    self.accept_evt.1.as_raw_fd(),
                    INCOMING_CONNECTION_FROM_FRONTEND,
                    epoll::Events::EPOLLIN | epoll::Events::EPOLLONESHOT,
                )
                .inspect_err(|_| self.needs_reset = true),
            Err(e) => {
                error!("Failed to accept socket, setting DEVICE_NEEDS_RESET.  Error {e}.");
                self.needs_reset = true;
                Ok(())
            }
        }
    }

    fn process_event(
        &mut self,
        ev_type: u16,
        helper: &mut EpollHelper,
    ) -> Result<(), EpollHelperError> {
        // Avoid Option::map here.  The compiler can't figure out the types
        // and produces confusing errors.

        // TODO: inline work queue
        let mut queue = VecDeque::with_capacity(6);
        queue.push_back(ev_type);
        let epoll_fd = self
            .frontend_requests
            .vm()
            .epoll_fd
            .expect("has fd")
            .as_raw_fd();
        while let Some(ev_type) = queue.pop_front() {
            let mut process = |direction, queue_pair: &mut dyn QueuePair, ev_type: u16, offset| {
                let translate: Option<Translate> = match self.access_platform.as_deref() {
                    None => None,
                    Some(a) => Some(&|base, size| {
                        a.translate_gva(base.0, size.try_into().unwrap())
                            .map(GuestAddress)
                    }),
                };
                let queue: &mut VecDeque<u16> = &mut queue;
                let (fd, produced_something) = queue_pair
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
                INCOMING_CONNECTION_FROM_FRONTEND => {
                    self.seen_listener = true;
                    if self.seen_accept {
                        self.check_accept(helper)?;
                    }
                    continue;
                }
                BACKEND_UP => {
                    self.seen_accept = true;
                    if self.seen_listener {
                        self.check_accept(helper)?;
                    }
                    continue;
                }
                // Frontend has sent requests, or backend has read them.
                F2B_REQUEST_QUEUE_SPACE_AVAIL | F2B_REQUEST_READABLE => {
                    process(Direction::Inbound, &mut self.frontend_requests, ev_type, 1)?
                }
                // Backend has sent replies, or frontend has read them.
                B2F_REPLY_AVAILABLE | B2F_REPLY_SENDABLE => {
                    process(Direction::Outbound, &mut self.frontend_requests, ev_type, 2)?
                }
                // Frontend has sent replies, or backend has read them.
                F2B_REPLY_QUEUE_SPACE_AVAIL | F2B_REPLY_READABLE => {
                    process(Direction::Inbound, &mut self.backend_requests, ev_type, 3)?
                }
                // Backend has sent requests, or frontend has read them.
                B2F_REQUEST_AVAILABLE | B2F_REQUEST_SENDABLE => {
                    process(Direction::Outbound, &mut self.backend_requests, ev_type, 4)?
                }
                evt if (MIN_KICK_EVENT..MIN_KICK_EVENT + 256).contains(&evt) => {
                    let vm = self.frontend_requests.vm_mut();
                    let event_fd_index = usize::from(evt - MIN_KICK_EVENT);
                    let event_fd = vm.drv_aux_notification_eventfds[event_fd_index]
                        .as_ref()
                        .unwrap();
                    const EVENTFD_BYTES: usize = 8;
                    // SAFETY: passing uninitialized memory to correctly-used kernel API
                    // that doesn't read from it.
                    match unsafe {
                        let mut buf = [MaybeUninit::<u8>::uninit(); EVENTFD_BYTES];
                        let ptr: *mut libc::c_void = (&raw mut buf).cast();
                        let junk = libc::iovec {
                            iov_base: ptr,
                            iov_len: EVENTFD_BYTES,
                        };
                        libc::preadv2(
                            event_fd.as_raw_fd(),
                            &raw const junk,
                            1,
                            0,
                            libc::RWF_NOWAIT,
                        )
                    } {
                        -1 => {
                            let e = io::Error::last_os_error();
                            if e.raw_os_error() != Some(libc::EAGAIN) {
                                warn!("Error reading from peer FD: {e}");
                            }
                        }
                        e => assert!(e >= 0),
                    }
                    vm.interrupt_cb
                        .trigger(VirtioInterruptType::DrvAuxNotification(
                            evt - MIN_KICK_EVENT,
                        ))
                        .map_err(|e| {
                            error!("Error triggering interrupt: {e}");
                            EpollHelperError::HandleEvent(anyhow!(e))
                        })?;
                    None
                }
                _ => {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unknown event for virtio-vhost-guest"
                    )));
                }
            };
            if let Some(queue) = res {
                self.frontend_requests
                    .vm_mut()
                    .interrupt_cb
                    .trigger(VirtioInterruptType::Queue(queue))
                    .map_err(|e| {
                        error!("Error triggering interrupt: {e}");
                        EpollHelperError::HandleEvent(anyhow!(e))
                    })?;
            }
            if let Some(socket) = self.frontend_requests.vm_mut().backend_socket.take() {
                register_socket(
                    helper,
                    &socket,
                    RequestSender::Backend,
                    &mut self.needs_reset,
                )
                .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
                self.backend_requests
                    .set_socket(socket)
                    .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
            }
        }
        Ok(())
    }
}

impl EpollHelperHandler for VhostGuestEpollHandler {
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
pub struct VirtioVhostGuestState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioVhostGuestConfig,
}

const _: () = assert!(
    size_of::<VirtioVhostGuestState>()
        == size_of::<u64>() * 2 + size_of::<VirtioVhostGuestConfig>()
);

// SAFETY: VirtioVhostGuestState has no padding and all values are valid.
unsafe impl ByteValued for VirtioVhostGuestState {}

// Virtio device backend
pub struct VhostGuest {
    common: VirtioCommon,
    id: String,
    /// Configuration space.
    config: VirtioVhostGuestConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    max_queues: u8,
    region: Region,
    #[expect(dead_code)]
    msix_fds: [Option<OwnedFd>; MSIX_ARRAY_SIZE],
    #[expect(dead_code)]
    statuses: [bool; MSIX_ARRAY_SIZE],
    ioeventfds: Arc<Mutex<IoEventFds>>,
    vm: Option<Arc<dyn hypervisor::Vm>>,
    access_platform: Option<Box<dyn AccessPlatform>>,
    accept_evt: Arc<(EventFd, UnixListener)>,
}

impl VhostGuest {
    // Create a new virtio-vhost-guest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VirtioVhostGuestState>,
        max_queues: u32,
        uuid: [u8; 16],
        device_type: u16,
        listener: UnixListener,
        vm: Arc<dyn hypervisor::Vm>,
        region: Region,
        access_platform: Option<Box<dyn AccessPlatform>>,
    ) -> io::Result<Self> {
        if max_queues > 255 {
            warn!("Cannot support {max_queues} queues, limit is 255");
            return Err(io::Error::other(format!(
                "Too many queues: {max_queues} > 255"
            )));
        }
        let accept_evt = Arc::new((
            EventFd::new(libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)?,
            listener,
        ));
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
            let v = VirtioVhostGuestConfig {
                max_queues: max_queues.into(),
                max_message_size: 1024.into(),
                max_migration_message_size: 0.into(),
                max_chained_rx_descriptors: 1.into(),
                max_chained_tx_descriptors: 1.into(),
                uuid,
                device_type: device_type.into(),
                status: 0.into(),
            };
            (1u64 << VIRTIO_F_VERSION_1, 0, v, false)
        };
        Ok(VhostGuest {
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
            statuses: [false; MSIX_ARRAY_SIZE],
            msix_fds: [const { None }; MSIX_ARRAY_SIZE],
            region,
            vm: Some(vm),
            ioeventfds,
            access_platform,
            accept_evt,
        })
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }

    fn set_device_type(&mut self, device_type: u16) {
        let old_device_type = u16::from(self.config.device_type);
        if old_device_type == 0 {
            self.config.device_type = device_type.into();
        } else {
            warn!(
                "Guest tried to write device type of {device_type} but it's already {old_device_type}"
            );
            // TODO: set NEEDS_RESET
        }
    }

    fn set_status(&mut self, status: u16) {
        if status == VHOST_GUEST_BACKEND_STATUS_UP {
            self.config.status =
                (u16::from(self.config.status) | VHOST_GUEST_BACKEND_STATUS_UP).into();
        } else {
            warn!("Guest tried to write bad status bit");
        }
    }
}

impl Drop for VhostGuest {
    fn drop(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

#[expect(dead_code)]
const MSIX_ARRAY_OFFSET: usize = 512;
const MSIX_ARRAY_SIZE: usize = 256;

impl VirtioDevice for VhostGuest {
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut bad = false;
        if offset == offset_of!(VirtioVhostGuestConfig, device_type) as u64 {
            if data.len() == 4 {
                self.set_device_type(u16::from_le_bytes(data[..2].try_into().unwrap()));
                self.set_status(u16::from_le_bytes(data[2..].try_into().unwrap()));
            } else if data.len() == 2 {
                self.set_device_type(u16::from_le_bytes(data.try_into().unwrap()));
            } else {
                bad = true;
            }
        } else if offset == offset_of!(VirtioVhostGuestConfig, status) as u64 && data.len() == 2 {
            self.set_status(u16::from_le_bytes(data.try_into().unwrap()));
        } else {
            bad = true;
        }
        if bad {
            trace!(
                "driver bug: write of {} bytes to offset {offset}",
                data.len()
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
        self.common.activate(&queues, Arc::clone(&interrupt_cb))?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;
        let (_, frontend_request_queue, frontend_request_queue_evt) = queues.remove(0);
        let (_, backend_reply_queue, backend_reply_queue_evt) = queues.remove(0);
        let (_, frontend_reply_queue, frontend_reply_queue_evt) = queues.remove(0);
        let (_, backend_request_queue, backend_request_queue_evt) = queues.remove(0);
        let queue_pair = VirtioVhostGuestQueuePair::new(
            (frontend_request_queue, frontend_request_queue_evt),
            (backend_reply_queue, backend_reply_queue_evt),
            None,
            mem.clone(),
        );
        let backend_request_queue_pair = VirtioVhostGuestQueuePair::new(
            (frontend_reply_queue, frontend_reply_queue_evt),
            (backend_request_queue, backend_request_queue_evt),
            None,
            mem.clone(),
        );
        let mapping = Mapping::new(Arc::clone(&self.region));
        let vm = InternalVM {
            vm: self.vm.take().expect("double activate"),
            interrupt_cb: Arc::clone(&interrupt_cb),
            backend_socket: None,
            epoll_fd: None,
            drv_aux_notification_eventfds: [const { None }; 256],
        };
        let mut handler = VhostGuestEpollHandler {
            kill_evt,
            pause_evt,
            frontend_requests: FrontendRequestQueuePair::new(
                queue_pair,
                mapping,
                Arc::clone(&self.ioeventfds),
                self.max_queues,
                vm,
            ),
            backend_requests: BackendRequestQueuePair::new(backend_request_queue_pair),
            needs_reset: false,
            access_platform: self.access_platform.take(),
            accept_evt: Arc::clone(&self.accept_evt),
            seen_listener: false,
            seen_accept: false,
        };

        let paused = Arc::clone(&self.common.paused);
        let paused_sync = self.common.paused_sync.clone();

        self.common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostGuest,
            &self.exit_evt,
            Arc::clone(&device_status),
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
