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

use core::slice;
use std::io::{self};
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::*;
use std::sync::{Arc, Mutex};

use log::{error, warn};
use queue_pair::{FdRearm, VhostUserMsgHeader};
use vhost::vhost_user::message::{
    FrontendReq, MAX_MSG_SIZE, VhostUserHeaderFlag, VhostUserLog, VhostUserMemory,
    VhostUserMemoryRegion, VhostUserProtocolFeatures, VhostUserSingleMemoryRegion,
    VhostUserTransferDeviceState,
};
use vhost::vhost_user::{self, Error};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::eventfd_checker::check_is_stream_socket;
use super::mapping::Allocator;
use super::queue_pair::{self, Translate};
use crate::eventfd_checker::{self, EventfdChecker};
use crate::queue_pair::Fds;
use crate::{Direction, extract_fd, read_bytevalued};

pub const SUPPORTED_PROTOCOL_FEATURES: VhostUserProtocolFeatures = VhostUserProtocolFeatures::MQ
    .union(VhostUserProtocolFeatures::LOG_SHMFD)
    .union(VhostUserProtocolFeatures::RARP)
    .union(VhostUserProtocolFeatures::MTU)
    .union(VhostUserProtocolFeatures::CROSS_ENDIAN)
    .union(VhostUserProtocolFeatures::CRYPTO_SESSION)
    .union(VhostUserProtocolFeatures::CONFIG)
    .union(VhostUserProtocolFeatures::RESET_DEVICE)
    .union(VhostUserProtocolFeatures::MTU)
    .union(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)
    .union(VhostUserProtocolFeatures::STATUS);

fn validate_reply(hdr: VhostUserMsgHeader, buf: &mut [u8]) -> Result<(), Error> {
    let flags = hdr.flags;
    if flags & 255 != 5 {
        error!("virtio-vhost-user: Wrong flags: 0x{flags:b}");
        return Err(Error::InvalidMessage);
    }
    if hdr.request == u32::from(FrontendReq::GET_PROTOCOL_FEATURES) {
        let Ok(features) = <[u8; 8]>::try_from(&buf[..]) else {
            error!("Bad reply to GET_PROTOCOL_FEATURES");
            return Err(Error::InvalidMessage);
        };
        let features = u64::from_ne_bytes(features) & SUPPORTED_PROTOCOL_FEATURES.bits();
        buf.copy_from_slice(features.as_slice());
    }
    Ok(())
}

pub struct FrontendRequestQueuePair<T: Allocator, U: VM> {
    queue_pair: queue_pair::VirtioVhostUserQueuePair,
    internals: FrontendRequestQueuePairInternals<T, U>,
}

pub struct IoEventFds {
    pub offset: u64,
    pub fds: Vec<Option<EventFd>>,
}

pub trait VM {
    fn register_ioevent(&mut self, fd: &EventFd, offset: u64);
    fn unregister_ioevent(&mut self, fd: EventFd, offset: u64);
    fn register_vring_kick(&mut self, fd: Option<EventFd>, queue: u8);
    fn backend_request_socket(&mut self, socket: UnixStream);
    fn set_inbound_migration_fd(&mut self, fd: OwnedFd) -> io::Result<()>;
    fn set_outbound_migration_fd(&mut self, fd: OwnedFd) -> io::Result<()>;
}

pub enum MigrationFd {
    Read(OwnedFd),
    Write(OwnedFd),
    NotReceived,
    Complete,
}

struct FrontendRequestQueuePairInternals<T: Allocator, U: VM> {
    mapping: super::mapping::Mapping<T>,
    ioeventfds: Arc<Mutex<IoEventFds>>,
    queues: u8,
    seen_log_mapping: bool,
    seen_backend_req_socket: bool,
    vm: U,
    checker: EventfdChecker,
}

impl<T: Allocator, U: VM> FrontendRequestQueuePairInternals<T, U> {
    fn set_mem_table(&mut self, buf: &[u8], fd: &mut [Option<OwnedFd>]) -> Result<(), Error> {
        const _: () = assert!(
            u64::MAX as usize as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        const _: () = assert!(
            u64::MAX as libc::size_t as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        const _: () = assert!(align_of::<VhostUserMemoryRegion>() == 1);
        if buf.len() > MAX_MSG_SIZE || buf.len() < size_of::<VhostUserMemory>() {
            error!("Bad buffer length {}", buf.len());
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Bounds checked above, alignment of VhostUserMemory is 1,
        // and VhostUserMemory is POD
        let memory: VhostUserMemory = unsafe { *buf.as_ptr().cast() };
        // Compiler-checked documentation that the
        // number of regions is bounded by u32::MAX.
        let num_regions: u32 = memory.num_regions;
        let num_regions = num_regions as usize;
        let padding1 = memory.padding1;
        if num_regions != fd.len() {
            error!(
                "Number of regions {num_regions} does not match number of FDs {}",
                fd.len()
            );
            return Err(Error::InvalidMessage);
        }
        if padding1 != 0 || !(1..9).contains(&num_regions) {
            error!("Bad padding {padding1} or number of regions {num_regions}");
            return Err(Error::InvalidMessage);
        }
        // Above check ensures that overflow is not possible.
        // Since usize::MAX is checked to equal u64::MAX it isn't
        // possible anyway.
        let expected_len =
            size_of::<VhostUserMemory>() + num_regions * size_of::<VhostUserMemoryRegion>();
        let buf_len = buf.len();
        if buf_len != expected_len {
            error!("Wrong buffer length: got {buf_len}, expected {expected_len}");
            return Err(Error::InvalidMessage);
        }

        // SAFETY: Bounds checked above, alignment of VhostUserMemoryRegion is 1,
        // and VhostUserMemoryRegion is POD
        let ctx = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(size_of::<VhostUserMemory>()).cast(),
                num_regions,
            )
        };
        // Validate all the regions before doing any mappings.
        ctx.iter()
            .try_for_each(|region| self.mapping.check_region(region))?;
        // Reset the mapping
        self.mapping.reset()?;
        for (&region, file) in ctx.iter().zip(fd.iter_mut()) {
            self.mapping
                .map_region_without_alignment_checks(region, file.take().unwrap().as_fd())?;
        }
        Ok(())
    }
    fn handle_vring_fd_request(&mut self, buf: &[u8], has_fd: bool) -> Result<u8, Error> {
        let Ok(msg) = <[u8; 8]>::try_from(buf) else {
            error!("Wrong buffer length (expected 8): {}", buf.len());
            return Err(Error::InvalidMessage);
        };

        let msg = u64::from_ne_bytes(msg);
        if msg >= 512 {
            return Err(Error::InvalidMessage);
        }
        let queue = msg as u8;
        if queue >= self.queues {
            return Err(Error::InvalidMessage);
        }
        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This bit is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        // If Bit 8 is unset, the data must contain a file descriptor.
        if ((msg & 0x100u64) == 0) != has_fd {
            return Err(Error::InvalidMessage);
        }
        Ok(queue)
    }
    fn handle_ioeventfd_req(
        &mut self,
        req: FrontendReq,
        buf: &[u8],
        files: &mut [Option<OwnedFd>],
    ) -> Result<(), Error> {
        let eventfd = self.check_eventfd(req, files)?;
        let (queue, queue_offset) = match req {
            FrontendReq::SET_VRING_CALL => {
                (self.handle_vring_fd_request(buf, eventfd.is_some())?, 0)
            }
            FrontendReq::SET_VRING_ERR => {
                (self.handle_vring_fd_request(buf, eventfd.is_some())?, 1)
            }
            FrontendReq::SET_LOG_FD => {
                if !buf.is_empty() {
                    error!("SET_LOG_FD has nonempty buffer (length {})", buf.len());
                    return Err(Error::InvalidMessage);
                }
                if eventfd.is_none() {
                    error!("SET_LOG_FD has no eventfd");
                    return Err(Error::IncorrectFds);
                }
                (0, 2)
            }
            _ => unreachable!(),
        };
        let fd_offset: u64 = queue as u64 + self.queues as u64 * queue_offset;
        let mut ioeventfds = self.ioeventfds.lock().unwrap();
        let offset: u64 = ioeventfds.offset + 4u64 * fd_offset;
        let fd_offset = usize::try_from(fd_offset).unwrap();
        if let Some(fd) = ioeventfds.fds[fd_offset].take() {
            self.vm.unregister_ioevent(fd, offset);
        }
        if let Some(fd) = eventfd {
            self.vm.register_ioevent(&fd, offset);
            ioeventfds.fds[fd_offset] = Some(fd);
        }
        Ok(())
    }

    fn check_eventfd(
        &mut self,
        req: FrontendReq,
        files: &mut [Option<OwnedFd>],
    ) -> Result<Option<EventFd>, Error> {
        match *files {
            [] => Ok(None),
            [ref mut fd] => match self.checker.convert_to_eventfd(fd.take().unwrap()) {
                Ok(eventfd) => Ok(Some(eventfd)),
                Err((_, eventfd_checker::Error::NotEventFd)) => {
                    error!("{req:?}: got a file descriptor that is not an eventfd");
                    Err(Error::InvalidMessage)
                }
                Err((_, eventfd_checker::Error::IO(e))) => {
                    error!("{req:?}: I/O error {e} checking if FD is eventfd");
                    Err(Error::ReqHandlerError(e))
                }
            },
            _ => {
                error!(
                    "{req:?}: wrong number of files (got {}, expected 0 or 1)",
                    files.len()
                );
                Err(Error::IncorrectFds)
            }
        }
    }

    fn process_f2b_requests(
        &mut self,
        msg: VhostUserMsgHeader,
        buf: &mut [u8],
        fd: &mut [Option<OwnedFd>],
    ) -> Result<(), Error> {
        // Check that this is a version 1 request.
        if msg.flags & !VhostUserHeaderFlag::NEED_REPLY.bits() != 1 {
            warn!("Flags are wrong: first 8 bits are {:b}", { msg.flags });
            return Err(Error::InvalidMessage);
        }
        let req = FrontendReq::try_from(msg.request).or(Err(Error::InvalidMessage))?;
        match req {
            FrontendReq::SET_MEM_TABLE
            | FrontendReq::SET_VRING_CALL
            | FrontendReq::SET_VRING_KICK
            | FrontendReq::SET_VRING_ERR
            | FrontendReq::SET_LOG_BASE
            | FrontendReq::SET_LOG_FD
            | FrontendReq::SET_BACKEND_REQ_FD
            | FrontendReq::SET_INFLIGHT_FD
            | FrontendReq::ADD_MEM_REG
            | FrontendReq::REM_MEM_REG
            | FrontendReq::SET_DEVICE_STATE_FD
            | FrontendReq::GPU_SET_SOCKET => Ok(()),
            _ if !fd.is_empty() => Err(Error::IncorrectFds),
            _ => Ok(()),
        }?;

        match req {
            FrontendReq::RESET_OWNER => Ok(()),
            FrontendReq::SET_OWNER
            | FrontendReq::RESET_DEVICE
            | FrontendReq::GET_FEATURES
            | FrontendReq::GET_PROTOCOL_FEATURES
            | FrontendReq::GET_QUEUE_NUM => {
                if !buf.is_empty() {
                    error!(
                        "Payload for {req:?} should be empty but has {} bytes",
                        buf.len()
                    );
                    return Err(Error::InvalidMessage);
                }
                Ok(())
            }

            FrontendReq::SET_PROTOCOL_FEATURES => set_protocol_features(buf),
            FrontendReq::SET_MEM_TABLE => self.set_mem_table(buf, fd),
            FrontendReq::SET_VRING_CALL | FrontendReq::SET_VRING_ERR | FrontendReq::SET_LOG_FD => {
                self.handle_ioeventfd_req(req, buf, fd)
            }

            FrontendReq::SET_VRING_KICK => self.vring_kick(buf, fd, req),

            FrontendReq::ADD_MEM_REG => self.add_mem_reg(buf, fd),

            FrontendReq::REM_MEM_REG => {
                if fd.len() > 1 {
                    return Err(Error::IncorrectFds);
                }
                let region: VhostUserSingleMemoryRegion =
                    read_bytevalued(buf).ok_or(Error::InvalidMessage)?;
                self.mapping.unmap_region(&region)?;
                Ok(())
            }
            FrontendReq::SET_LOG_BASE => self.set_log_base(buf, fd),
            FrontendReq::SET_BACKEND_REQ_FD => self.set_backend_req_fd(fd),

            FrontendReq::SET_DEVICE_STATE_FD => self.set_device_state_fd(buf, fd),
            FrontendReq::CHECK_DEVICE_STATE => Err(Error::FeatureMismatch),

            // These are features that are not implemented yet.
            // Migration messages

            // These are features that aren't implemented,
            // and aren't planned to be.

            // Need backend to frontend FD transfer
            FrontendReq::SET_INFLIGHT_FD
            | FrontendReq::GET_INFLIGHT_FD
            | FrontendReq::POSTCOPY_ADVISE
            | FrontendReq::POSTCOPY_LISTEN
            | FrontendReq::POSTCOPY_END => Err(Error::FeatureMismatch),
            // Old-style virtio-GPU
            FrontendReq::GPU_SET_SOCKET => Err(Error::FeatureMismatch),
            // In-band notifications, for simulation only.
            FrontendReq::VRING_KICK => Err(Error::FeatureMismatch),
            // Legacy devices
            FrontendReq::SET_VRING_ENDIAN => Err(Error::FeatureMismatch),
            // Network device MTU (only useful with migration)
            // This could be implemented, but the IOMMU ought to
            // be enforced by the frontend, not the backend.
            FrontendReq::IOTLB_MSG => Err(Error::FeatureMismatch),
            // Only needed for "exotic" devices like GPUs.
            FrontendReq::GET_SHMEM_CONFIG => Err(Error::FeatureMismatch),
            // Shared objects.  TODO: this can be made to work,
            // but only with integration into the rest of Cloud Hypervisor.
            FrontendReq::GET_SHARED_OBJECT => Err(Error::FeatureMismatch),
            /* Messages needing no interaction */
            FrontendReq::SET_FEATURES
            | FrontendReq::NET_SET_MTU
            | FrontendReq::SEND_RARP
            | FrontendReq::SET_VRING_NUM
            | FrontendReq::SET_VRING_ADDR
            | FrontendReq::SET_VRING_BASE
            | FrontendReq::GET_VRING_BASE
            | FrontendReq::SET_VRING_ENABLE
            | FrontendReq::GET_CONFIG
            | FrontendReq::SET_CONFIG
            | FrontendReq::CREATE_CRYPTO_SESSION
            | FrontendReq::CLOSE_CRYPTO_SESSION
            | FrontendReq::GET_MAX_MEM_SLOTS
            | FrontendReq::SET_STATUS
            | FrontendReq::GET_STATUS => Ok(()),
        }
    }

    fn set_device_state_fd(
        &mut self,
        buf: &mut [u8],
        fd: &mut [Option<OwnedFd>],
    ) -> Result<(), Error> {
        let Some(VhostUserTransferDeviceState { direction, phase }) = read_bytevalued(buf) else {
            let len = buf.len();
            error!("SET_DEVICE_STATE_FD: length is {len} but expected 8");
            return Err(Error::InvalidMessage);
        };
        let is_load = match direction {
            0 => false,
            1 => true,
            _ => {
                error!("SET_DEVICE_STATE_FD: bad direction {direction}");
                return Err(Error::InvalidMessage);
            }
        };
        if phase != 0 {
            error!("SET_DEVICE_STATE_FD: bad phase {phase}");
            return Err(Error::InvalidMessage);
        }
        let fd = Self::get_single_file(fd)?;
        // SAFETY: libc::F_GETFL is safe on valid FDs, and fd.as_raw_fd returns valid FD
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        match (is_load, flags & libc::O_ACCMODE) {
            (true, libc::O_RDONLY) | (true, libc::O_RDWR) => self
                .vm
                .set_inbound_migration_fd(fd)
                .map_err(|_| Error::InvalidOperation("Inbound migration FD already set")),
            (false, libc::O_WRONLY) | (false, libc::O_RDWR) => self
                .vm
                .set_outbound_migration_fd(fd)
                .map_err(|_| Error::InvalidOperation("Outbound migration FD already set")),
            _ => {
                error!(
                    "Migration state fd is not {}",
                    if is_load { "readable" } else { "writeable" }
                );
                Err(Error::InvalidMessage)
            }
        }
    }

    fn set_backend_req_fd(&mut self, fd: &mut [Option<OwnedFd>]) -> Result<(), Error> {
        if self.seen_backend_req_socket {
            return Err(Error::InvalidOperation("Backend request FD already sent"));
        }
        let file = Self::get_single_file(fd)?;
        let socket = check_is_stream_socket(file).map_err(Error::ReqHandlerError)?;
        self.vm.backend_request_socket(socket);
        self.seen_backend_req_socket = true;
        Ok(())
    }

    fn set_log_base(&mut self, buf: &mut [u8], fd: &mut [Option<OwnedFd>]) -> Result<(), Error> {
        if self.seen_log_mapping {
            return Err(Error::InvalidOperation("Duplicate log mapping"));
        }
        let file = Self::get_single_file(fd)?;
        let region: VhostUserLog = read_bytevalued(buf).ok_or(Error::InvalidMessage)?;
        let region = VhostUserMemoryRegion {
            guest_phys_addr: u64::MAX,
            memory_size: region.mmap_size,
            user_addr: u64::MAX,
            mmap_offset: region.mmap_offset,
        };
        self.mapping.check_region(&region)?;
        self.mapping
            .map_region_without_alignment_checks(region, file.as_fd())?;
        self.seen_log_mapping = true;
        Ok(())
    }

    fn add_mem_reg(&mut self, buf: &mut [u8], fd: &mut [Option<OwnedFd>]) -> Result<(), Error> {
        if fd.len() != 1 {
            return Err(Error::IncorrectFds);
        }
        let file = fd[0].take().unwrap();
        let region: VhostUserSingleMemoryRegion =
            read_bytevalued(buf).ok_or(Error::InvalidMessage)?;
        self.mapping.map_region(*region, file.as_fd())?;
        Ok(())
    }

    fn vring_kick(
        &mut self,
        buf: &mut [u8],
        fd: &mut [Option<OwnedFd>],
        req: FrontendReq,
    ) -> Result<(), Error> {
        let eventfd = self.check_eventfd(req, fd)?;
        let index = self.handle_vring_fd_request(buf, eventfd.is_some())?;
        self.vm.register_vring_kick(eventfd, index);
        Ok(())
    }

    fn get_single_file(files: &mut [Option<OwnedFd>]) -> Result<OwnedFd, Error> {
        if files.len() == 1 {
            Ok(files[0].take().unwrap())
        } else {
            error!(
                "Wrong number of files in get_single_file: expected 1, got {}",
                files.len()
            );
            Err(Error::InvalidMessage)
        }
    }
}

impl<T: Allocator, U: VM> super::QueuePair for FrontendRequestQueuePair<T, U> {
    fn process(
        &mut self,
        translate: Option<Translate>,
        direction: Direction,
        max_iterations: usize,
    ) -> io::Result<(Option<(BorrowedFd<'_>, Direction)>, bool)> {
        let (rearm, did_something) = match direction {
            Direction::Inbound => self.process_f2b_requests(translate, max_iterations)?,
            Direction::Outbound => self.process_b2f_replies(translate, max_iterations)?,
        };
        let fd = extract_fd(direction, &rearm, self.fds());
        Ok((fd, did_something))
    }
}

fn set_protocol_features(buf: &mut [u8]) -> Result<(), Error> {
    let Some(protocol_features) = read_bytevalued::<u64>(buf) else {
        error!("Bad parameter length for SET_PROTOCOL_FEATURES!");
        return Err(Error::InvalidMessage);
    };
    let unsupported_features = protocol_features & !SUPPORTED_PROTOCOL_FEATURES.bits();
    if unsupported_features != 0 {
        error!("Unsupported vhost-user protocol feature 0b{unsupported_features:b} negotiated!");
        return Err(Error::InvalidMessage);
    }
    Ok(())
}

impl<T: Allocator, U: VM> FrontendRequestQueuePair<T, U> {
    pub fn new(
        queue_pair: queue_pair::VirtioVhostUserQueuePair,
        mapping: super::mapping::Mapping<T>,
        ioeventfds: Arc<Mutex<IoEventFds>>,
        queues: u8,
        vm: U,
    ) -> Self {
        Self {
            queue_pair,
            internals: FrontendRequestQueuePairInternals {
                checker: EventfdChecker::new()
                    .expect("cannot create eventfd checker, you're out of resources"),
                mapping,
                ioeventfds,
                queues,
                seen_log_mapping: false,
                vm,
                seen_backend_req_socket: false,
            },
        }
    }

    /// Return a mutable reference to the VM.
    ///
    /// This will never panic, and unless the queue pair is moved,
    /// it will always return the same address.
    pub fn vm_mut(&mut self) -> &mut U {
        &mut self.internals.vm
    }

    /// Return a reference to the VM.
    ///
    /// This will never panic, and unless the queue pair is moved,
    /// it will always return the same address.
    pub fn vm(&mut self) -> &U {
        &self.internals.vm
    }

    pub fn process_b2f_replies(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> Result<(FdRearm, bool), vhost_user::Error> {
        self.queue_pair
            .process_outgoing(access_platform, max_iterations, &mut |hdr, buf| {
                validate_reply(hdr, buf)
            })
    }
    pub fn process_f2b_requests(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> Result<(FdRearm, bool), vhost_user::Error> {
        self.queue_pair
            .process_incoming(access_platform, max_iterations, &mut |hdr, buf, files| {
                self.internals.process_f2b_requests(hdr, buf, files)
            })
    }
    pub fn fds(&self) -> Fds<'_> {
        self.queue_pair.fds()
    }
}
