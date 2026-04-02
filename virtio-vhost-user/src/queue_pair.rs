// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
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

//! Queue pairs for frontend <=> backend communication.
//!
//! This includes lots of code from the vhost-user crate, but generalized.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Error as IoError, ErrorKind};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process;

use libc::iovec;
use log::{debug, error, warn};
use vhost::vhost_user::Error;
use vhost::vhost_user::message::{MAX_ATTACHED_FD_ENTRIES, MAX_MSG_SIZE};
use virtio_queue::{Queue, QueueT as _};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    ByteValued, Bytes as _, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryMmap, Permissions,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket as _;

use crate::read_bytevalued;

// SAFETY: is POD
unsafe impl ByteValued for VhostUserMsgHeader {}
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserMsgHeader {
    pub request: u32,
    pub flags: u32,
    pub size: u32,
}

pub type Translate<'a> = &'a dyn Fn(GuestAddress, usize) -> io::Result<GuestAddress>;

pub enum FdRearm {
    Neither,
    Socket,
    Queue,
}

#[derive(Clone, Copy)]
pub struct Fds<'a> {
    pub queue_in: &'a EventFd,
    pub queue_out: &'a EventFd,
    pub socket: Option<BorrowedFd<'a>>,
}

pub struct OutgoingData {
    outgoing_buf: Vec<u8>,
    offset: usize,
    back2front_queue: Queue,
    back2front_queue_evt: EventFd,
    mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

impl OutgoingData {
    /// Send an outgoing message if possible.
    ///
    /// Returns true if a full message was successfully sent.
    ///
    /// If the function returns true, the buffer will be empty.
    ///
    /// # Errors
    ///
    /// Fails if there is an I/O error on the socket.
    pub fn send_data(
        &mut self,
        send_to_socket: &mut dyn FnMut(&[u8], BorrowedFd<'_>) -> isize,
        fd: Option<BorrowedFd<'_>>,
    ) -> Result<bool, Error> {
        let Some(socket) = &fd else {
            error!(
                "No socket yet - did the backend place buffers on its request or reply queue without getting an FD from the frontend?"
            );
            return Err(Error::FeatureMismatch);
        };
        let buf = &self.outgoing_buf[self.offset..];
        loop {
            // SAFETY: FFI with valid parameters
            let v = send_to_socket(buf, socket.as_fd());
            if v == -1 {
                let e = IoError::last_os_error();
                let errno = e.raw_os_error().unwrap();
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    break Ok(false);
                }
                if errno != libc::EINTR {
                    break Err(Error::ReqHandlerError(e));
                }
            } else {
                let v: usize = v.try_into().unwrap();
                if v > buf.len() {
                    process::abort();
                }
                self.offset += v;
                if self.offset == buf.len() {
                    self.outgoing_buf.clear();
                    self.offset = 0;
                    break Ok(true);
                }
            }
        }
    }
}

pub struct VirtioVhostUserQueuePair {
    front2back_queue: Queue,
    front2back_queue_evt: EventFd,
    incoming_data: Vec<u8>,
    files_for_cycle: Vec<Option<OwnedFd>>,
    outgoing: OutgoingData,
    socket: Option<UnixStream>,
}

fn validate_hdr(exact_len: bool, buf: &mut [u8]) -> Result<(VhostUserMsgHeader, &mut [u8]), Error> {
    let desc_len = buf.len();
    if desc_len < size_of::<VhostUserMsgHeader>() {
        error!("virtio-vhost-user: descriptor too short");
        return Err(Error::InvalidMessage);
    }
    let (hdr, body) = buf.split_at_mut(size_of::<VhostUserMsgHeader>());
    let hdr: VhostUserMsgHeader = read_bytevalued(hdr).expect("length correct");
    let version = hdr.flags & 3;
    if version != 1 {
        error!("virtio-vhost-user: Bad version {version}");
        return Err(Error::InvalidMessage);
    }
    if exact_len && hdr.size as usize != body.len() {
        error!(
            "virtio-vhost-user: Message from guest has wrong length: \
             got {} but descriptor is of length {}",
            { hdr.size },
            body.len()
        );
        return Err(Error::InvalidMessage);
    }
    Ok((hdr, body))
}

impl VirtioVhostUserQueuePair {
    pub fn new(
        front2back_queue: Queue,
        back2front_queue: Queue,
        front2back_queue_evt: EventFd,
        back2front_queue_evt: EventFd,
        socket: Option<UnixStream>,
        mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    ) -> Self {
        Self {
            front2back_queue,
            front2back_queue_evt,
            incoming_data: Vec::new(),
            files_for_cycle: Vec::new(),
            socket,
            outgoing: OutgoingData {
                outgoing_buf: Vec::new(),
                offset: 0,
                back2front_queue,
                back2front_queue_evt,
                mem,
            },
        }
    }

    /// Sets the file descriptor to use for the socket.
    /// Does not close the socket on success
    /// (so socket.as_raw_fd() is still a valid fd).
    pub fn set_socket(&mut self, socket: UnixStream) -> Result<(), Error> {
        if self.socket.is_some() {
            return Err(Error::InvalidMessage);
        }
        self.socket = Some(socket);
        Ok(())
    }

    pub fn fds(&self) -> Fds<'_> {
        Fds {
            queue_in: &self.front2back_queue_evt,
            queue_out: &self.outgoing.back2front_queue_evt,
            socket: self.socket.as_ref().map(AsFd::as_fd),
        }
    }

    /// Send an outgoing message if possible.
    ///
    /// On success, the first element of the returned tuple indicates
    /// which file descriptors need to be polled.  The second element
    /// indicates whether the queue interrupt needs to be triggered.
    ///
    /// The callback will be called for each message sent.  It is allowed
    /// to modify the message's contents but not its header.  It can
    /// reject the message by returning an error.
    ///
    /// # Errors
    ///
    /// Fails if there is an I/O error on the socket or if the callback
    /// returns an error.
    #[allow(clippy::type_complexity)] // pulling this out leads to borrowck error
    pub(super) fn process_outgoing<'a>(
        &mut self,
        access_platform: Option<Translate<'a>>,
        max_messages: usize,
        process_message: MessageProcessor,
    ) -> Result<(FdRearm, bool), Error> {
        send_data(
            access_platform,
            max_messages,
            process_message,
            validate_hdr,
            &mut self.outgoing,
            &mut send_to_socket,
            self.socket.as_ref().map(AsFd::as_fd),
        )
    }

    fn extend_buffer(&mut self, min_size: usize) -> Result<(), Error> {
        let Some(socket) = &self.socket else {
            error!(
                "No socket yet - did the backend place buffers on its request \
                 or reply queue without getting an FD from the frontend?"
            );
            return Err(Error::BackendInternalError);
        };

        while min_size > self.incoming_data.len() {
            let extra_space = min_size - self.incoming_data.len();
            self.incoming_data.reserve(extra_space);
            let ptr: *mut c_void = self.incoming_data.as_mut_ptr().cast();
            // SAFETY: current_len points to before the end of the vec's capacity,
            // as at least one byte was reserved after it.
            let ptr = unsafe { ptr.add(self.incoming_data.len()) };
            let mut iov = [iovec {
                iov_base: ptr,
                iov_len: extra_space,
            }];

            let mut fd_array = vec![-1; MAX_ATTACHED_FD_ENTRIES];

            // SAFETY: anything can be written into unallocated capacity of a Vec<u8>
            let recv_res = unsafe { socket.recv_with_fds(&mut iov[..], &mut fd_array) };
            let (len, num_fds) = match recv_res {
                Ok(e) => e,
                Err(e) => match e.errno() {
                    libc::EAGAIN => {
                        return Err(Error::SocketRetry(IoError::from_raw_os_error(e.errno())));
                    }
                    libc::EINTR => continue,
                    e => return Err(Error::SocketError(IoError::from_raw_os_error(e))),
                },
            };

            if len == 0 {
                // End of file on the socket. This is never expected:
                // the connection should stay alive until the frontend exits.
                return Err(Error::SocketBroken(IoError::from(ErrorKind::UnexpectedEof)));
            }

            assert!(len <= extra_space);
            // SAFETY: the extra space has been reserved,
            // has been initialized by the kernel, and does
            // not exceed the spare capacity.
            unsafe {
                self.incoming_data.set_len(self.incoming_data.len() + len);
            }

            for &fd in fd_array.iter().take(num_fds) {
                assert!(fd >= 0);
                // SAFETY: we have the ownership of `fd`.
                let fd = unsafe { File::from_raw_fd(fd) };
                self.files_for_cycle.push(Some(fd.into()));
            }
        }
        Ok(())
    }

    /// Process incoming data on the vhost-user socket.
    ///
    /// Returns true if a full message was received, or false if
    /// all data has been consumed.  In the latter case, if
    /// edge-triggered file descriptor watching is used, the watch
    /// must be re-armed.
    ///
    /// # Errors
    ///
    /// Returns an error if the callback returns an error or an
    /// invalid message was received.
    fn socket_rx(&mut self) -> Result<(), Error> {
        let min_size = size_of::<VhostUserMsgHeader>();
        // TODO: better error
        self.extend_buffer(min_size)?;
        let msg_size = validate_hdr(false, &mut self.incoming_data)?.0.size;
        if msg_size > MAX_MSG_SIZE.try_into().unwrap() {
            error!("Bad message from frontend: size is {msg_size} (limit {MAX_MSG_SIZE})");
            return Err(Error::InvalidMessage);
        }
        self.extend_buffer(msg_size as usize + min_size)
    }

    /// Process an incoming message from the frontend if possible.
    ///
    /// The callback will be invoked for each such message.
    /// The file descriptor slice provided will only contain `Some`
    /// entries, but the callback is free to consume them (replace them
    /// with `None`).  File descriptors not consumed will be lost.
    ///
    /// Returns `Ok(true)` if a message was processed and `Ok(false)`
    /// if there was no message processed.
    ///
    /// # Errors
    ///
    /// Returns an error if the callback returns an error or an
    /// invalid message was received.
    #[allow(clippy::type_complexity)] // pulling this out leads to borrowck error
    pub(super) fn process_incoming(
        &mut self,
        mut access_platform: Option<Translate>,
        max_messages: usize,
        process_message: &mut dyn FnMut(
            VhostUserMsgHeader,
            &mut [u8],
            &mut [Option<OwnedFd>],
        ) -> Result<(), Error>,
    ) -> Result<(FdRearm, bool), Error> {
        let mut used_descs = false;
        for _ in 0..max_messages {
            match self.socket_rx() {
                Ok(()) => {}
                Err(Error::SocketRetry(_)) => return Ok((FdRearm::Socket, used_descs)),
                Err(e) => return Err(e),
            }
            let (hdr, body) = self
                .incoming_data
                .split_at_mut(size_of::<VhostUserMsgHeader>());
            let hdr: VhostUserMsgHeader = read_bytevalued(hdr).unwrap();
            used_descs = true;
            process_message(hdr, body, &mut self.files_for_cycle)?;

            let mut bytes_written = 0usize;
            let Some(mut desc_chain) = self
                .front2back_queue
                .pop_descriptor_chain(self.outgoing.mem.memory())
            else {
                return Ok((FdRearm::Queue, used_descs));
            };
            while let Some(desc) = desc_chain.next() {
                if !desc.is_write_only() {
                    // TODO: better error
                    warn!("Guest provided read-only descriptor to write to");
                    return Err(Error::InvalidParam);
                }

                let desc_len = usize::try_from(desc.len()).unwrap();
                let mem = desc_chain.memory();
                let mut addr = desc.addr();
                if desc_len == 0 {
                    debug!("Guest provided empty descriptor");
                    continue;
                }
                if let Some(ref mut translate) = access_platform {
                    addr = translate(addr, desc_len).map_err(Error::ReqHandlerError)?;
                }
                if !mem.check_range(addr, desc_len, Permissions::Write) {
                    warn!("Guest provided invalid descriptor");
                    return Err(Error::InvalidParam);
                }
                let to_write = desc_len.min(self.incoming_data.len() - bytes_written);
                if let Err(e) = mem.write_slice(
                    &self.incoming_data[bytes_written..bytes_written + to_write],
                    addr,
                ) {
                    error!("virtio-vhost-user: Problem writing guest data: {e}");
                    return Err(Error::InvalidMessage);
                }
                bytes_written += to_write;
            }
            if bytes_written != self.incoming_data.len() {
                warn!(
                    "Guest provided too short descriptor: {bytes_written} < {}",
                    self.incoming_data.len()
                );
                return Err(Error::InvalidMessage);
            }
            // TODO: better errors
            self.front2back_queue
                .add_used(
                    desc_chain.memory(),
                    desc_chain.head_index(),
                    bytes_written.try_into().unwrap(),
                )
                .map_err(|e| Error::ReqHandlerError(io::Error::other(e.to_string())))?;
            // Clear per-message state for the next cycle.
            // This drops all file descriptors not consumed by the callback.
            self.files_for_cycle.clear();
            self.incoming_data.clear();
        }
        Ok((FdRearm::Neither, used_descs))
    }
}

pub(super) type Validator = fn(bool, &mut [u8]) -> Result<(VhostUserMsgHeader, &mut [u8]), Error>;

pub(super) type SocketSender<'a> = &'a mut dyn FnMut(&[u8], BorrowedFd<'_>) -> isize;

pub(super) type MessageProcessor<'a> =
    &'a mut dyn FnMut(VhostUserMsgHeader, &mut [u8]) -> Result<(), Error>;

fn send_data(
    mut access_platform: Option<Translate>,
    max_messages: usize,
    process_message: MessageProcessor,
    validator: Validator,
    outgoing: &mut OutgoingData,
    send_to_socket: SocketSender,
    socket: Option<BorrowedFd<'_>>,
) -> Result<(FdRearm, bool), Error> {
    let mut used_descs = false;
    for _ in 0..max_messages {
        if outgoing.outgoing_buf.is_empty() {
            let Some(mut desc_chain) = outgoing
                .back2front_queue
                .pop_descriptor_chain(outgoing.mem.memory())
            else {
                return Ok((FdRearm::Queue, used_descs));
            };
            used_descs = true;
            let Some(desc) = desc_chain.next() else {
                error!("virtio-vhost-user: descriptor chain is empty");
                return Err(Error::InvalidMessage);
            };
            let mem = desc_chain.memory();
            if desc.is_write_only() {
                error!("virito-vhost-user: descriptor is write-only");
                return Err(Error::InvalidMessage);
            }
            let desc_len = desc.len() as usize;
            if desc_len > MAX_MSG_SIZE {
                error!("virtio-vhost-user: descriptor too long");
                return Err(Error::InvalidMessage);
            }
            outgoing.outgoing_buf.resize(desc_len, 0);

            let mut addr = desc.addr();
            if let Some(ref mut translate) = access_platform {
                addr = translate(addr, desc_len).map_err(Error::ReqHandlerError)?;
            }

            if let Err(e) = mem.read_slice(&mut outgoing.outgoing_buf, addr) {
                error!("virtio-vhost-user: Problem reading guest data: {e}");
                return Err(Error::InvalidMessage);
            }

            let (hdr, buf) = validator(true, &mut outgoing.outgoing_buf)?;
            process_message(hdr, buf)?;
            if desc_chain.next().is_some() {
                error!("virtio-vhost-user: guest provided chained descriptors");
                return Err(Error::InvalidMessage);
            }
        }
        if !outgoing.send_data(send_to_socket, socket)? {
            return Ok((FdRearm::Socket, used_descs));
        }
    }
    Ok((FdRearm::Neither, used_descs))
}

pub(crate) fn send_to_socket(buf: &[u8], socket: BorrowedFd<'_>) -> isize {
    // SAFETY: FFI with valid parameters
    unsafe {
        libc::send(
            socket.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    }
}
