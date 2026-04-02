// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the virtio-vhost-user protocol
//! This implements a vhost-user device backend.  Documentation can be found at:
//! https://github.com/DemiMarie/virtio-spec.git, branch virtio-vhost-user.

#![expect(dead_code, reason = "incomplete crate")]

mod backend_request;
mod mapping;
mod queue_pair;

use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::{io, ptr};

pub use mapping::{Allocator, Mapping, Region};
pub use queue_pair::{FdRearm, Fds, Translate, VirtioVhostUserQueuePair};
use vm_memory::ByteValued;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Extract the file descriptor that needs to be polled from an [`Fds`].
/// There might be none, and the direction depends on which one it is
/// and on the direction of data flow.
fn extract_fd<'a>(
    direction: Direction,
    rearm: &'_ FdRearm,
    fds: Fds<'a>,
) -> Option<(BorrowedFd<'a>, Direction)> {
    match rearm {
        FdRearm::Neither => None,
        FdRearm::Queue => {
            let fd = match direction {
                Direction::Inbound => fds.queue_in,
                Direction::Outbound => fds.queue_out,
            };
            // SAFETY: as_raw_fd returns valid FD
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) };
            // EventFds always need to be read.
            Some((borrowed_fd, Direction::Inbound))
        }
        FdRearm::Socket => Some((
            fds.socket.expect("always have a socket at this point"),
            direction,
        )),
    }
}

pub trait QueuePair {
    fn process(
        &mut self,
        translate: Option<Translate>,
        direction: Direction,
        max_iterations: usize,
    ) -> io::Result<(Option<(BorrowedFd<'_>, Direction)>, bool)>;
}

fn read_bytevalued<T: ByteValued>(buf: &[u8]) -> Option<T> {
    if buf.len() == size_of::<T>() {
        // SAFETY: T is ByteValued and as_ptr().cast() returns valid pointer
        // for size_of::<T>().  The pointer may be unaligned, but that is what
        // read_unaligned is for.
        unsafe { Some(ptr::read_unaligned(buf.as_ptr().cast::<T>())) }
    } else {
        None
    }
}
