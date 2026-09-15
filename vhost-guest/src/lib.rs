// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the virtio-vhost-user protocol
//! This implements a vhost-user device backend.  Documentation can be found at:
//! https://github.com/DemiMarie/virtio-spec.git, branch virtio-vhost-user.

#![expect(dead_code, reason = "incomplete crate")]

mod mapping;
mod no_overlap_mapping;
mod queue_pair;

use std::ptr;

pub use mapping::{Allocator, Mapping, Region};
pub use queue_pair::{FdRearm, Fds, Translate, VirtioVhostGuestQueuePair};
use vm_memory::ByteValued;

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
