// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the virtio-vhost-user protocol
//! This implements a vhost-user device backend.  Documentation can be found at:
//! https://github.com/DemiMarie/virtio-spec.git, branch virtio-vhost-user.

#![expect(dead_code, reason = "incomplete crate")]

mod mapping;
mod no_overlap_mapping;

pub use mapping::{Allocator, Mapping, Region};
