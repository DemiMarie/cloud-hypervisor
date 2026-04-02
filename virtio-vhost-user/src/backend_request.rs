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

use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;

use vhost::vhost_user::Error;

use super::queue_pair::{FdRearm, Translate, VirtioVhostUserQueuePair};
use crate::queue_pair::Fds;
use crate::{Direction, extract_fd};

pub struct BackendRequestQueuePair {
    queue_pair: VirtioVhostUserQueuePair,
}
impl super::QueuePair for BackendRequestQueuePair {
    fn process(
        &mut self,
        translate: Option<Translate>,
        direction: Direction,
        max_iterations: usize,
    ) -> io::Result<(Option<(BorrowedFd<'_>, Direction)>, bool)> {
        let (rearm, did_something) = match direction {
            Direction::Inbound => self.process_f2b_replies(translate, max_iterations)?,
            Direction::Outbound => self.process_b2f_requests(translate, max_iterations)?,
        };
        let fd = extract_fd(direction, &rearm, self.fds());
        Ok((fd, did_something))
    }
}

impl BackendRequestQueuePair {
    pub fn set_socket(&mut self, socket: UnixStream) -> Result<(), Error> {
        self.queue_pair.set_socket(socket)
    }
    pub fn new(queue_pair: VirtioVhostUserQueuePair) -> Self {
        Self { queue_pair }
    }

    pub fn fds(&mut self) -> Fds<'_> {
        self.queue_pair.fds()
    }
    pub fn process_f2b_replies(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> Result<(FdRearm, bool), Error> {
        self.queue_pair.process_incoming(
            access_platform,
            max_iterations,
            &mut |_hdr, _buf, files| {
                if files.is_empty() {
                    Ok(())
                } else {
                    Err(Error::IncorrectFds)
                }
            },
        )
    }
    pub fn process_b2f_requests(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> Result<(FdRearm, bool), Error> {
        self.queue_pair
            .process_outgoing(access_platform, max_iterations, &mut |_hdr, _buf| Ok(()))
    }
}
