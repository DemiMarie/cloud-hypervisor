// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io::Error;
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{IoUring, opcode, types};
use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use log::{error, trace};
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::{BatchRequest, RequestType, SECTOR_SIZE};

struct AbortIfUnwind;
impl Drop for AbortIfUnwind {
    // There is no way to handle unwinding in this situation.
    fn drop(&mut self) {
        if std::thread::panicking() {
            panic!(
                "Cannot handle unwinding while the io_uring \
submission queue has pointers to \
potentially stack-allocated slices of 'struct iovec' \
that the kernel hasn't read yet.  The kernel would look at \
them at some point, likely after they go out of scope."
            )
        }
    }
}

pub struct RawFileAsync {
    fd: RawFd,
    io_uring: IoUring,
    eventfd: EventFd,
    alignment: u64,
}

impl RawFileAsync {
    pub fn new(fd: RawFd, ring_depth: u32) -> BlockResult<Self> {
        let io_uring =
            IoUring::new(ring_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let eventfd =
            EventFd::new(libc::EFD_NONBLOCK).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        // Register the io_uring eventfd that will notify when something in
        // the completion queue is ready.
        io_uring
            .submitter()
            .register_eventfd(eventfd.as_raw_fd())
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        Ok(RawFileAsync {
            fd,
            io_uring,
            eventfd,
            alignment: SECTOR_SIZE,
        })
    }
}

impl AsyncIo for RawFileAsync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    unsafe fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        // Until spin_until_all_submitted() returns,
        // there is no way to safely return from the function.
        // This includes unwinding.  Therefore, turn all unwinds
        // into aborts.
        let _turn_panic_into_abort = AbortIfUnwind;

        // SAFETY: we know the file descriptor is valid and we
        // rely on the caller to provide the buffer address.
        // The caller is responsible for waiting for completion.
        // Furthermore, we spin until the iovecs have all been
        // submitted to the kernel.
        unsafe {
            sq.push(
                &opcode::Readv::new(types::Fd(self.fd), iovecs.as_ptr(), iovecs.len() as u32)
                    .offset(offset.try_into().unwrap())
                    .build()
                    .user_data(user_data),
            )
            .map_err(|_| AsyncIoError::ReadVectored(Error::other("Submission queue is full")))?;
        };

        spin_until_all_submitted(&submitter, sq);

        Ok(())
    }

    unsafe fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        // Until spin_until_all_submitted() returns,
        // there is no way to safely return from the function.
        // This includes unwinding.  Therefore, turn all unwinds
        // into aborts.
        let _turn_panic_into_abort = AbortIfUnwind;

        // SAFETY: we know the file descriptor is valid and we
        // rely on the caller to provide the buffer address.
        // The caller is responsible for waiting for completion.
        // Furthermore, we spin until the iovecs have all been
        // submitted to the kernel.
        unsafe {
            sq.push(
                &opcode::Writev::new(types::Fd(self.fd), iovecs.as_ptr(), iovecs.len() as u32)
                    .offset(offset.try_into().unwrap())
                    .build()
                    .user_data(user_data),
            )
            .map_err(|_| AsyncIoError::WriteVectored(Error::other("Submission queue is full")))?;
        };

        spin_until_all_submitted(&submitter, sq);

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if let Some(user_data) = user_data {
            let (submitter, mut sq, _) = self.io_uring.split();

            // SAFETY: we know the file descriptor is valid.
            unsafe {
                sq.push(
                    &opcode::Fsync::new(types::Fd(self.fd))
                        .build()
                        .user_data(user_data),
                )
                .map_err(|_| AsyncIoError::Fsync(Error::other("Submission queue is full")))?;
            };

            // Update the submission queue and submit new operations to the
            // io_uring instance.
            sq.sync();
            submitter.submit().map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(self.fd) };
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.io_uring
            .completion()
            .next()
            .map(|entry| (entry.user_data(), entry.result()))
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        if batch_request.is_empty() {
            return Ok(());
        }

        let (submitter, mut sq, _) = self.io_uring.split();
        let mut submitted = 0usize;
        if sq.capacity() - sq.len() < batch_request.len() {
            return Err(match batch_request[0].request_type {
                RequestType::In => AsyncIoError::ReadVectored,
                RequestType::Out => AsyncIoError::WriteVectored,
                _ => unreachable!(),
            }(Error::other("Submission queue is full")));
        }

        for req in batch_request {
            match req.request_type {
                RequestType::In | RequestType::Out => {}
                _ => {
                    unreachable!("Unexpected batch request type: {:?}", req.request_type)
                }
            }
        }

        // Until spin_until_all_submitted() returns,
        // there is no way to safely return from the function.
        // This includes unwinding.  Therefore, turn all unwinds
        // into aborts.
        let _turn_panic_into_abort = AbortIfUnwind;
        // The closure is used to check that there are no unexpected error
        // returns (by ? or otherwise).
        #[allow(clippy::redundant_closure_call)]
        let _: () = (|| {
            for req in batch_request {
                match req.request_type {
                    RequestType::In => {
                        // SAFETY: we know the file descriptor is valid and we
                        // rely on the caller to provide the buffer address.
                        // The caller is responsible for waiting for completion.
                        // Furthermore, we spin until the iovecs have all been
                        // submitted to the kernel.
                        unsafe {
                            sq.push(
                                &opcode::Readv::new(
                                    types::Fd(self.fd),
                                    req.iovecs.as_ptr(),
                                    req.iovecs.len() as u32,
                                )
                                .offset(req.offset as u64)
                                .build()
                                .user_data(req.user_data),
                            )
                            .expect("Submission queue space checked above");
                        };
                        submitted += 1;
                    }
                    RequestType::Out => {
                        // SAFETY: we know the file descriptor is valid and we
                        // rely on the caller to provide the buffer address.
                        // The caller is responsible for waiting for completion.
                        // Furthermore, we spin until the iovecs have all been
                        // submitted to the kernel.
                        unsafe {
                            sq.push(
                                &opcode::Writev::new(
                                    types::Fd(self.fd),
                                    req.iovecs.as_ptr(),
                                    req.iovecs.len() as u32,
                                )
                                .offset(req.offset as u64)
                                .build()
                                .user_data(req.user_data),
                            )
                            .expect("Submission queue space checked above");
                        };
                        submitted += 1;
                    }
                    _ => {
                        unreachable!("Unexpected batch request type: {:?}", req.request_type)
                    }
                }
            }

            // Only submit if we actually queued something
            if submitted > 0 {
                spin_until_all_submitted(&submitter, sq);
            }
        })();

        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: The file descriptor is known to be valid.
        unsafe {
            sq.push(
                &opcode::Fallocate::new(types::Fd(self.fd), length)
                    .offset(offset)
                    .mode(mode)
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::PunchHole(Error::other(format!("Submission queue is full: {e:?}")))
            })?;
        };

        sq.sync();
        submitter.submit().map_err(AsyncIoError::PunchHole)?;

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: The file descriptor is known to be valid.
        unsafe {
            sq.push(
                &opcode::Fallocate::new(types::Fd(self.fd), length)
                    .offset(offset)
                    .mode(mode)
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::WriteZeroes(Error::other(format!("Submission queue is full: {e:?}")))
            })?;
        };

        sq.sync();
        submitter.submit().map_err(AsyncIoError::WriteZeroes)?;

        Ok(())
    }
}

fn spin_until_all_submitted(
    submitter: &io_uring::Submitter<'_>,
    mut sq: io_uring::SubmissionQueue<'_>,
) {
    // Update the submission queue and submit new operations to the
    // io_uring instance.
    sq.sync();
    // The iovecs are likely on the caller's stack
    // and will be invalid once the function returns.
    // The only safe thing to do is to spin until
    // they have all been submitted to the kernel.
    //
    // Do not log anything here.  Logging might
    // panic, and that will be turned into an abort.
    let mut len = sq.len();
    while len > 0 {
        let amount_submitted = match submitter.submit() {
            Ok(e) => e,
            Err(e) => match e.raw_os_error().expect("always an OS error") {
                // anecdotally EINVAL can occasionally happen
                libc::EAGAIN | libc::EINTR | libc::EINVAL | libc::EBUSY => continue,
                libc::EFAULT => panic!("Bad address in io_uring submission"),
                libc::ENXIO => panic!("I/O safety violation: ring being torn down"),
                libc::EBADF => panic!("I/O safety violation: ring not valid FD"),
                libc::EOPNOTSUPP => panic!("I/O safety violation: ring not io_uring FD"),
                libc::EEXIST => panic!("DEFER_TASKRUN used"),
                // TODO: rate limit
                _ => {
                    error!("Unknown error {e}, retrying submission");
                    continue;
                }
            },
        };
        trace!("Submitted {amount_submitted} entries");
        assert!(amount_submitted <= len);
        len -= amount_submitted;
    }
    if cfg!(debug_assertions) {
        sq.sync();
        assert_eq!(sq.len(), 0);
    }
}
