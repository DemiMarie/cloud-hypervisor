// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Utilities for checking that FDs that are inherited or
//! received over SCM_RIGHTS are AF_UNIX stream sockets of
//! the expected type (listening or connected).

use std::ffi::{c_int, c_void};
use std::io::{self, ErrorKind};
use std::mem;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

/// Check if a file descriptor is a connected AF_UNIX stream socket.
/// If it is, and no kernel errors occur, return a [`UnixStream`].
/// Otherwise, return an error and close the FD.
pub fn fd_to_unixstream(fd: OwnedFd) -> io::Result<UnixStream> {
    common_stream_checks(&fd)?;
    // SAFETY: zero is valid for libc types
    let mut s: libc::sockaddr_un = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = size_of_val(&s).try_into().unwrap();
    // SAFETY: FFI call, valid arguments
    match unsafe { libc::getpeername(fd.as_raw_fd(), (&raw mut s).cast(), &raw mut len) } {
        0 => {}
        -1 => return Err(io::Error::last_os_error()),
        bad => panic!("bad return value {bad} from getpeername"),
    }
    // SAFETY: File descriptor is valid stream socket
    Ok(unsafe { UnixStream::from_raw_fd(fd.into_raw_fd()) })
}

/// Check if a file descriptor is a AF_UNIX listening stream socket.
/// If it is, and no kernel errors occur, return a [`UnixListener`].
/// Otherwise, return an error and close the FD.
pub fn fd_to_unixlistener(fd: OwnedFd) -> io::Result<UnixListener> {
    common_stream_checks(&fd)?;
    let msg = "not a listening socket";
    // SAFETY: SO_ACCEPTCONN is valid socket option for SOL_SOCKET.
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_ACCEPTCONN, 1, msg) }?;
    // SAFETY: File descriptor is valid stream socket
    Ok(unsafe { UnixListener::from_raw_fd(fd.into_raw_fd()) })
}

/// Check that the given socket option has the expected value.
///
/// # Safety
///
/// The option must a valid SOL_SOCKET.socket option.
///
/// # Panics
///
/// Panics if the socket option doesn't take a value of type
/// [`std::ffi::c_int`].
unsafe fn check_int_getsockopt(
    fd: BorrowedFd,
    option: c_int,
    expected: c_int,
    msg: &str,
) -> io::Result<()> {
    let size = size_of_val(&expected) as libc::socklen_t;
    // Flip this so that if the kernel didn't write to the whole thing,
    // the socket option will be treated as wrong.
    let mut actual_value = !expected;
    let mut actual_size = size;
    // SAFETY: FFI call with correct arguments.
    // Caller promised that the socket option is valid for SOL_SOCKET.
    match unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            &mut actual_value as *mut c_int as *mut c_void,
            &raw mut actual_size,
        )
    } {
        0 if actual_size == size => {
            if actual_value == expected {
                Ok(())
            } else {
                Err(io::Error::new(ErrorKind::InvalidData, msg))
            }
        }
        0 => panic!("socket option was supposed to be an int, but its size was {actual_size}"),
        -1 => Err(io::Error::last_os_error()),
        e => panic!("bad return value from {e} from getsockopt"),
    }
}

fn common_stream_checks(fd: &OwnedFd) -> Result<(), io::Error> {
    let msg = "domain is not AF_UNIX";
    // SAFETY: SO_DOMAIN is valid socket option for SOL_SOCKET.
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_DOMAIN, libc::AF_UNIX, msg) }?;
    let msg = "type is not SOCK_STREAM";
    // SAFETY: SO_TYPE is valid socket option for SOL_SOCKET.
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_TYPE, libc::SOCK_STREAM, msg) }?;
    let msg = "protocol is not 0";
    // SAFETY: SO_PROTOCOL is valid socket option for SOL_SOCKET.
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_PROTOCOL, 0, msg) }?;
    Ok(())
}
