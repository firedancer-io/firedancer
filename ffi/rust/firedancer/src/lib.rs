#![allow(clippy::missing_safety_doc)]

pub mod log;
#[cfg(feature = "frankendancer")]
pub mod pack_rx;
pub mod pod;
pub mod wksp;

use firedancer_sys::util;
use std::ffi::c_int;

/// fd_boot wraps fd_boot().
///
/// Must be called prior to application startup.
///
/// As the lifetime of the argv strings and the argv string array is not
/// well defined, the given args strings will be leaked onto the heap so
/// they persist for the lifetime of the local thread group.
pub fn fd_boot(args: &[&str]) {
    let argc = args.len() as c_int;

    // Find required size of buffer
    let mut argv_buf_sz = 0usize;
    for arg in args {
        argv_buf_sz += arg.len() + 1;
    }

    // Allocate buffer for null-delimited string data
    let mut argv_buf = Vec::<u8>::with_capacity(argv_buf_sz);
    // Remember byte offsets of strings
    let mut argv_offs = Vec::<usize>::with_capacity(args.len());

    // Create null-delimited strings
    for arg in args {
        argv_offs.push(argv_buf.len());
        argv_buf.extend_from_slice(arg.as_bytes());
        argv_buf.push(0u8);
    }

    // Leak argv backing string buffer
    let argv_buf_ptr = argv_buf.leak().as_mut_ptr() as *mut i8;

    // Rewrite byte offsets into absolute addresses
    let mut argv_ptrs = Vec::<*mut i8>::with_capacity(args.len() + 1);
    for argv_off in argv_offs {
        argv_ptrs.push(unsafe { argv_buf_ptr.add(argv_off) });
    }
    argv_ptrs.push(std::ptr::null_mut()); // argv is NULL-terminated in ANSI C

    // Leak argv string array
    let argv: *mut *mut i8 = argv_ptrs.leak().as_mut_ptr();

    // Move argv/argc to heap and create pointers
    let pargc = Box::into_raw(Box::new(argc));
    let pargv = Box::into_raw(Box::new(argv));

    unsafe {
        util::fd_boot(pargc, pargv);
    }
}

/// fd_halt wraps fd_halt().
///
/// # Safety
///
/// U.B. if Firedancer FFI subsystem is used after calling fd_halt().
pub unsafe fn fd_halt() {
    util::fd_halt();
}
