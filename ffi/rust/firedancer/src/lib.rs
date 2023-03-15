pub mod pack_rx;

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
    let mut argc = args.len() as c_int;

    // Allocate buffer for null-delimited string data
    let mut argv_buf = Vec::<u8>::new();
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
    let argv_ptrs = argv_offs
        .into_iter()
        .map(|off| unsafe { argv_buf_ptr.offset(off as isize) })
        .collect::<Vec<*mut i8>>();

    // Leak argv string array
    let mut argv: *mut *mut i8 = argv_ptrs.leak().as_mut_ptr();

    unsafe {
        util::fd_boot(&mut argc, &mut argv);
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
