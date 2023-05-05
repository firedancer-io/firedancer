extern crate libc;

use std::ffi::CString;
use std::os::unix::io::RawFd;
use libc::{open, O_RDONLY, O_CLOEXEC, setns};

pub(crate) fn set_network_namespace(netns: &str) {
    let ns_file_path = CString::new(netns).unwrap();
    let fd: RawFd = unsafe { open(ns_file_path.as_ptr(), O_RDONLY | O_CLOEXEC) };
    assert!(fd >= 0);

    let result = unsafe { setns(fd, libc::CLONE_NEWNET) };
    if result != 0 {
        panic!("{}", std::io::Error::last_os_error());
    }
}
