use paste::paste;
use std::{
    ffi::{c_char, CString},
    os::fd::RawFd,
};

use libc::{c_uint, open, pid_t, setns, size_t, O_CLOEXEC, O_RDONLY};

use crate::utility::*;

macro_rules! capabilities {
    ($($name:ident($id:expr)),*) => {
        paste! {
            $(
                pub(crate) const [<$name:snake:upper>]: Capability = Capability::$name;
            )*
        }

        #[derive(Debug, Copy, Clone)]
        pub(crate) enum Capability {
            $($name),*
        }

        impl Capability {
            fn id(&self) -> u32 {
                match self {
                    $(
                        Capability::$name => $id
                    ),*
                }
            }
        }
    }
}

capabilities!(
    CapSysAdmin(21),
    CapSysNice(23),
    CapNetRaw(13),
    CapNetAdmin(12)
);

pub(crate) enum Permission {
    Root,
    Capability(Capability),
    FileCapability((String, Capability)),
}

#[repr(C)]
#[derive(Debug)]
struct __user_cap_data_struct {
    effective: c_uint,
    permitted: c_uint,
    inheritable: c_uint,
}

#[repr(C)]
#[derive(Debug)]
struct __user_cap_header_struct {
    version: c_uint,
    pid: pid_t,
}

#[repr(C)]
#[derive(Debug)]
struct __v3_file_cap_data_struct {
    permitted: c_uint,
    inheritable: c_uint,
}

#[repr(C)]
#[derive(Debug)]
struct __vfs_ns_cap_data_struct {
    magic_etc: c_uint,
    data: [__user_cap_data_struct; 2],
}

const _LINUX_CAPABILITY_VERSION_3: c_uint = 0x20080522;

fn process_has_capability(capability: &Capability) -> bool {
    let header = __user_cap_header_struct {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = __user_cap_data_struct {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };

    assert_eq!(0, unsafe {
        libc::syscall(libc::SYS_capget, &header, &mut data)
    });
    data.effective & (1 << capability.id()) != 0
}

fn file_has_capability(file: &str, capability: &Capability) -> bool {
    let path = CString::new(file).unwrap();
    let attr_name = CString::new("security.capability").unwrap();
    let mut attr_value: [c_char; std::mem::size_of::<__vfs_ns_cap_data_struct>()] =
        unsafe { std::mem::zeroed() };

    let result = unsafe {
        libc::getxattr(
            path.as_ptr(),
            attr_name.as_ptr(),
            attr_value.as_mut_ptr() as *mut libc::c_void,
            attr_value.len() as size_t,
        )
    };

    if result == -1 {
        let errno = unsafe { *libc::__errno_location() };
        if ![libc::ENOENT, libc::ENODATA].contains(&errno) {
            panic!("`getxattr` returned unknown error code {errno}");
        }
        return false; // ENOENT, ENODATA indicates no capability xattr exists
    }

    let file_cap_data: __vfs_ns_cap_data_struct = unsafe { std::mem::transmute(attr_value) };
    file_cap_data.data[0].effective & (1 << capability.id()) != 0
}

pub(crate) fn set_network_namespace(netns: &str) {
    let ns_file_path = CString::new(netns).unwrap();
    let fd: RawFd = unsafe { open(ns_file_path.as_ptr(), O_RDONLY | O_CLOEXEC) };
    assert!(fd >= 0, "Can't open {netns}");

    let result = unsafe { setns(fd, libc::CLONE_NEWNET) };
    if result != 0 {
        panic!("{}", std::io::Error::last_os_error());
    }
}

pub(crate) struct Requirement {
    name: &'static str,
    reason: String,
    permission: Permission,
}

pub(crate) fn check_root(name: &'static str, reason: &str) -> Option<String> {
    check(Requirement {
        name,
        reason: reason.into(),
        permission: Permission::Root,
    })
}

pub(crate) fn check_file_cap(
    name: &'static str,
    path: &str,
    capability: Capability,
    reason: &str,
) -> Option<String> {
    check(Requirement {
        name,
        reason: reason.into(),
        permission: Permission::FileCapability((path.to_string(), capability)),
    })
}

pub(crate) fn check_process_cap(
    name: &'static str,
    capability: Capability,
    reason: &str,
) -> Option<String> {
    check(Requirement {
        name,
        reason: reason.into(),
        permission: Permission::Capability(capability),
    })
}

pub(crate) fn check(requirement: Requirement) -> Option<String> {
    if uid() == 0 {
        // If running as root, all capabilities pass.
        return None;
    }

    let name = &requirement.name;
    let reason = &requirement.reason;

    match &requirement.permission {
        Permission::Root => Some(format!(
            "[Security] {name} ... process requires root to {reason}"
        )),
        Permission::Capability(capability) => {
            if process_has_capability(capability) {
                None
            } else {
                Some(format!(
                    "[Security] {name} ... process requires {capability:?} to {reason}"
                ))
            }
        }
        Permission::FileCapability((path, capability)) => {
            if file_has_capability(path, capability) {
                None
            } else {
                Some(format!(
                    "[Security] {name} ... {path} requires {capability:?} to {reason}"
                ))
            }
        }
    }
}
