use std::ffi::{
    CStr,
    CString,
};
use std::io::ErrorKind;
use std::path::Path;

use libc::{
    c_char,
    cpu_set_t,
    getpwnam_r,
    if_nametoindex,
    sched_setaffinity,
    CPU_SET,
    CPU_SETSIZE,
    CPU_ZERO,
};

macro_rules! run_builder {
    ($cmd:literal) => {
        crate::utility::run_builder!(cwd=None, env=None, cmd=$cmd,)
    };
    ($cmd:literal, $($args:tt)*) => {
        crate::utility::run_builder!(cwd=None, env=None, cmd=$cmd, $($args)*)
    };
    (cwd=$cwd:expr, env=$env:expr, cmd=$cmd:literal, $($args:tt)*) => {
        {
            let cwd: Option<&str> = $cwd;
            let env: Option<&[(&str, String)]> = $env;
            let command_string = format!($cmd, $($args)*);
            log::trace!("{}", command_string);
            let parts: Vec<&str> = command_string.split_whitespace().collect();
            let mut command = std::process::Command::new(parts[0]);
            command.args(&parts[1..]);
            if let Some(cwd) = cwd {
                command.current_dir(cwd);
            }
            if let Some(env) = env {
                for (key, value) in env {
                    command.env(key, value);
                }
            }
            command
        }
    }
}

macro_rules! run_inner {
    (cwd=$cwd:expr, env=$env:expr, err=$err:expr, cmd=$cmd:literal, $($args:tt)*) => {
        {
            let output = crate::utility::run_builder!(cwd=$cwd, env=$env, cmd=$cmd, $($args)*).output().unwrap();
            if $err {
                if !output.status.success() {
                    let stderr = String::from_utf8(output.stderr).unwrap();
                    let command_string = format!($cmd, $($args)*);
                    panic!("{}\n{}", command_string, stderr);
                }
            }
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        }
    };
    (status, cwd=$cwd:expr, env=$env:expr, err=$err:expr, cmd=$cmd:literal, $($args:tt)*) => {
        crate::utility::run_builder!(cwd=$cwd, env=$env, cmd=$cmd, $($args)*).status().unwrap()
    };
}

macro_rules! run {
    ($cmd:literal) => {
        crate::utility::run_inner!(cwd=None, env=None, err=true, cmd=$cmd,)
    };
    ($cmd:literal, $($args:tt)*) => {
        crate::utility::run_inner!(cwd=None, env=None, err=true, cmd=$cmd, $($args)*)
    };
    (cwd=$cwd:expr, $cmd:literal) => {
        crate::utility::run_inner!(cwd=Some($cwd), env=None, err=true, cmd=$cmd,)
    };
    (cwd=$cwd:expr, env=$env:expr, $cmd:literal) => {
        crate::utility::run_inner!(cwd=Some($cwd), env=Some($env), err=true, cmd=$cmd)
    };
    (no_error, $cmd:literal) => {
        crate::utility::run_inner!(cwd=None, env=None, err=false, cmd=$cmd,)
    };
    (status, $cmd:literal) => {
        crate::utility::run_inner!(status, cwd=None, env=None, err=true, cmd=$cmd,)
    };
    (status, $cmd:literal, $($args:tt)*) => {
        crate::utility::run_inner!(status, cwd=None, env=None, err=true, cmd=$cmd, $($args)*)
    };
}

pub(crate) use {
    run,
    run_builder,
    run_inner,
};

pub(crate) fn repermission<T: AsRef<str>>(path: T, uid: u32, gid: u32, perm: u32) {
    let path = CString::new(path.as_ref()).unwrap();
    assert_eq!(0, unsafe { libc::chown(path.as_ptr(), uid, gid) });
    assert_eq!(0, unsafe { libc::chmod(path.as_ptr(), perm) });
}

pub(crate) fn remove_file_not_found_ok<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    match std::fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(crate) fn remove_directory_not_found_ok<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    match std::fs::remove_dir(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

mod externed {
    #[link(name = "c")]
    extern "C" {
        pub(super) fn getuid() -> i32;
        pub(super) fn getlogin_r(name: *mut i8, name_len: u64) -> i32;
    }
}

pub(crate) fn uid() -> i32 {
    unsafe { externed::getuid() }
}

pub(crate) fn username() -> String {
    let mut username: [i8; 32] = [0; 32];
    assert_eq!(0, unsafe {
        externed::getlogin_r(username.as_mut_ptr(), 32)
    });
    unsafe {
        CStr::from_ptr(username.as_ptr())
            .to_str()
            .unwrap()
            .to_owned()
    }
}

pub(crate) fn set_affinity_zero() {
    let mut cpuset: cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(0, unsafe {
        CPU_ZERO(&mut cpuset);
        CPU_SET(0, &mut cpuset);
        sched_setaffinity(0, CPU_SETSIZE as usize, &cpuset)
    });
}

pub(crate) fn get_uid_by_username(username: &str) -> Option<u32> {
    let c_username = CString::new(username).unwrap();

    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize > 0 { bufsize as usize } else { 1024 };

    let mut buf = Vec::with_capacity(bufsize);

    let err = unsafe {
        getpwnam_r(
            c_username.as_ptr(),
            &mut passwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.capacity(),
            &mut result,
        )
    };

    if err == 0 && !result.is_null() {
        Some(unsafe { (*result).pw_uid })
    } else {
        None
    }
}

pub(crate) fn interface_exists(interface: &str) -> bool {
    let interface = CString::new(interface).unwrap();
    let result = unsafe { if_nametoindex(interface.as_ptr() as *const c_char) };
    if result == 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::ENODEV {
            panic!("if_nametoindex failed");
        }
        false
    } else {
        true
    }
}
