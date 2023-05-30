use firedancer_sys::util;
use std::time::SystemTime;

pub fn fd_log_wallclock() -> i64 {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    since_epoch.as_nanos() as i64
}

pub fn fd_log_private_1(level: i32, now: i64, file: &str, line: u32, func: &str, msg: &str) {
    let file_cstr = std::ffi::CString::new(file).unwrap();
    let func_cstr = std::ffi::CString::new(func).unwrap();
    let msg_cstr = std::ffi::CString::new(msg).unwrap();

    unsafe {
        util::fd_log_private_1(
            level,
            now,
            file_cstr.as_ptr(),
            line as i32,
            func_cstr.as_ptr(),
            msg_cstr.as_ptr(),
        );
    }
}

#[macro_export]
macro_rules! function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

#[macro_export]
macro_rules! fd_log_debug {
    ($($arg:tt)*) => {
        $crate::log::fd_log_private_1(0, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_info {
    ($($arg:tt)*) => {
        $crate::log::fd_log_private_1(1, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_notice {
    ($($arg:tt)*) => {
        $crate::log::fd_log_private_1(2, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_warning {
    ($($arg:tt)*) => {
        $crate::log::fd_log_private_1(3, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_err {
    ($($arg:tt)*) => {
        fd_log_private_2(4, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_crit {
    ($($arg:tt)*) => {
        fd_log_private_2(5, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_alert {
    ($($arg:tt)*) => {
        fd_log_private_2(6, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}

#[macro_export]
macro_rules! fd_log_emerg {
    ($($arg:tt)*) => {
        fd_log_private_2(7, $crate::log::fd_log_wallclock(), std::file!(), std::line!(), $crate::function_name!(), &format!($($arg)*));
    };
}
