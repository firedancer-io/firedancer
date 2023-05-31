use std::ffi::c_void;
use std::ptr::{
    null,
    null_mut,
};

pub use crate::generated::{
    fd_pod_cnt_subpod,
    fd_pod_info_t,
    fd_pod_query,
    FD_POD_VAL_TYPE_BUF,
    FD_POD_VAL_TYPE_CHAR,
    FD_POD_VAL_TYPE_CSTR,
    FD_POD_VAL_TYPE_DOUBLE,
    FD_POD_VAL_TYPE_FLOAT,
    FD_POD_VAL_TYPE_INT,
    FD_POD_VAL_TYPE_INT128,
    FD_POD_VAL_TYPE_LONG,
    FD_POD_VAL_TYPE_SCHAR,
    FD_POD_VAL_TYPE_SHORT,
    FD_POD_VAL_TYPE_SUBPOD,
    FD_POD_VAL_TYPE_UCHAR,
    FD_POD_VAL_TYPE_UINT,
    FD_POD_VAL_TYPE_UINT128,
    FD_POD_VAL_TYPE_ULONG,
    FD_POD_VAL_TYPE_USHORT,
};

impl Default for fd_pod_info_t {
    fn default() -> Self {
        Self {
            key_sz: 0,
            key: null(),
            val_type: 0,
            val_sz: 0,
            val: null(),
            parent: null_mut(),
        }
    }
}

macro_rules! impl_query {
    ( $name:ident, $type:ty, { $($value:tt)* }) => {
        paste::paste! {
            #[inline]
            pub unsafe fn [<fd_pod_query_ $name>](
                pod: *const u8,
                path: *const i8,
                default: $type
            ) -> $type {
                let mut info: fd_pod_info_t = fd_pod_info_t::default();
                if fd_pod_query(pod, path, &mut info) != 0 || info.val_type != [<FD_POD_VAL_TYPE_ $name:upper>] as i32 {
                    return default;
                }
                $($value)*
                val(&info)
            }
        }
    };
}

macro_rules! impl_query_pun {
    ( $name:ident, $type:ty ) => {
        impl_query!($name, $type, {
            unsafe fn val(info: &fd_pod_info_t) -> $type {
                *(info.val as *const $type)
            }
        });
    };
}

impl_query_pun!(char, char);
impl_query_pun!(schar, char);
impl_query_pun!(uchar, u8);

macro_rules! impl_query_svw_dec {
    ( $name:ident, $type:ty ) => {
        impl_query!($name, $type, {
            unsafe fn val(info: &fd_pod_info_t) -> $type {
                let mut u: u64 = 0;
                let _ = super::bits::fd_ulong_svw_dec(info.val as *const u8, &mut u);
                u as $type
            }
        });
    };
}

impl_query_svw_dec!(ushort, u16);
impl_query_svw_dec!(uint, u32);
impl_query_svw_dec!(ulong, u64);

macro_rules! impl_query_svw_zz_dec {
    ( $name:ident, $type:ty ) => {
        impl_query!($name, $type, {
            unsafe fn val(info: &fd_pod_info_t) -> $type {
                let mut u: u64 = 0;
                let _ = super::bits::fd_ulong_svw_dec(info.val as *const u8, &mut u);
                super::bits::fd_long_zz_dec(u) as $type
            }
        });
    };
}

impl_query_svw_zz_dec!(short, i16);
impl_query_svw_zz_dec!(int, i32);
impl_query_svw_zz_dec!(long, i64);

pub unsafe fn fd_pod_query_subpod(pod: *const u8, path: *const i8) -> *const u8 {
    let mut info: fd_pod_info_t = fd_pod_info_t::default();
    if fd_pod_query(pod, path, &mut info) != 0 || info.val_type != FD_POD_VAL_TYPE_SUBPOD as i32 {
        return null();
    }
    info.val as *const u8
}

pub unsafe fn fd_pod_query_buf(
    pod: *const u8,
    path: *const i8,
    opt_buf_sz: *mut u64,
) -> *const c_void {
    let mut info: fd_pod_info_t = fd_pod_info_t::default();
    if fd_pod_query(pod, path, &mut info) != 0 || info.val_type != FD_POD_VAL_TYPE_BUF as i32 {
        return null();
    }
    if !opt_buf_sz.is_null() {
        *opt_buf_sz = info.val_sz;
    }
    info.val
}

impl_query!(cstr, *const char, {
    unsafe fn val(info: &fd_pod_info_t) -> *const char {
        if info.val_sz > 0 {
            info.val as *const char
        } else {
            null()
        }
    }
});
