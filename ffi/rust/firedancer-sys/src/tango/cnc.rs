pub use crate::generated::fd_cnc_t;
pub use crate::generated::{
    FD_CNC_ALIGN,
    FD_CNC_APP_ALIGN,
    FD_CNC_DIAG_BACKP_CNT,
    FD_CNC_DIAG_IN_BACKP,
    FD_CNC_ERR_AGAIN,
    FD_CNC_ERR_FAIL,
    FD_CNC_ERR_INVAL,
    FD_CNC_ERR_UNSUP,
    FD_CNC_MAGIC,
    FD_CNC_SIGNAL_BOOT,
    FD_CNC_SIGNAL_CSTR_BUF_MAX,
    FD_CNC_SIGNAL_FAIL,
    FD_CNC_SIGNAL_HALT,
    FD_CNC_SIGNAL_RUN,
    FD_CNC_SUCCESS,
};
pub use crate::generated::{
    fd_cnc_align,
    fd_cnc_delete,
    fd_cnc_footprint,
    fd_cnc_join,
    fd_cnc_leave,
    fd_cnc_new,
    fd_cnc_open,
    fd_cnc_signal_cstr,
    fd_cnc_strerror,
    fd_cnc_wait,
    fd_cstr_to_cnc_signal,
};
use std::{
    os::raw::c_void,
    sync::atomic::{
        compiler_fence,
        Ordering,
    },
};

#[inline(always)]
pub unsafe fn fd_cnc_app_sz(cnc: *const fd_cnc_t) -> u64 {
    (*cnc).app_sz
}

#[inline(always)]
pub unsafe fn fd_cnc_app_laddr(cnc: *mut fd_cnc_t) -> *mut c_void {
    (cnc as *mut u8).add(64usize) as *mut c_void
}

#[inline(always)]
pub unsafe fn fd_cnc_app_laddr_const(cnc: *const fd_cnc_t) -> *const c_void {
    (cnc as *const u8).add(64usize) as *const c_void
}

#[inline(always)]
pub unsafe fn fd_cnc_type(cnc: *const fd_cnc_t) -> u64 {
    (*cnc).type_
}

#[inline(always)]
pub unsafe fn fd_cnc_heartbeat0(cnc: *const fd_cnc_t) -> i64 {
    (*cnc).heartbeat0
}

#[inline(always)]
pub unsafe fn fd_cnc_heartbeat_query(cnc: *const fd_cnc_t) -> i64 {
    compiler_fence(Ordering::AcqRel);
    let then = (*cnc).heartbeat;
    compiler_fence(Ordering::AcqRel);
    then
}

#[inline(always)]
pub unsafe fn fd_cnc_heartbeat(cnc: *mut fd_cnc_t, now: i64) {
    compiler_fence(Ordering::AcqRel);
    (*cnc).heartbeat = now;
    compiler_fence(Ordering::AcqRel);
}

#[inline(always)]
pub unsafe fn fd_cnc_close(cnc: *mut fd_cnc_t) {
    compiler_fence(Ordering::AcqRel);
    (*cnc).lock = 0u64;
    compiler_fence(Ordering::AcqRel);
}
