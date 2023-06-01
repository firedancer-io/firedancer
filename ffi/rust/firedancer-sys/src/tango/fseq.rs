use std::ffi::c_void;
use std::sync::atomic::{
    compiler_fence,
    Ordering,
};

pub use crate::generated::{
    fd_fseq_align,
    fd_fseq_delete,
    fd_fseq_footprint,
    fd_fseq_join,
    fd_fseq_leave,
    fd_fseq_new,
    FD_FSEQ_ALIGN,
    FD_FSEQ_APP_ALIGN,
    FD_FSEQ_APP_FOOTPRINT,
    FD_FSEQ_DIAG_FILT_CNT,
    FD_FSEQ_DIAG_FILT_SZ,
    FD_FSEQ_DIAG_OVRNP_CNT,
    FD_FSEQ_DIAG_OVRNR_CNT,
    FD_FSEQ_DIAG_PUB_CNT,
    FD_FSEQ_DIAG_PUB_SZ,
    FD_FSEQ_DIAG_SLOW_CNT,
    FD_FSEQ_FOOTPRINT,
};

pub unsafe fn fd_fseq_app_laddr_const(fseq: *const u64) -> *const c_void {
    fseq.add(2) as *const c_void
}

pub unsafe fn fd_fseq_seq0(fseq: *const u64) -> u64 {
    *fseq.sub(1)
}

#[inline(always)]
pub unsafe fn fd_fseq_query(fseq: *const u64) -> u64 {
    compiler_fence(Ordering::AcqRel);
    let res = *fseq;
    compiler_fence(Ordering::AcqRel);
    res
}

#[inline(always)]
pub unsafe fn fd_fseq_update(fseq: *mut u64, seq: u64) {
    compiler_fence(Ordering::AcqRel);
    *fseq = seq;
    compiler_fence(Ordering::AcqRel);
}
