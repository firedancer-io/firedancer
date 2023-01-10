pub use crate::generated::{
    FD_MCACHE_ALIGN,
    FD_MCACHE_BLOCK,
    FD_MCACHE_LG_BLOCK,
    FD_MCACHE_LG_INTERLEAVE,
    FD_MCACHE_SEQ_CNT,
};
pub use crate::generated::fd_frag_meta_t;
pub use crate::generated::{
    fd_mcache_align,
    fd_mcache_app_laddr,
    fd_mcache_app_laddr_const,
    fd_mcache_app_sz,
    fd_mcache_delete,
    fd_mcache_depth,
    fd_mcache_footprint,
    fd_mcache_join,
    fd_mcache_leave,
    fd_mcache_new,
    fd_mcache_seq0,
    fd_mcache_seq_laddr,
    fd_mcache_seq_laddr_const,
};
use std::sync::atomic::{
    compiler_fence,
    Ordering,
};

#[inline(always)]
pub unsafe fn fd_mcache_seq_query(seq_ptr: *const u64) -> u64 {
    compiler_fence(Ordering::AcqRel);
    let ret = *seq_ptr;
    compiler_fence(Ordering::AcqRel);
    ret
}

#[inline(always)]
pub unsafe fn fd_mcache_seq_update(seq_ptr: *mut u64, seq: u64) {
    compiler_fence(Ordering::AcqRel);
    *seq_ptr = seq;
    compiler_fence(Ordering::AcqRel);
}

#[inline(always)]
pub unsafe fn fd_mcache_line_idx(seq: u64, depth: u64) -> u64 {
    seq & (depth.wrapping_sub(1u64))
}

#[inline]
pub unsafe fn fd_mcache_publish(
    mcache: *mut fd_frag_meta_t,
    depth: u64,
    seq: u64,
    sig: u64,
    chunk: u64,
    sz: u64,
    ctl: u64,
    tsorig: u64,
    tspub: u64,
) {
    let meta_union = mcache.add(fd_mcache_line_idx(seq, depth) as usize);
    let meta = (*meta_union).__bindgen_anon_1.as_mut();

    compiler_fence(Ordering::AcqRel);
    meta.seq = seq.wrapping_sub(1u64);
    compiler_fence(Ordering::AcqRel);
    meta.sig = sig;
    meta.chunk = chunk as u32;
    meta.sz = sz as u16;
    meta.ctl = ctl as u16;
    meta.tsorig = tsorig as u32;
    meta.tspub = tspub as u32;
    compiler_fence(Ordering::AcqRel);
    meta.seq = seq;
    compiler_fence(Ordering::AcqRel);
}
