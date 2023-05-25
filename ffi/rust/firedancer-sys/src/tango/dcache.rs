use std::os::raw::c_void;

use crate::generated::FD_CHUNK_LG_SZ;
pub use crate::generated::{
    fd_dcache_align,
    fd_dcache_app_laddr,
    fd_dcache_app_laddr_const,
    fd_dcache_app_sz,
    fd_dcache_compact_is_safe,
    fd_dcache_data_sz,
    fd_dcache_delete,
    fd_dcache_footprint,
    fd_dcache_join,
    fd_dcache_leave,
    fd_dcache_new,
    fd_dcache_req_data_sz,
    FD_DCACHE_ALIGN,
    FD_DCACHE_GUARD_FOOTPRINT,
};

#[inline(always)]
pub fn fd_dcache_compact_chunk0(base: *const c_void, dcache: *const c_void) -> usize {
    ((dcache as usize) - (base as usize)) >> FD_CHUNK_LG_SZ
}
