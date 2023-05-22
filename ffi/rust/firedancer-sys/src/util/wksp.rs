pub use crate::generated::fd_wksp_t;
pub use crate::generated::{
    fd_wksp_cstr,
    fd_wksp_cstr_alloc,
    fd_wksp_cstr_free,
    fd_wksp_cstr_laddr,
    fd_wksp_cstr_memset,
};
pub use crate::generated::{
    fd_wksp_map,
    fd_wksp_pod_attach,
    fd_wksp_pod_detach,
    fd_wksp_pod_map,
    fd_wksp_pod_unmap,
    fd_wksp_unmap,
};
pub use crate::generated::{
    fd_wksp_align,
    fd_wksp_attach,
    fd_wksp_containing,
    fd_wksp_delete,
    fd_wksp_detach,
    fd_wksp_footprint,
    fd_wksp_gaddr,
    fd_wksp_join,
    fd_wksp_laddr,
    fd_wksp_leave,
    fd_wksp_name,
    fd_wksp_new,
};
pub use crate::generated::{
    fd_wksp_alloc_at_least,
    fd_wksp_alloc_laddr,
    fd_wksp_free,
    fd_wksp_free_laddr,
};

#[inline]
pub unsafe fn fd_wksp_alloc(wksp: *mut fd_wksp_t, align: u64, sz: u64, tag: u64) -> u64 {
    let mut lo = 0u64;
    let mut hi = 0u64;
    unsafe { fd_wksp_alloc_at_least(wksp, align, sz, tag, &mut lo, &mut hi) }
}
