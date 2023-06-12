use firedancer_sys::*;

use std::ffi::c_void;

use crate::*;

pub struct DCache {
    laddr: *mut u8,
    wksp: *mut util::fd_wksp_t,
    _workspace: Workspace,
}

impl Drop for DCache {
    fn drop(&mut self) {
        unsafe { tango::fd_dcache_leave(self.laddr) };
    }
}

impl DCache {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
        let workspace = Workspace::map(gaddr)?;
        let laddr = tango::fd_dcache_join(workspace.laddr.as_ptr());
        if laddr.is_null() {
            return Err(());
        }

        let wksp = util::fd_wksp_containing(laddr as *const c_void);
        Ok(Self {
            laddr,
            wksp,
            _workspace: workspace,
        })
    }

    pub unsafe fn copy_from(&self, other: &DCache, chunk: u64, size: u64) {
        let in_laddr = tango::fd_chunk_to_laddr_const(other.wksp as *const c_void, chunk);
        let out_laddr = tango::fd_chunk_to_laddr(self.wksp as *mut c_void, chunk);
        std::ptr::copy_nonoverlapping(in_laddr, out_laddr, size as usize);
    }
}
