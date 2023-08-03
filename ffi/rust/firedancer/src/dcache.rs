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

  pub unsafe fn slice<'a>(&self, chunk: u64, offset: u64, len: u64) -> &'a[u8] {
    let laddr = tango::fd_chunk_to_laddr_const(self.wksp as *const c_void, chunk);
    std::slice::from_raw_parts(laddr.offset(offset as isize) as *const u8, len as usize)
  }
}
