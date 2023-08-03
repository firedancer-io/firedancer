use std::ffi::c_ulong;
use std::ptr::{
    read_volatile,
    write_volatile,
};

use firedancer_sys::*;

use crate::*;

pub struct FSeq {
    pub(crate) laddr: *mut c_ulong,
    pub(crate) diagnostic: *mut c_ulong,
    _workspace: Workspace,
}

impl Drop for FSeq {
    fn drop(&mut self) {
        unsafe { tango::fd_fseq_leave(self.laddr) };
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum FSeqDiag {
    PublishedCount = tango::FD_FSEQ_DIAG_PUB_CNT,
    PublishedSize = tango::FD_FSEQ_DIAG_PUB_SZ,
    FilteredCount = tango::FD_FSEQ_DIAG_FILT_CNT,
    FilteredSize = tango::FD_FSEQ_DIAG_FILT_SZ,
    OverrunPollingCount = tango::FD_FSEQ_DIAG_OVRNP_CNT,
    OverrunReadingCount = tango::FD_FSEQ_DIAG_OVRNR_CNT,
    SlowCount = tango::FD_FSEQ_DIAG_SLOW_CNT,
}

impl FSeq {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
      let workspace = Workspace::map(gaddr)?;
      let laddr = tango::fd_fseq_join(workspace.laddr.as_ptr());
      if laddr.is_null() {
          Err(())
      } else {
          let diagnostic = tango::fd_fseq_app_laddr(laddr) as *mut c_ulong;
          if diagnostic.is_null() {
              Err(())
          } else {
              Ok(Self {
                  laddr,
                  diagnostic,
                  _workspace: workspace,
              })
          }
      }
  }

  pub unsafe fn set(&self, diag: u64, value: u64) {
      write_volatile(self.diagnostic.offset(diag as isize), value)
  }

  pub unsafe fn increment(&self, diag: u64, value: u64) {
      let offset = self.diagnostic.offset(diag as isize);
      write_volatile(offset, read_volatile(offset) + value)
  }

  pub fn rx_cr_return(&self, mcache: &MCache) {
      unsafe { tango::fd_fctl_rx_cr_return(self.laddr, mcache.sequence_number) }
  }
}