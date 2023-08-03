use std::ffi::c_ulong;
use std::ptr::{
    read_volatile,
    write_volatile,
};
use firedancer_sys::*;

use crate::*;

pub struct Cnc {
    laddr: *mut tango::fd_cnc_t,
    diagnostic: *mut c_ulong,
    _workspace: Workspace,
}

impl Drop for Cnc {
    fn drop(&mut self) {
        unsafe { tango::fd_cnc_leave(self.laddr) };
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum CncSignal {
    Run = tango::FD_CNC_SIGNAL_RUN,
    Boot = tango::FD_CNC_SIGNAL_BOOT,
    Fail = tango::FD_CNC_SIGNAL_FAIL,
    Halt = tango::FD_CNC_SIGNAL_HALT,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum CncDiag {
    InBackpressure = tango::FD_CNC_DIAG_IN_BACKP,
    BackpressureCount = tango::FD_CNC_DIAG_BACKP_CNT,
}

impl Cnc {
    pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
      let workspace = Workspace::map(gaddr)?;
      let laddr = tango::fd_cnc_join(workspace.laddr.as_ptr());
      if laddr.is_null() {
          Err(())
      } else {
          let diagnostic = tango::fd_cnc_app_laddr(laddr) as *mut c_ulong;
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

  pub fn query(&self) -> u64 {
      unsafe { tango::fd_cnc_signal_query(self.laddr) }
  }

  pub fn signal(&self, signal: u64) {
      unsafe { tango::fd_cnc_signal(self.laddr, signal) }
  }

  pub unsafe fn set(&self, diag: u64, value: u64) {
    write_volatile(self.diagnostic.offset(diag as isize), value)
  }

  pub unsafe fn increment(&self, diag: u64, value: u64) {
      let offset = self.diagnostic.offset(diag as isize);
      write_volatile(offset, read_volatile(offset) + value)
  }

  pub fn heartbeat(&self, now: i64) {
      unsafe { tango::fd_cnc_heartbeat(self.laddr, now) }
  }
}
