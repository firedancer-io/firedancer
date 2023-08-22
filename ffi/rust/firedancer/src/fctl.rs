use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::{
    align_of,
    size_of,
};
use std::ptr::null_mut;

use firedancer_sys::*;

use crate::*;

macro_rules! footprint {
    ( $rx_max:expr ) => {
        layout!(
            align = tango::FD_FCTL_ALIGN as usize,
            [
                (
                    align_of::<tango::fd_fctl_t>(),
                    size_of::<tango::fd_fctl_t>()
                ),
                (
                    align_of::<tango::fd_fctl_private_rx_t>(),
                    $rx_max * size_of::<tango::fd_fctl_private_rx_t>()
                ),
            ]
        )
    };
}

pub struct FCtl<'a, 'b> {
    _stack: Vec<u8>,
    shmem: *mut c_void,
    fctl: *mut tango::fd_fctl_t,
    _seq: PhantomData<&'a u64>,
    _slow: PhantomData<&'b mut u64>,
}

impl<'a, 'b> Drop for FCtl<'a, 'b> {
    fn drop(&mut self) {
        unsafe { tango::fd_fctl_leave(self.fctl) };
        unsafe { tango::fd_fctl_delete(self.shmem) };
    }
}

impl<'a, 'b> FCtl<'a, 'b> {
    pub fn new(
      cr_burst: u64,
      cr_max: u64,
      cr_resume: u64,
      cr_refill: u64,
      fseq: &FSeq,
  ) -> Result<Self, ()> {
      let mut stack = vec![0; footprint!(1usize)];
      let shmem = unsafe { tango::fd_fctl_new(stack.as_mut_ptr() as *mut _, 1) };
      if shmem.is_null() {
          return Err(());
      }

      let fctl = unsafe { tango::fd_fctl_join(shmem) };
      if fctl.is_null() {
          return Err(());
      }

      let fctl = unsafe {
          tango::fd_fctl_cfg_rx_add(
              fctl,
              cr_max,
              fseq.laddr,
              fseq.diagnostic.offset(FSeqDiag::SlowCount as isize),
          )
      };
      if fctl.is_null() {
          return Err(());
      }

      let fctl = unsafe { tango::fd_fctl_cfg_done(fctl, cr_burst, cr_max, cr_resume, cr_refill) };

      Ok(FCtl {
          _stack: stack,
          shmem,
          fctl,
          _seq: PhantomData,
          _slow: PhantomData,
      })
  }

  pub fn tx_cr_update(&self, cr_avail: u64, mcache: &MCache) -> u64 {
      unsafe { tango::fd_fctl_tx_cr_update(self.fctl, cr_avail, mcache.sequence_number) }
  }
}

pub fn housekeeping_default_interval_nanos(cr_max: u64) -> i64 {
  unsafe { util::fd_tempo_lazy_default(cr_max) }
}

pub fn minimum_housekeeping_tick_interval(lazy: i64) -> u64 {
  unsafe { util::fd_tempo_async_min(lazy, 1, util::fd_tempo_tick_per_ns(null_mut()) as f32) }
}
