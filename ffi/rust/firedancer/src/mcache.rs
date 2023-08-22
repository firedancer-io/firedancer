use std::sync::atomic::{
  compiler_fence,
  Ordering,
};

use firedancer_sys::*;

use crate::*;

pub struct MCache {
    laddr: *mut tango::fd_frag_meta_t,
    mline: *mut tango::fd_frag_meta_t,
    pub(crate) sequence_number: u64,
    depth: u64,

    sync: *mut u64,
    _workspace: Workspace,
}

#[derive(Copy, Clone)]
pub enum MCacheCtl {
    None
}

impl MCacheCtl {
  fn ctl(&self) -> u64 {
    match self {
        MCacheCtl::None => 0,
    }
  }
}

#[derive(Copy, Clone, Debug)]
pub enum Poll {
    CaughtUp,
    Overrun,
    Ready,
}

#[derive(Copy, Clone)]
  pub enum Advance {
    Overrun,
    Normal,
}

impl MCache {
  pub unsafe fn join<T: Into<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
      let workspace = Workspace::map(gaddr)?;
      let laddr = tango::fd_mcache_join(workspace.laddr.as_ptr());
      if laddr.is_null() {
          return Err(());
      }

      let depth = tango::fd_mcache_depth(laddr);
      let sync = tango::fd_mcache_seq_laddr(laddr);
      let sequence_number = tango::fd_mcache_seq_query(sync);
      let mline = laddr.offset(tango::fd_mcache_line_idx(sequence_number, depth) as isize);

      Ok(Self {
          laddr,
          mline,
          sequence_number,
          depth,
          sync,
          _workspace: workspace,
      })
  }

  pub fn depth(&self) -> u64 {
      self.depth
  }

  pub fn chunk(&self) -> u32 {
      unsafe { (*self.mline).__bindgen_anon_1.chunk }
  }

  pub fn housekeep(&self) {
      unsafe { tango::fd_mcache_seq_update(self.sync, self.sequence_number) }
  }

  pub fn poll(&mut self) -> Poll {
      compiler_fence(Ordering::AcqRel);
      let sequence_number_found = unsafe { (*self.mline).__bindgen_anon_1.seq };
      compiler_fence(Ordering::AcqRel);

      let result: i64 = sequence_number_found.wrapping_sub(self.sequence_number) as i64;
      if result < 0 {
        Poll::CaughtUp
      } else if result == 0 {
        Poll::Ready
      } else {
        self.sequence_number = sequence_number_found;
        Poll::Overrun
      }
  }

  pub fn size(&self) -> u16 {
    unsafe { (*self.mline).__bindgen_anon_1.sz }
  }

  pub fn advance(&mut self) -> Advance {
      compiler_fence(Ordering::AcqRel);
      let sequence_number_found = unsafe { (*self.mline).__bindgen_anon_1.seq };
      compiler_fence(Ordering::AcqRel);

      if sequence_number_found != self.sequence_number {
          self.sequence_number = sequence_number_found;
          Advance::Overrun
      } else {
          self.sequence_number += 1;
          self.mline = unsafe {
              self.laddr
                  .offset(tango::fd_mcache_line_idx(self.sequence_number, self.depth) as isize)
          };
          Advance::Normal
      }
  }

  pub fn publish(&mut self, sig: u64, chunk: u64, sz: u64, ctl: MCacheCtl, tsorig: u64, tspub: u64) {
      unsafe { tango::fd_mcache_publish(self.mline, self.depth, self.sequence_number, sig, chunk, sz, ctl.ctl(), tsorig, tspub) }
  }
}
