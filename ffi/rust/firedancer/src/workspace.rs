use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;

use firedancer_sys::*;

use crate::*;

pub struct Workspace {
    pub(crate) laddr: NonNull<c_void>,
    pub(crate) _marker: PhantomData<Cell<c_void>>, // Not covariant
}

impl Drop for Workspace {
    fn drop(&mut self) {
        unsafe { firedancer_sys::util::fd_wksp_unmap(self.laddr.as_ptr()) }
    }
}

impl Workspace {
    pub(crate) unsafe fn map<G: TryInto<GlobalAddress>>(gaddr: G) -> Result<Self, ()> {
        let addr: GlobalAddress = match gaddr.try_into() {
            Ok(addr) => addr,
            _ => return Err(()),
        };
        let laddr = unsafe { util::fd_wksp_map(addr.as_ptr()) };
        if laddr.is_null() {
            Err(())
        } else {
            Ok(Self {
                laddr: NonNull::new(laddr).unwrap(),
                _marker: PhantomData,
            })
        }
    }
}
