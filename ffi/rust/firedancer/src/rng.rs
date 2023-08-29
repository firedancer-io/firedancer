use std::ffi::c_void;

use firedancer_sys::*;

pub struct Rng {
    inner: util::fd_rng_t,
    shmem: *mut c_void,
}

impl Drop for Rng {
    fn drop(&mut self) {
        unsafe { util::fd_rng_leave(&mut self.inner) };
        unsafe { util::fd_rng_delete(self.shmem) };
    }
}

impl Rng {
    pub fn new(seed: u32, id: u64) -> Result<Self, ()> {
        let mut inner = util::fd_rng_t { seq: 0, idx: 0 };

        let shmem = unsafe { util::fd_rng_new(&mut inner as *mut _ as *mut c_void, seed, id) };
        if shmem.is_null() {
            return Err(());
        }

        let rng = unsafe { util::fd_rng_join(shmem) };
        if rng.is_null() {
            return Err(());
        }

        Ok(Rng { inner, shmem })
    }

    pub fn async_reload(&mut self, min: u64) -> u64 {
        unsafe { util::fd_tempo_async_reload(&mut self.inner, min) }
    }
}

pub fn boot() {
    let mut argc: i32 = 0;
    unsafe {
        util::fd_boot(&mut argc as *mut _, std::ptr::null_mut());
    }
}
