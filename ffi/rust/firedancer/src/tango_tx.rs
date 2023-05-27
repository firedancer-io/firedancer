use std::{
    ffi::CString,
    hint::spin_loop,
    mem::transmute,
    os::raw::c_void,
    ptr,
    sync::atomic::{
        compiler_fence,
        Ordering,
    },
    time::Duration,
};
use anyhow::anyhow;
pub use anyhow::Result;
use firedancer_sys::{
    tango::{
        fd_dcache_compact_chunk0,
        fd_dcache_compact_is_safe,
        fd_dcache_join,
        fd_dcache_leave,
        fd_frag_meta_t,
        fd_mcache_depth,
        fd_mcache_join,
        fd_mcache_leave,
        fd_mcache_publish,
        fd_mcache_seq_laddr,
        fd_mcache_seq_query,
        fd_mcache_seq_update,
        fd_tempo_lazy_default, fd_dcache_compact_wmark, fd_chunk_to_laddr, fd_frag_meta_ctl, fd_dcache_compact_next, fd_seq_inc,
    },
    util::{
        fd_pod_query_subpod,
        fd_wksp_containing,
        fd_wksp_pod_attach,
        fd_wksp_pod_map,
    },
};
use minstant::{Instant, Anchor};
use rand::prelude::*;

/// TangoTx exposes a simple API for publishing data to a Tango mcache/dcache message queue.
/// This producer does not respect flow control.
pub struct TangoTx {
    // config
    mcache: *mut fd_frag_meta_t,
    dcache: *mut u8,
    max_payload_size: u64,
    depth: u64,
    wmark: u64,
    chunk0: u64,
    sync: *mut u64,
    seq: u64,
    chunk: u64,
    base: *const c_void,
    housekeeping_interval_ns: i64,
    next_housekeeping: Instant, // pack.out-mcache
                                //
}

unsafe impl Send for TangoTx {}
unsafe impl Sync for TangoTx {}

impl TangoTx {
    pub unsafe fn new(
        pod_gaddr: &str,
        cfg_path: &str
    ) -> Result<Self> {
        let pod_gaddr_cstr = CString::new(pod_gaddr).unwrap();
        let cfg_path_cstr = CString::new(cfg_path).unwrap();

        let max_payload_size = 1024 * 1024; // TODO

        let mcache: *mut fd_frag_meta_t;
        let dcache: *mut u8;

        unsafe {
            let pod = fd_wksp_pod_attach(pod_gaddr_cstr.as_ptr());
            let cfg_pod = fd_pod_query_subpod(pod, cfg_path_cstr.as_ptr());

            mcache = fd_mcache_join(fd_wksp_pod_map(
                cfg_pod,
                CString::new("mcache")?.as_ptr() as *const i8,
            ));
            if mcache.is_null() {
                return Err(anyhow!("fd_mcache_join failed"));
            }
            dcache = fd_dcache_join(fd_wksp_pod_map(
                cfg_pod,
                CString::new("dcache")?.as_ptr() as *const i8,
            ));
            if dcache.is_null() {
                fd_mcache_leave(mcache);
                return Err(anyhow!("fd_dcache_join failed"));
            }
        }

        // mcache setup
        let mcache = mcache;
        let depth = fd_mcache_depth(mcache);
        let sync = fd_mcache_seq_laddr(mcache);
        let seq = fd_mcache_seq_query(sync);

        // Find the base address of the dcache
        let base = fd_wksp_containing(dcache as *const c_void) as *const c_void;
        if base.is_null() {
            return Err(anyhow!("fd_wksp_containing failed"));
        }
        println!("base: {:?}. seq{}", base, seq);

        // Check to see if the dcache base address is safe
        if 0 == fd_dcache_compact_is_safe(base, dcache as *const c_void, max_payload_size, depth) {
            return Err(anyhow!("dcache not compatible with wksp base, pkt-framing, pkt-payload-max and mcache depth"));
        }

        // Initialize the chunk location
        let chunk0: u64 =
            fd_dcache_compact_chunk0(base as *const c_void, dcache as *const c_void) as u64;
        let wmark: u64 = fd_dcache_compact_wmark(base, dcache as *const c_void, max_payload_size);
        let chunk = chunk0;

        let housekeeping_interval_ns = fd_tempo_lazy_default(depth);
        Ok(Self {
            mcache,
            dcache,
            max_payload_size,
            depth,
            wmark,
            chunk0,
            sync,
            seq,
            chunk,
            base,
            housekeeping_interval_ns,
            next_housekeeping: Instant::now(),
        })
    }

    pub unsafe fn publish(&mut self, data: &[u8])  {
        // Set frequency of houskeeping operations

        let mut rng = rand::thread_rng();

        // Actually publish the data
        // Pull the latest bytes out of the crossbeam channel
        let sz = data.len() as u64;
        // Send the data
        let p = fd_chunk_to_laddr(transmute(self.base), self.chunk) as *mut u8;

        ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());

        let now = Instant::now();
        let nowv = now.as_unix_nanos(&Anchor::new());
        let ctl = fd_frag_meta_ctl(0, 1, 1, 0);
        fd_mcache_publish(
            self.mcache,
            self.depth,
            self.seq,
            sz,
            self.chunk,
            sz,
            ctl,
            nowv,
            nowv,
        );

        self.chunk = fd_dcache_compact_next(self.chunk, sz, self.chunk0, self.wmark);
        self.seq = fd_seq_inc(self.seq, 1);

        // Do housekeeping at intervals

        if now >= self.next_housekeeping {
            // Send synchronization info
            fd_mcache_seq_update(self.sync, self.seq);

            self.next_housekeeping = now
                + Duration::from_nanos(rng.gen_range(
                    self.housekeeping_interval_ns,
                    2 * self.housekeeping_interval_ns,
                ) as u64);
        }
        // Ok(())
    }
}

impl Drop for TangoTx {
    fn drop(&mut self) {
        unsafe {
            fd_mcache_leave(self.mcache);
            fd_dcache_leave(self.dcache);
        }
    }
}
