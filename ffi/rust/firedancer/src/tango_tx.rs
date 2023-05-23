use std::{
    ptr,
    ffi::CString,
    hint::spin_loop,
    mem::transmute,
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
        fd_chunk_to_laddr_const,
        fd_dcache_join,
        fd_dcache_leave,
        fd_frag_meta_seq_query,
        fd_frag_meta_t,
        fd_mcache_depth,
        fd_mcache_join,
        fd_mcache_leave,
        fd_mcache_line_idx,
        fd_mcache_seq_laddr_const,
        fd_mcache_seq_query,
        fd_tempo_lazy_default,
    },
    util::{
        fd_pod_query_subpod,
        fd_wksp_containing,
        fd_wksp_pod_attach,
        fd_wksp_pod_map,
    },
};
use minstant::Instant;
use rand::prelude::*;

/// TangoTx exposes a simple API for publishing data to a Tango mcache/dcache message queue.
/// This producer does not respect flow control.
pub struct TangoTx {

    // config
    mcache: *mut fd_frag_meta_t,
    dcache: *mut u8,
    max_payload_size: usize,

    // pack.out-mcache
    // 

    receiver: crossbeam_channel::Receiver<Vec<u8>>,
}

impl TangoTx {
    pub fn new(
        pod_gaddr: &str,
        cfg_path: &str,
        mcache_path: &str,
        dcache_path: &str,
        receiver: crossbeam_channel::Receiver<Vec<u8>>) -> Result<Self> {
        let pod_gaddr_cstr = CString::new(pod_gaddr).unwrap();
        let cfg_path_cstr = CString::new(cfg_path).unwrap();

        let max_payload_size = 500; // TODO

        let mcache: *mut fd_frag_meta_t;
        let dcache: *mut u8;

        unsafe {
            let pod = fd_wksp_pod_attach(pod_gaddr_cstr.as_ptr());
            let cfg_pod = fd_pod_query_subpod(pod, cfg_path_cstr.as_ptr());

            mcache = fd_mcache_join(fd_wksp_pod_map(
                cfg_pod,
                mcache_path.as_bytes().as_ptr() as *const i8,
            ));
            if mcache.is_null() {
                return Err(anyhow!("fd_mcache_join failed"));
            }
            dcache = fd_dcache_join(fd_wksp_pod_map(
                cfg_pod,
                dcache_path.as_bytes().as_ptr() as *const i8,
            ));
            if dcache.is_null() {
                fd_mcache_leave(mcache);
                return Err(anyhow!("fd_dcache_join failed"));
            }
        }

        Ok(Self {
            mcache,
            dcache,
            max_payload_size,
            receiver,
        })
    }

    pub unsafe fn run(&mut self) -> Result<()> {
        // mcache setup
        let mcache = self.mcache;
        let depth = fd_mcache_depth(mcache);
        let sync = fd_mcache_seq_laddr_const(mcache);
        let mut seq = fd_mcache_seq_query(sync);

        // Find the base address of the dcache
        let base = fd_wksp_containing( self.dcache );
        if base.is_null() {
            return Err(anyhow!("fd_wksp_containing failed"));
        }

        let max_pkt_size = 200000; // TODO: choose better number

        // Check to see if the dcache base address is safe
        if !fd_dcache_compact_is_safe( base, dcache, pkt_max, depth ) {
            return Err(anyhow!("dcache not compatible with wksp base, pkt-framing, pkt-payload-max and mcache depth"));
        }

        // Initialize the chunk location
        let chunk = fd_dcache_compact_chunk0( base, dcache );
        ulong wmark  = fd_dcache_compact_wmark ( base, dcache, pkt_max );

        // Set frequency of houskeeping operations
        let mut next_housekeeping = Instant::now();
        let housekeeping_interval_ns = fd_tempo_lazy_default(depth);
        let mut rng = rand::thread_rng();

        // Continually publish data to the queue
        loop {
            // Do housekeeping at intervals
            let now = Instant::now();
            if now >= next_housekeeping {
                // Send synchronization info
                fd_mcache_seq_update( sync, seq );

                next_housekeeping = now
                    + Duration::from_nanos(
                        rng.gen_range(housekeeping_interval_ns, 2 * housekeeping_interval_ns)
                            as u64,
                    );
            }

            // Actually publish the data
            // Pull the latest bytes out of the crossbeam channel
            if ( let Ok(bs) = self.receiver.try_recv() ) {
                // Send the data
                let p = fd_chunk_to_laddr_const(
                    transmute(base),
                    chunk
                ) as *const u8;
                let mut bytes = Vec::with_capacity(size.into());
                ptr::copy_nonoverlapping(bytes.as_mut_ptr(), chunk, size.into());

                let ctl = fd_frag_meta_ctl( 0, 1, 1, 0 );
                fd_mcache_publish( mcache, depth, seq, seq, chunk, size.into(), ctl, now, now );
            }

            chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
            seq   = fd_seq_inc( seq, 1 );
        }
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
