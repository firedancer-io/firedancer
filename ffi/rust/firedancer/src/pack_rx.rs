use std::{
    ffi::CString,
    hint::spin_loop,
    mem::transmute,
    sync::atomic::{
        compiler_fence,
        Ordering,
    },
    time::Duration,
};
use anyhow::{
    anyhow,
    Result,
};
use firedancer_sys::{
    tango::{
        fd_chunk_to_laddr_const,
        fd_dcache_join,
        fd_dcache_leave,
        fd_frag_meta_seq_query,
        fd_frag_meta_t,
        fd_fseq_app_laddr,
        fd_fseq_join,
        fd_fseq_leave,
        fd_mcache_depth,
        fd_mcache_join,
        fd_mcache_leave,
        fd_mcache_line_idx,
        fd_mcache_seq_laddr_const,
        fd_mcache_seq_query,
        fd_tempo_lazy_default,
        FD_FSEQ_DIAG_FILT_CNT,
        FD_FSEQ_DIAG_FILT_SZ,
        FD_FSEQ_DIAG_OVRNP_CNT,
        FD_FSEQ_DIAG_OVRNR_CNT,
        FD_FSEQ_DIAG_PUB_CNT,
        FD_FSEQ_DIAG_PUB_SZ,
        FD_FSEQ_DIAG_SLOW_CNT,
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

/// PackRxReceiver receives callbacks for incoming messages.
pub trait PackRxReceiver {
    /// Callback on speculative receive of a Tango message.
    /// Recipient should copy data out of buffer into target at this point.
    fn recv_txn_prepare(&mut self, txn: &[u8]);

    /// Callback on complete of speculative receive.
    /// success is true if the message was received uncorrupted.
    /// If success is false, previous message received in
    /// `recv_txn_prepare` should be discarded.
    /// Returns whether message was actually received or dropped.
    fn recv_txn_commit(&mut self, success: bool) -> bool;

    /// Periodic house-keeping callback.
    fn housekeep(&mut self);
}

/// PackRx exposes a simple API for consuming the output from the Frank pack tile.
/// This is an unreliable consumer: if the producer overruns the consumer, the
/// consumer will skip data to catch up with the producer.
pub struct PackRx<R: PackRxReceiver> {
    mcache: *mut fd_frag_meta_t,
    dcache: *mut u8,
    fseq: *mut u64,

    out: R,
}

impl<R: PackRxReceiver> PackRx<R> {
    pub fn new(pod_gaddr: &str, cfg_path: &str, out: R) -> Result<Self> {
        // Load configuration

        let pod_gaddr_cstr = CString::new(pod_gaddr).unwrap();
        let cfg_path_cstr = CString::new(cfg_path).unwrap();

        let mcache: *mut fd_frag_meta_t;
        let dcache: *mut u8;
        let fseq: *mut u64;

        unsafe {
            let pod = fd_wksp_pod_attach(pod_gaddr_cstr.as_ptr());
            let cfg_pod = fd_pod_query_subpod(pod, cfg_path_cstr.as_ptr());

            mcache = fd_mcache_join(fd_wksp_pod_map(
                cfg_pod,
                b"pack.out-mcache\0".as_ptr() as *const i8,
            ));
            if mcache.is_null() {
                return Err(anyhow!("fd_mcache_join failed"));
            }
            dcache = fd_dcache_join(fd_wksp_pod_map(
                cfg_pod,
                b"pack.out-dcache\0".as_ptr() as *const i8,
            ));
            if dcache.is_null() {
                fd_mcache_leave(mcache);
                return Err(anyhow!("fd_dcache_join failed"));
            }
            fseq = fd_fseq_join(fd_wksp_pod_map(
                cfg_pod,
                b"pack.return-fseq\0".as_ptr() as *const i8,
            ));
            if fseq.is_null() {
                fd_mcache_leave(mcache);
                fd_dcache_leave(dcache);
                return Err(anyhow!("fd_fseq_join failed"));
            }
        }

        Ok(Self {
            mcache,
            dcache,
            fseq,
            out,
        })
    }

    pub unsafe fn run(&mut self) -> Result<()> {
        let mcache = self.mcache;
        let fseq = self.fseq;

        // Look up the mline cache line
        let depth = fd_mcache_depth(mcache);
        let sync = fd_mcache_seq_laddr_const(mcache);
        let mut seq = fd_mcache_seq_query(sync);
        let mut mline = mcache.add(fd_mcache_line_idx(seq, depth).try_into().unwrap());

        // Join the workspace
        let workspace = fd_wksp_containing(transmute(mline));
        if workspace.is_null() {
            return Err(anyhow!("fd_wksp_containing failed"));
        }

        // Hook up to flow control diagnostics
        let fseq_diag = fd_fseq_app_laddr(fseq) as *mut u64;

        let mut accum_pub_cnt: u64 = 0;
        let mut accum_pub_sz: u64 = 0;
        let mut accum_ovrnp_cnt: u64 = 0;
        let mut accum_ovrnr_cnt: u64 = 0;
        let mut accum_filt_cnt: u64 = 0;
        let mut accum_filt_sz: u64 = 0;

        compiler_fence(Ordering::AcqRel);
        fseq_diag
            .add(FD_FSEQ_DIAG_PUB_CNT.try_into().unwrap())
            .write_volatile(accum_pub_cnt);
        fseq_diag
            .add(FD_FSEQ_DIAG_PUB_SZ.try_into().unwrap())
            .write_volatile(accum_pub_sz);
        fseq_diag
            .add(FD_FSEQ_DIAG_FILT_CNT.try_into().unwrap())
            .write_volatile(accum_filt_cnt);
        fseq_diag
            .add(FD_FSEQ_DIAG_FILT_SZ.try_into().unwrap())
            .write_volatile(accum_filt_sz);
        fseq_diag
            .add(FD_FSEQ_DIAG_OVRNP_CNT.try_into().unwrap())
            .write_volatile(accum_ovrnp_cnt);
        fseq_diag
            .add(FD_FSEQ_DIAG_OVRNR_CNT.try_into().unwrap())
            .write_volatile(accum_ovrnr_cnt);
        fseq_diag
            .add(FD_FSEQ_DIAG_SLOW_CNT.try_into().unwrap())
            .write_volatile(0);
        compiler_fence(Ordering::AcqRel);

        // Set frequency of houskeeping operations
        let mut next_housekeeping = Instant::now();
        let housekeeping_interval_ns = fd_tempo_lazy_default(depth);
        let mut rng = rand::thread_rng();

        // Continually consume data from the queue
        loop {
            // Do housekeeping at intervals
            let now = Instant::now();
            if now >= next_housekeeping {
                compiler_fence(Ordering::AcqRel);
                fseq_diag
                    .add(FD_FSEQ_DIAG_PUB_CNT.try_into().unwrap())
                    .write_volatile(accum_pub_cnt);
                fseq_diag
                    .add(FD_FSEQ_DIAG_PUB_SZ.try_into().unwrap())
                    .write_volatile(accum_pub_sz);
                fseq_diag
                    .add(FD_FSEQ_DIAG_FILT_CNT.try_into().unwrap())
                    .write_volatile(accum_filt_cnt);
                fseq_diag
                    .add(FD_FSEQ_DIAG_FILT_SZ.try_into().unwrap())
                    .write_volatile(accum_filt_sz);
                fseq_diag
                    .add(FD_FSEQ_DIAG_OVRNP_CNT.try_into().unwrap())
                    .write_volatile(accum_ovrnp_cnt);
                fseq_diag
                    .add(FD_FSEQ_DIAG_OVRNR_CNT.try_into().unwrap())
                    .write_volatile(accum_ovrnr_cnt);
                compiler_fence(Ordering::AcqRel);

                next_housekeeping = now
                    + Duration::from_nanos(
                        rng.gen_range(housekeeping_interval_ns, 2 * housekeeping_interval_ns)
                            as u64,
                    );

                self.out.housekeep();
            }

            // Overrun check
            let seq_found = fd_frag_meta_seq_query(mline);
            if seq_found != seq {
                // Check to see if we have caught up to the producer - if so, wait
                if seq_found < seq {
                    // println!("caught up");
                    spin_loop();
                    continue;
                }

                // We were overrun by the producer. Keep processing from the new sequence number.
                accum_ovrnp_cnt += 1;
                seq = seq_found;
                println!("overran");
            }

            // Construct slice over data
            let chunk = fd_chunk_to_laddr_const(
                transmute(workspace),
                (*mline).__bindgen_anon_1.as_ref().chunk.into(),
            ) as *const u8;
            let size = (*mline).__bindgen_anon_1.as_ref().sz as usize;
            let payload = std::slice::from_raw_parts(chunk, size);

            // Deliver speculatively received message
            self.out.recv_txn_prepare(payload);

            // Check the producer hasn't overran us while we were serving the data
            let seq_found = fd_frag_meta_seq_query(mline);
            if seq_found != seq {
                accum_ovrnr_cnt += 1;
                seq = seq_found;
                self.out.recv_txn_commit(false);
                continue;
            }

            // Update seq and mline
            seq += 1;
            mline = mcache.add(fd_mcache_line_idx(seq, depth).try_into().unwrap());

            // Commit receive
            if self.out.recv_txn_commit(true) {
                accum_pub_cnt += 1;
                accum_pub_sz += size as u64;
            } else {
                accum_filt_cnt += 1;
                accum_filt_sz += size as u64;
            }
        }
    }
}

impl<R: PackRxReceiver> Drop for PackRx<R> {
    fn drop(&mut self) {
        unsafe {
            fd_fseq_leave(self.fseq);
            fd_mcache_leave(self.mcache);
            fd_dcache_leave(self.dcache);
        }
    }
}
