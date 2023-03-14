use std::{
    ffi::CString,
    hint::spin_loop,
    mem::transmute,
    ops::Not,
    os::raw::c_int,
    ptr,
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
        fd_frag_meta_seq_query,
        fd_fseq_app_laddr,
        fd_fseq_join,
        fd_mcache_depth,
        fd_mcache_join,
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
        fd_boot,
        fd_halt,
        fd_wksp_containing,
        fd_wksp_map,
    },
};
use minstant::Instant;
use rand::prelude::*;

/// PackRx exposes a simple API for consuming the output from the Frank pack tile.
/// This is an unreliable consumer: if the producer overruns the consumer, the
/// consumer will skip data to catch up with the producer.
pub struct PackRx {
    /// Configuration
    // TODO: proper config using pod api
    mcache: String,
    dcache: String,
    fseq: String,

    /// Crossbeam channel to send consumed data on
    out: crossbeam_channel::Sender<Vec<u8>>,
}

impl PackRx {
    pub fn new(
        mcache: String,
        dcache: String,
        fseq: String,
        out: crossbeam_channel::Sender<Vec<u8>>,
    ) -> Self {
        Self::boot();

        Self {
            mcache,
            dcache,
            fseq,
            out,
        }
    }

    pub unsafe fn run(&self) -> Result<()> {
        // Join the mcache
        let mcache = fd_mcache_join(fd_wksp_map(CString::new(self.mcache.clone())?.as_ptr()));
        mcache
            .is_null()
            .not()
            .then(|| ())
            .ok_or(anyhow!("fd_mcache_join failed"))?;

        // Join the dcache
        let dcache = fd_dcache_join(fd_wksp_map(CString::new(self.dcache.clone())?.as_ptr()));
        dcache
            .is_null()
            .not()
            .then(|| ())
            .ok_or(anyhow!("fd_dcache_join failed"))?;

        // Look up the mline cache line
        let depth = fd_mcache_depth(mcache);
        let sync = fd_mcache_seq_laddr_const(mcache);
        let mut seq = fd_mcache_seq_query(sync);
        let mut mline = mcache.add(fd_mcache_line_idx(seq, depth).try_into().unwrap());

        // Join the workspace
        let workspace = fd_wksp_containing(transmute(mline));
        workspace
            .is_null()
            .not()
            .then(|| ())
            .ok_or(anyhow!("fd_wksp_containing failed"))?;

        // Hook up to flow control diagnostics
        let fseq = fd_fseq_join(fd_wksp_map(CString::new(self.fseq.clone())?.as_ptr()));
        fseq.is_null()
            .not()
            .then(|| ())
            .ok_or(anyhow!("fd_fseq_join failed"))?;
        let fseq_diag = fd_fseq_app_laddr(fseq) as *mut u64;

        let mut accum_pub_cnt: u64 = 0;
        let mut accum_pub_sz: u64 = 0;
        let mut accum_ovrnp_cnt: u64 = 0;
        let mut accum_ovrnr_cnt: u64 = 0;

        compiler_fence(Ordering::AcqRel);
        fseq_diag
            .add(FD_FSEQ_DIAG_PUB_CNT.try_into().unwrap())
            .write_volatile(accum_pub_cnt);
        fseq_diag
            .add(FD_FSEQ_DIAG_PUB_SZ.try_into().unwrap())
            .write_volatile(accum_pub_sz);
        fseq_diag
            .add(FD_FSEQ_DIAG_FILT_CNT.try_into().unwrap())
            .write_volatile(0);
        fseq_diag
            .add(FD_FSEQ_DIAG_FILT_SZ.try_into().unwrap())
            .write_volatile(0);
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
                    .add(FD_FSEQ_DIAG_OVRNP_CNT.try_into().unwrap())
                    .write_volatile(accum_ovrnp_cnt);
                fseq_diag
                    .add(FD_FSEQ_DIAG_OVRNR_CNT.try_into().unwrap())
                    .write_volatile(accum_ovrnr_cnt);
                compiler_fence(Ordering::AcqRel);

                next_housekeeping =
                    now + Duration::from_nanos(rng.gen_range(housekeeping_interval_ns, 2 * housekeeping_interval_ns) as u64)
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

            // Speculatively copy data out of dcache into Rust slice
            let chunk = fd_chunk_to_laddr_const(
                transmute(workspace),
                (*mline).__bindgen_anon_1.as_ref().chunk.into(),
            ) as *const u8;
            let size = (*mline).__bindgen_anon_1.as_ref().sz;

            // Allocate new record on Rust heap
            let mut bytes = Vec::with_capacity(size.into());

            ptr::copy_nonoverlapping(chunk, bytes.as_mut_ptr(), size.into());
            bytes.set_len(size.into());

            // Check the producer hasn't overran us while we were copying the data
            let seq_found = fd_frag_meta_seq_query(mline);
            if seq_found != seq {
                accum_ovrnr_cnt += 1;
                seq = seq_found;
                continue;
            }

            accum_pub_cnt += 1;
            accum_pub_sz += bytes.len() as u64;

            // Update seq and mline
            seq += 1;
            mline = mcache.add(fd_mcache_line_idx(seq, depth).try_into().unwrap());

            // Send the data on the channel
            _ = self.out.send(bytes)
        }
    }

    fn boot() {
        let mut argc = c_int::from(2);
        let mut argv = vec![
            CString::new("--tile-cpus").unwrap(),
            CString::new("0").unwrap(),
        ]
        .into_iter()
        .map(|s| s.into_raw())
        .collect::<Vec<_>>();
        argv.shrink_to_fit();

        unsafe {
            /* TODO: call fd_shmem_private_boot instead */
            fd_boot(&mut argc, &mut argv.as_mut_ptr());
        }
    }
}

impl Drop for PackRx {
    fn drop(&mut self) {
        unsafe {
            fd_halt();
        }
    }
}

#[test]
fn test_basic_pack_rx() {
    let (tx, rx) = crossbeam_channel::unbounded();

    let pack_rx = PackRx::new(
        "test_ipc:2101248".to_string(),
        "test_ipc:3158016".to_string(),
        "test_ipc:57696256".to_string(),
        tx,
    );
    let _rx_t = thread::spawn(move || loop {
        let data = rx.recv().unwrap();
        println!("received {} bytes: {:?}", data.len(), data);
    });

    unsafe {
        pack_rx.run().expect("consuming data");
    }
}
