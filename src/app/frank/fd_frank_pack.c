#include "fd_frank.h"
#include "../../ballet/pack/fd_pack.h"

#include <linux/unistd.h>

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_futex,     /* logging, glibc fprintf unfortunately uses a futex internally */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_nanosleep, /* fd_tempo_tick_per_ns calibration */
};

#define FD_PACK_TAG 0x17ac1C711eUL

static void
init( fd_frank_args_t * args ) {
  args->pod = fd_wksp_pod_attach( args->pod_gaddr );
  args->close_fd_start = 4; /* stdin, stdout, stderr, logfile */
  args->allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]);
  args->allow_syscalls = allow_syscalls;
}

static void
run( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "pack init" ));

  /* Load up the configuration for this frank instance */

  uchar const * cfg_pod = fd_pod_query_subpod( args->pod, "firedancer" );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining firedancer.pack.cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "pack.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  /* FIXME: CNC DIAG REGION? */

  FD_LOG_INFO(( "joining firedancer.dedup.mcache" ));
  fd_frag_meta_t const * mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "dedup.mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong         depth = fd_mcache_depth( mcache );
  ulong const * sync  = fd_mcache_seq_laddr_const( mcache );
  ulong         seq   = fd_mcache_seq_query( sync );

  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );

  FD_LOG_INFO(( "joining firedancer.verify.*.dcache" ));
  /* Note (chunks are referenced relative to the containing workspace
     currently and there is just one workspace).  (FIXME: VALIDATE
     COMMON WORKSPACE FOR THESE) */
  fd_wksp_t * wksp = fd_wksp_containing( mcache );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  FD_LOG_INFO(( "joining firedancer.dedup.fseq" ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "dedup.fseq" ) );
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  /* Hook up to this pack's flow control diagnostics (will be stored in
     the pack's fseq) */
  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  FD_COMPILER_MFENCE();
  fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] = 0UL;
  fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] = 0UL;
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt   = 0UL;
  ulong accum_pub_sz    = 0UL;
  ulong accum_ovrnp_cnt = 0UL;
  ulong accum_ovrnr_cnt = 0UL;

  ulong cu_limit  = fd_pod_query_ulong( cfg_pod, "pack.cu-limit", 12000000U );

  ulong bank_cnt = fd_pod_query_ulong( cfg_pod, "pack.bank-cnt", 0UL );
  if( FD_UNLIKELY( !bank_cnt ) ) FD_LOG_ERR(( "pack.bank-cnt unset or set to zero" ));

  ulong txnq_sz = fd_pod_query_ulong( cfg_pod, "pack.txnq-sz", 0UL );
  if( FD_UNLIKELY( !txnq_sz ) ) FD_LOG_ERR(( "pack.txnq-sz unset or set to zero" ));

  uchar const * cu_est_pod = fd_pod_query_subpod( cfg_pod, "pack.cu-est-tbl" );
  if( FD_UNLIKELY( !cu_est_pod ) ) FD_LOG_ERR(( "pack.cu-est-tbl unset" ));

  ulong bin_cnt    = fd_pod_query_ulong( cu_est_pod, "bin-cnt",     4096UL );
  ulong hist_coeff = fd_pod_query_ulong( cu_est_pod, "history",     1000UL );
  ulong default_cu = fd_pod_query_ulong( cu_est_pod, "default",   200000UL );
  ulong footprint  = fd_pod_query_ulong( cu_est_pod, "footprint",      0UL );

  ulong footprint_rqd = fd_est_tbl_footprint( bin_cnt );
  if( FD_UNLIKELY( footprint<footprint_rqd ) ) FD_LOG_ERR(( "pack.cu-est-tbl.memory too small. Needs %lu bytes", footprint_rqd ));

  void * cu_est_mem = fd_wksp_pod_map( cu_est_pod, "memory" );
  if( FD_UNLIKELY( !cu_est_mem ) ) FD_LOG_ERR(( "pack.cu-est-tbl.memory unset" ));

  fd_est_tbl_t * est_tbl = fd_est_tbl_join( fd_est_tbl_new( cu_est_mem, bin_cnt, hist_coeff, (uint)default_cu ) );
  if( FD_UNLIKELY( !est_tbl ) ) FD_LOG_ERR(( "creating the CU estimation table failed" ));

  FD_LOG_INFO(( "joining firedancer.pack.out-mcache" ));
  fd_frag_meta_t * out_mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "pack.out-mcache" ) );
  if( FD_UNLIKELY( !out_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining firedancer.pack.out-dcache" ));
  uchar * out_dcache = fd_dcache_join( fd_wksp_pod_map( cfg_pod, "pack.out-dcache" ) );
  if( FD_UNLIKELY( !out_dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  void * dcache_base = out_dcache;

  ulong out_depth = fd_mcache_depth( out_mcache );

  ulong pack_footprint   = fd_pack_footprint(        bank_cnt, out_depth, txnq_sz );
  ulong txnmem_footprint = fd_pack_txnmem_footprint( bank_cnt, out_depth, txnq_sz );

  if( FD_UNLIKELY( fd_dcache_data_sz( out_dcache )<txnmem_footprint ) )
    FD_LOG_ERR(( "dcache too small. Data region must be at least %lu bytes. %lu %lu %lu", txnmem_footprint, bank_cnt, out_depth, txnq_sz ));


  /* Setup local objects used by this tile */

  long lazy = fd_pod_query_long( cfg_pod, "pack.lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (firedancer.pack.lazy %li)", lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( cfg_pod, "pack.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (firedancer.pack.seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));


  ulong pack_gaddr = fd_wksp_alloc( wksp, fd_pack_align(), pack_footprint, FD_PACK_TAG );
  if( FD_UNLIKELY( !pack_gaddr ) ) FD_LOG_ERR(( "allocating memory for pack object failed" ));

  void * pack_laddr = fd_wksp_laddr( wksp, pack_gaddr );
  if( FD_UNLIKELY( !pack_laddr ) ) FD_LOG_ERR(( "allocating memory for pack object failed" ));

  fd_pack_t * pack = fd_pack_join( fd_pack_new( pack_laddr, out_dcache, est_tbl, bank_cnt, out_depth, txnq_sz, cu_limit, rng ) );

  ulong * out_sync = fd_mcache_seq_laddr( out_mcache );
  ulong   out_seq  = fd_mcache_seq_query( out_sync );

  FD_LOG_INFO(( "packing blocks of %lu CUs with a max parallelism of %lu", cu_limit, bank_cnt ));

  // const ulong lamports_per_signature = 5000UL;
  const ulong block_duration_ns      = 400UL*1000UL*1000UL; /* 400ms */

  long block_duration_ticks = (long)(fd_tempo_tick_per_ns( NULL ) * (double)block_duration_ns);

  int ctl_som = 1;
  int ctl_eom = 1;
  int ctl_err = 0;
  ulong   ctl    = fd_frag_meta_ctl( args->tile_idx, ctl_som, ctl_eom, ctl_err );
  /* Start packing */


  FD_LOG_INFO(( "pack run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );

  long now            = fd_tickcount();
  long then           = now;            /* Do housekeeping on first iteration of run loop */
  long block_end      = now + block_duration_ticks;
  long schedule_ready = now;
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( out_sync, out_seq );

      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );
      FD_COMPILER_MFENCE();
      fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] += accum_pub_cnt;
      fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] += accum_pub_sz;
      fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] += accum_ovrnp_cnt;
      fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] += accum_ovrnr_cnt;
      FD_COMPILER_MFENCE();
      accum_pub_cnt   = 0UL;
      accum_pub_sz    = 0UL;
      accum_ovrnp_cnt = 0UL;
      accum_ovrnr_cnt = 0UL;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_HALT ) ) FD_LOG_ERR(( "Unexpected signal" ));
        break;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Are we ready to end the block? */
    if( FD_UNLIKELY( (now-block_end)>=0L ) ) {
      for( ulong i=0UL; i<bank_cnt; i++ ) {
        fd_pack_scheduled_txn_t t = fd_pack_drain_block( pack );
        if( t.txn ) {
          ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
          ulong chunk = fd_laddr_to_chunk( dcache_base, t.txn );
          ulong sig = (((ulong)t.bank) << 32) | (ulong)t.start;
          fd_mcache_publish( out_mcache, out_depth, out_seq, sig, chunk, sizeof(fd_txn_p_t), ctl, 0UL, tspub );
        }
        else break;
      }
      fd_pack_clear( pack, 0 );
      block_end += block_duration_ticks;
      schedule_ready = now;
    }

    /* Is it time to schedule the next transaction? */
    /* FIXME: add flow control */
    if( FD_LIKELY( !!fd_pack_avail_txn_cnt( pack ) ) & FD_LIKELY( (now-schedule_ready)>=0L ) ) {
      fd_pack_scheduled_txn_t t = fd_pack_schedule_next( pack );
      if( FD_LIKELY( t.txn ) ) {
        ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        ulong chunk = fd_laddr_to_chunk( dcache_base, t.txn );
        ulong sig = (((ulong)t.bank) << 32) | (ulong)t.start;
        fd_mcache_publish( out_mcache, out_depth, out_seq, sig, chunk, sizeof(fd_txn_p_t), ctl, 0UL, tspub );
        schedule_ready = block_end - block_duration_ticks + block_duration_ticks * (long)t.start / (long)cu_limit;
      }
    }


    /* See if there are any transactions waiting to be packed */
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* caught up */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* overrun by dedup tile ... recover */
      accum_ovrnp_cnt++;
      seq = seq_found;
      /* can keep processing from the new seq */
    }

    now = fd_tickcount();

    /* At this point, we have started receiving frag seq with details in
       mline at time now.  Speculatively processs it here. */

    /* Speculative pack operations */
    fd_txn_p_t * slot          = fd_pack_insert_txn_init( pack );

    ulong         sz           = (ulong)mline->sz;
    uchar const * dcache_entry = fd_chunk_to_laddr_const( wksp, mline->chunk );
    ulong         mline_sig    = mline->sig;
    /* Assume that the dcache entry is:
         Payload ....... (payload_sz bytes)
         0 or 1 byte of padding (since alignof(fd_txn) is 2)
         fd_txn ....... (size computed by fd_txn_footprint)
         payload_sz  (2B)
      mline->sz includes all three fields and the padding */
    ulong payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
    uchar    const * payload = dcache_entry;
    fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );
    fd_memcpy( slot->payload, payload, payload_sz                                                     );
    fd_memcpy( TXN(slot),     txn,     fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
    slot->meta = mline_sig;

#if DETAILED_LOGGING
    FD_LOG_NOTICE(( "Pack got a packet. Payload size: %lu, txn footprint: %lu", payload_sz,
          fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt )
        ));
#endif

    /* Check that we weren't overrun while processing */
    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
      fd_pack_insert_txn_cancel( pack, slot );
      accum_ovrnr_cnt++;
      seq = seq_found;
      continue;
    }

    /* Non-speculative pack operations */
    accum_pub_cnt++;
    accum_pub_sz += sz;

    fd_pack_insert_txn_fini( pack, slot );

    /* Wind up for the next iteration */
    seq   = fd_seq_inc( seq, 1UL );
    mline = mcache + fd_mcache_line_idx( seq, depth );
  }
}

fd_frank_task_t pack = {
  .name = "pack",
  .init = init,
  .run  = run,
};
