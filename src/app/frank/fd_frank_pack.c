#include "fd_frank.h"

#include "../../ballet/pack/fd_pack.h"

#include <stdio.h>
#include <linux/unistd.h>

#define FD_PACK_TAG 0x17ac1C711eUL

#define MAX_MICROBLOCK_SZ USHORT_MAX /* in bytes.  Defined this way to
                                        use the size field of mcache */

/* Helper struct containing all the state associated with one output */
typedef struct {
  fd_wksp_t      * out_wksp;
  fd_frag_meta_t * out_mcache;
  uchar          * out_dcache;
  ulong          * out_fseq;
  ulong          * out_sync;
  ulong            out_seq;
  ulong            out_chunk0;
  ulong            out_wmark;
  ulong            out_chunk;
  ulong            out_cr_avail;
  ulong            out_depth;
  fd_fctl_t      * out_fctl;
  uchar            _fctl_footprint[ FD_FCTL_FOOTPRINT( 1 ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
} out_state;


#define FD_FRANK_PACK_MAX_OUT (16UL) /* About 1.5 kB on the stack */

static void
join_out( out_state * state,
          uchar const * pod,
          ulong         suffix ) {
  char path[ 32 ];

  FD_LOG_INFO(( "joining mcache%lu", suffix ));
  snprintf( path, sizeof( path ), "mcache%lu", suffix );
  fd_frag_meta_t * out_mcache = fd_mcache_join( fd_wksp_pod_map( pod, path ) );
  if( FD_UNLIKELY( !out_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining dcache%lu", suffix ));
  snprintf( path, sizeof( path ), "dcache%lu", suffix );
  uchar * out_dcache = fd_dcache_join( fd_wksp_pod_map( pod, path ) );
  if( FD_UNLIKELY( !out_dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "joining fseq%lu", suffix ));
  snprintf( path, sizeof( path ), "fseq%lu", suffix );
  ulong * out_fseq = fd_fseq_join( fd_wksp_pod_map( pod, path) );
  if( FD_UNLIKELY( !out_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( out_fseq );
  if( FD_UNLIKELY( !fseq_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));

  fd_wksp_t * wksp = fd_wksp_containing( out_dcache );

  ulong * out_sync   = fd_mcache_seq_laddr( out_mcache );
  ulong   out_seq    = fd_mcache_seq_query( out_sync   );
  ulong   out_chunk0 = fd_dcache_compact_chunk0( wksp, out_dcache );
  ulong   out_wmark  = fd_dcache_compact_wmark ( wksp, out_dcache, MAX_MICROBLOCK_SZ );
  ulong   out_chunk  = out_chunk0;
  ulong   out_cr_avail = 0UL;
  ulong   out_depth = fd_mcache_depth( out_mcache );

  fd_fctl_t * out_fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add(
                                      fd_fctl_join( fd_fctl_new( state->_fctl_footprint, 1UL ) ),
                                      out_depth, out_fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                    1UL /*cr_burst*/, 0UL, 0UL, 0UL ); /* TODO: allow manual configuration of these? */

  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
        fd_fctl_cr_burst( out_fctl ), fd_fctl_cr_max( out_fctl ), fd_fctl_cr_resume( out_fctl ), fd_fctl_cr_refill( out_fctl ) ));

  state->out_wksp     =  wksp;
  state->out_mcache   =  out_mcache;
  state->out_dcache   =  out_dcache;
  state->out_fseq     =  out_fseq;
  state->out_sync     =  out_sync;
  state->out_seq      =  out_seq;
  state->out_chunk0   =  out_chunk0;
  state->out_wmark    =  out_wmark;
  state->out_chunk    =  out_chunk;
  state->out_cr_avail =  out_cr_avail;
  state->out_depth    =  out_depth;
  state->out_fctl     =  out_fctl;
}


static void
run( fd_frank_args_t * args ) {
  /* Join the IPC objects needed this tile instance */

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  cnc_diag[ FD_FRANK_CNC_DIAG_PID ] = (ulong)args->pid;

  FD_LOG_INFO(( "joining mcache" ));
  fd_frag_meta_t const * mcache = fd_mcache_join( fd_wksp_pod_map( args->in_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong         depth = fd_mcache_depth( mcache );
  ulong const * sync  = fd_mcache_seq_laddr_const( mcache );
  ulong         seq   = fd_mcache_seq_query( sync );

  fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  /* Note (chunks are referenced relative to the containing workspace
     currently and there is just one workspace). */
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( args->extra_pod, "dcache0" ) );
  fd_wksp_t * wksp = fd_wksp_containing( dcache );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  FD_LOG_INFO(( "joining fseq" ));
  ulong * fseq = fd_fseq_join( fd_wksp_pod_map( args->in_pod, "fseq" ) );
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


  ulong pack_depth = fd_pod_query_ulong( args->tile_pod, "depth", 0UL );
  if( FD_UNLIKELY( !pack_depth ) ) FD_LOG_ERR(( "pack.depth unset or set to zero" ));

  /* Should these be allocated with alloca instead? */
  out_state out[ FD_FRANK_PACK_MAX_OUT ];

  /* FIXME: Plumb this through properly: */
  ulong bank_cnt = fd_pod_query_ulong( args->out_pod, "num_tiles", 0UL );
  if( FD_UNLIKELY( !bank_cnt ) ) FD_LOG_ERR(( "pack.num_tiles unset or set to zero" ));
  if( FD_UNLIKELY( bank_cnt>FD_FRANK_PACK_MAX_OUT ) ) FD_LOG_ERR(( "pack tile connects to too many banking tiles" ));

  for( ulong i=0UL; i<bank_cnt; i++ ) join_out( out+i, args->out_pod, i );

  ulong max_txn_per_microblock = MAX_MICROBLOCK_SZ/sizeof(fd_txn_p_t);

  ulong pack_footprint   = fd_pack_footprint( pack_depth, bank_cnt, max_txn_per_microblock );

  ulong cus_per_microblock = 1500000UL; /* 1.5 M cost units, enough for 1 max size transaction */
  float vote_fraction = 0.75;

  /* Setup local objects used by this tile */

  long lazy = fd_pod_query_long( args->tile_pod, "lazy", 0L );
  FD_LOG_INFO(( "configuring flow control (lazy %li)", lazy ));
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)args->tick_per_ns );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( args->tile_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  void * pack_laddr = fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), fd_pack_align(), pack_footprint, FD_PACK_TAG );
  if( FD_UNLIKELY( !pack_laddr ) ) FD_LOG_ERR(( "allocating memory for pack object failed" ));


  fd_pack_t * pack = fd_pack_join( fd_pack_new( pack_laddr, pack_depth, bank_cnt, max_txn_per_microblock, rng ) );


  FD_LOG_INFO(( "packing blocks of at most %lu transactions to %lu bank tiles", max_txn_per_microblock, bank_cnt ));

  const ulong block_duration_ns      = 400UL*1000UL*1000UL; /* 400ms */

  long block_duration_ticks = (long)(args->tick_per_ns * (double)block_duration_ns);

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
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );

      /* TODO: It's not clear what the best way to do this is.  Should
         we update them all in one housekeeping loop, or do like other
         parts of the code and update a random one each housekeeping
         loop? */
      for( ulong i=0UL; i<bank_cnt; i++ ) {
        out_state * o = out+i;

        /* Send synchronization info */
        fd_mcache_seq_update( o->out_sync, o->out_seq );

        /* Receive flow control credits */
        o->out_cr_avail = fd_fctl_tx_cr_update( o->out_fctl, o->out_cr_avail, o->out_seq );
      }

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
      fd_pack_end_block( pack );
      block_end += block_duration_ticks;
    }

    /* Is it time to schedule the next microblock? */
    /* for each banking thread, if it has credits */
    for( ulong i=0UL; i<bank_cnt; i++ ) {
      out_state * o = out+i;
      if( FD_LIKELY( o->out_cr_avail>0UL ) ) { /* optimize for the case we send a microblock */
        void * microblock_dst = fd_chunk_to_laddr( o->out_wksp, o->out_chunk );
        fd_pack_microblock_complete( pack, i );
        ulong schedule_cnt = fd_pack_schedule_next_microblock( pack, cus_per_microblock, vote_fraction, i, microblock_dst );
        if( FD_LIKELY( schedule_cnt ) ) {
          ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
          ulong chunk  = o->out_chunk;
          ulong sig    = 0UL;
          ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);

          fd_mcache_publish( o->out_mcache, o->out_depth, o->out_seq, sig, chunk, msg_sz, ctl, 0UL, tspub );

          o->out_chunk = fd_dcache_compact_next( o->out_chunk, msg_sz, o->out_chunk0, o->out_wmark );
          o->out_seq   = fd_seq_inc( o->out_seq, 1UL );
          o->out_cr_avail--;
        }
      }
    }
    /* Normally, we have an "else, do housekeeping next iteration"
       branch here, but because we're using extremely short queues, we
       actually expect to spend a significant fraction of the time in
       the "no transmit credits available" state.  */


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
    slot->payload_sz = payload_sz;
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

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
};

static ulong
allow_fds( fd_frank_args_t * args,
           ulong out_fds_sz,
           int * out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 2 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_frank_task_t frank_pack = {
  .name              = "pack",
  .in_wksp           = "dedup_pack",
  .out_wksp          = "pack_bank",
  .extra_wksp        = "tpu_txn_data",
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = NULL,
  .run               = run,
};
