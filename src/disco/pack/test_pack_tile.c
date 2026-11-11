/* Unit test for the pack tile's fast leader handover state machine:
   a slot on an unconfirmed parent ends held, confirmed, switched to a
   new parent or given up, in every order replay's messages, the old
   bank's last microblock and the slot timer can interleave. */

#include "fd_pack_tile.c"

#define TEST_EXECLE_CNT (2UL)
#define TEST_DEPTH      (64UL)
#define TEST_SLOT       (4UL)
#define TEST_OLD_SEQ    (40UL)
#define TEST_NEW_SEQ    (41UL)
#define TEST_BUSY_SEQ   (5UL)

static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

static fd_topo_t         topo[1];
static fd_frag_meta_t *  out_mcache[ TEST_EXECLE_CNT+1UL ];
static ulong             out_seq   [ TEST_EXECLE_CNT+1UL ];
static ulong             out_depth [ TEST_EXECLE_CNT+1UL ];
static int               out_rel   [ TEST_EXECLE_CNT+1UL ];
static fd_stem_context_t stem[1];

static ulong
test_obj( fd_wksp_t * wksp,
          void *      laddr ) {
  ulong id = topo->obj_cnt++;
  topo->objs[ id ].id      = id;
  topo->objs[ id ].wksp_id = 0UL;
  topo->objs[ id ].offset  = fd_wksp_gaddr_fast( wksp, laddr );
  return id;
}

static ulong
test_link( fd_wksp_t *  wksp,
           char const * name,
           ulong        kind_id,
           ulong        mtu ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, TEST_DEPTH, 1UL, 1 );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  FD_TEST( mem );
  ulong id = topo->link_cnt++;
  fd_topo_link_t * link = topo->links+id;
  fd_cstr_ncpy( link->name, name, sizeof(link->name) );
  link->id            = id;
  link->kind_id       = kind_id;
  link->mtu           = mtu;
  link->dcache        = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
  FD_TEST( link->dcache );
  link->dcache_obj_id = test_obj( wksp, mem );
  return id;
}

static fd_pack_ctx_t *
test_pack_new( fd_wksp_t * wksp ) {
  fd_wksp_reset( wksp, 42U );
  memset( topo, 0, sizeof(topo) );
  topo->workspaces[0].wksp = wksp;
  topo->obj_cnt = 1UL; /* obj id 0 is not valid as a tile object */
  FD_TEST( fd_pod_new( topo->props, sizeof(topo->props) ) );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  fd_topo_tile_t * tile = topo->tiles;
  tile->pack.max_pending_transactions = 128UL;
  tile->pack.execle_tile_count        = TEST_EXECLE_CNT;
  tile->pack.max_cost_per_block       = FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND;
  tile->pack.max_shreds_per_block     = FD_SHRED_BLK_MAX;
  tile->pack.schedule_strategy        = FD_PACK_STRATEGY_PERF;

  tile->in_link_id[ tile->in_cnt++ ] = test_link( wksp, "replay_out", 0UL, sizeof(fd_replay_message_t) );
  for( ulong i=0UL; i<TEST_EXECLE_CNT; i++ ) {
    tile->out_link_id[ tile->out_cnt++ ] = test_link( wksp, "pack_execle", i, FD_PACK_EXECLE_MTU );
    void * fseq = fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fd_fseq_footprint(), 1UL );
    FD_TEST( fd_fseq_new( fseq, ULONG_MAX ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, test_obj( wksp, fseq ), "execle_busy.%lu", i ) );
  }
  tile->out_link_id[ tile->out_cnt++ ] = test_link( wksp, "pack_poh", 0UL, sizeof(fd_done_packing_t) );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  FD_TEST( scratch );
  tile->tile_obj_id = test_obj( wksp, scratch );
  unprivileged_init( topo, tile );

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    void * mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( TEST_DEPTH, 0UL ), 1UL );
    FD_TEST( mem );
    out_mcache[ i ] = fd_mcache_join( fd_mcache_new( mem, TEST_DEPTH, 0UL, 0UL ) );
    out_seq   [ i ] = 0UL;
    out_depth [ i ] = TEST_DEPTH;
    out_rel   [ i ] = 0;
  }
  *stem = (fd_stem_context_t){ .mcaches=out_mcache, .seqs=out_seq, .depths=out_depth, .out_reliable=out_rel };
  return scratch;
}

/* deliver drives one replay_out frag through during_frag and
   after_frag. */

static void
deliver( fd_pack_ctx_t * ctx,
         ulong           sig,
         void const *    msg,
         ulong           sz ) {
  ulong chunk = ctx->in[ 0 ].chunk0;
  fd_memcpy( fd_chunk_to_laddr( ctx->in[ 0 ].mem, chunk ), msg, sz );
  during_frag( ctx, 0UL, 0UL, sig, chunk, sz, 0UL );
  after_frag ( ctx, 0UL, 0UL, sig, sz, 0UL, 0UL, stem );
}

/* settle runs the tile loop's after_credit until it settles. */

static void
settle( fd_pack_ctx_t * ctx ) {
  for( ulong i=0UL; i<16UL; i++ ) {
    int charge_busy = 0;
    ctx->skip_cnt = 0L;
    after_credit( ctx, stem, NULL, &charge_busy );
  }
}

static fd_became_leader_t
became_leader( ulong bank_seq,
               int   unconfirmed,
               long  slot_end_ns,
               uchar parent_blockhash ) {
  fd_became_leader_t msg;
  memset( &msg, 0, sizeof(msg) );
  msg.slot                              = TEST_SLOT;
  msg.parent_slot                       = TEST_SLOT-1UL;
  msg.slot_start_ns                     = fd_log_wallclock();
  msg.slot_end_ns                       = slot_end_ns;
  msg.bank_idx                          = bank_seq;
  msg.bank_seq                          = bank_seq;
  msg.max_microblocks_in_slot           = 1UL<<20;
  msg.ticks_per_slot                    = 64UL;
  msg.tick_duration_ns                  = 6250000UL;
  msg.limits.slot_max_cost              = FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND;
  msg.limits.slot_max_write_cost_per_acct      = FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND;
  msg.limits.slot_max_allocated_data_per_block = FD_PACK_MAX_ALLOCATED_DATA_PER_BLOCK;
  msg.limits.slot_max_data_shreds       = FD_SHRED_BLK_MAX;
  msg.parent_unconfirmed                = unconfirmed;
  memset( msg.parent_blockhash.uc, parent_blockhash, sizeof(fd_hash_t) );
  return msg;
}

/* What pack sent motor on pack_poh, and the event index it went out at
   (ULONG_MAX if it did not). */

struct test_poh_seen {
  ulong drained_cnt, drained_at;
  ulong resume_cnt,  resume_at;
  ulong done_cnt,    done_at;
  int   done_reason;
};
typedef struct test_poh_seen test_poh_seen_t;

static void
scan_poh( fd_pack_ctx_t *   ctx,
          ulong *           seq,
          ulong             event,
          test_poh_seen_t * seen ) {
  ulong out_idx = ctx->poh_out.out_idx;
  for( ; *seq<out_seq[ out_idx ]; (*seq)++ ) {
    fd_frag_meta_t const * m = out_mcache[ out_idx ] + fd_mcache_line_idx( *seq, TEST_DEPTH );
    if( m->sig==FD_PACK_MSG_DONE_DRAINING ) continue;
    void const * payload = fd_chunk_to_laddr_const( ctx->poh_out.mem, m->chunk );
    FD_TEST( fd_disco_execle_sig_slot( m->sig )==TEST_SLOT );
    if( m->sz==sizeof(fd_pack_prefix_drained_t) ) {
      fd_pack_prefix_drained_t const * d = payload;
      FD_TEST( d->slot==TEST_SLOT && d->parent_slot==TEST_SLOT-2UL && d->bank_seq==TEST_OLD_SEQ );
      seen->drained_cnt++; seen->drained_at = event;
    } else if( m->sz==sizeof(fd_pack_resume_t) ) {
      fd_pack_resume_t const * r = payload;
      FD_TEST( r->slot==TEST_SLOT && r->parent_blockhash[0]==0x22 );
      seen->resume_cnt++; seen->resume_at = event;
    } else {
      FD_TEST( m->sz==sizeof(fd_done_packing_t) );
      seen->done_cnt++; seen->done_at = event;
      seen->done_reason = ((fd_done_packing_t const *)payload)->end_slot_reason;
    }
  }
}

/* Every order of a slot on an optimistic parent.  Replay sends, in
   order, one of: C (CONFIRM_LEADER), A (ABANDON_LEADER, the window was
   skipped before LEADER), K B (UPDATE_PARENT_KILL then
   UPDATE_PARENT_BANK), or K A (the window was skipped mid-switch).
   Interleaved with those anywhere: E, the old bank's in-flight
   microblock completes, and T, the slot's time runs out.

   Pack must send prefix_drained once per kill, only once the old bank's
   microblock is done, resume once the new bank is in, after
   prefix_drained, and done packing once, as soon as the slot may end
   and no sooner. */

static void
test_switch_orders( fd_wksp_t * wksp ) {
  static char const * chains[] = { "C", "A", "KB", "KA" };
  ulong case_cnt = 0UL;

  for( ulong c=0UL; c<4UL; c++ ) {
    char const * chain = chains[ c ];
    ulong n = strlen( chain );
    /* E goes in at e, T at t, of the n+2 positions */
    for( ulong e=0UL; e<n+2UL; e++ ) {
      for( ulong t=0UL; t<n+2UL; t++ ) {
        if( t==e ) continue;
        char order[ 8 ];
        for( ulong i=0UL, j=0UL; i<n+2UL; i++ ) order[ i ] = i==e ? 'E' : i==t ? 'T' : chain[ j++ ];
        order[ n+2UL ] = '\0';

        fd_pack_ctx_t * ctx = test_pack_new( wksp );
        long far = fd_log_wallclock() + (long)3600e9;
        fd_became_leader_t start = became_leader( TEST_OLD_SEQ, 1, far, 0x11 );
        deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
        FD_TEST( ctx->leader_slot==TEST_SLOT && ctx->slot_parent_unconfirmed );

        /* The old bank has a microblock in flight on execle 0. */
        ctx->execle_idle_bitset &= ~1UL;
        ctx->execle_expect[ 0 ]  = TEST_BUSY_SEQ;

        test_poh_seen_t seen = { .drained_at = ULONG_MAX, .resume_at = ULONG_MAX, .done_at = ULONG_MAX };
        ulong poh_seq = 0UL;
        ulong at_e = ULONG_MAX, at_t = ULONG_MAX, at_k = ULONG_MAX, at_b = ULONG_MAX, at_a = ULONG_MAX, at_c = ULONG_MAX;
        int   timed_out = 0;
        settle( ctx );
        scan_poh( ctx, &poh_seq, ULONG_MAX, &seen );
        FD_TEST( !seen.drained_cnt && !seen.resume_cnt && !seen.done_cnt );

        for( ulong i=0UL; order[ i ]; i++ ) {
          switch( order[ i ] ) {
          case 'E':
            fd_fseq_update( ctx->execle_current[ 0 ], TEST_BUSY_SEQ );
            at_e = i;
            break;
          case 'T':
            /* the wallclock passes every slot end, a held new bank's too */
            if( ctx->leader_slot!=ULONG_MAX )               ctx->slot_end_ns                     = 0L;
            if( ctx->update_parent_bank->slot!=ULONG_MAX )  ctx->update_parent_bank->slot_end_ns = 0L;
            timed_out = 1;
            at_t = i;
            break;
          case 'C': {
            fd_replay_leader_slot_t msg = { .slot = TEST_SLOT };
            deliver( ctx, REPLAY_SIG_CONFIRM_LEADER, &msg, sizeof(msg) );
            at_c = i;
            break;
          }
          case 'A': {
            fd_replay_leader_slot_t msg = { .slot = TEST_SLOT };
            deliver( ctx, REPLAY_SIG_ABANDON_LEADER, &msg, sizeof(msg) );
            at_a = i;
            break;
          }
          case 'K': {
            fd_replay_update_parent_kill_t msg = { .slot = TEST_SLOT, .parent_slot = TEST_SLOT-2UL, .slot_end_ns = far };
            deliver( ctx, REPLAY_SIG_UPDATE_PARENT_KILL, &msg, sizeof(msg) );
            FD_TEST( ctx->parent_switch==FD_PACK_PARENT_SWITCH_DRAINING && !ctx->slot_end_held );
            at_k = i;
            break;
          }
          case 'B': {
            /* the new bank's slot end has passed if the time ran out */
            fd_became_leader_t msg = became_leader( TEST_NEW_SEQ, 0, timed_out ? 0L : far, 0x22 );
            deliver( ctx, REPLAY_SIG_UPDATE_PARENT_BANK, &msg, sizeof(msg) );
            at_b = i;
            break;
          }
          }
          settle( ctx );
          scan_poh( ctx, &poh_seq, i, &seen );
          FD_TEST( seen.drained_cnt<=1UL && seen.resume_cnt<=1UL && seen.done_cnt<=1UL );
          if( ctx->parent_switch!=FD_PACK_PARENT_SWITCH_NONE ) FD_TEST( ctx->leader_slot==TEST_SLOT );
        }

        int killed  = at_k!=ULONG_MAX;
        int resumed = at_b!=ULONG_MAX;
        if( FD_UNLIKELY( seen.drained_cnt!=(ulong)killed || seen.resume_cnt!=(ulong)resumed || seen.done_cnt!=1UL ) )
          FD_LOG_ERR(( "order %s: %lu prefix_drained, %lu resume, %lu done packing", order, seen.drained_cnt, seen.resume_cnt, seen.done_cnt ));
        if( killed )  FD_TEST( seen.drained_at==fd_ulong_max( at_k, at_e ) );
        if( resumed ) FD_TEST( seen.resume_at==fd_ulong_max( at_b, seen.drained_at ) );

        ulong done_at;
        int   reason;
        if(      at_c!=ULONG_MAX ) { done_at = fd_ulong_max( at_c, at_t );            reason = FD_PACK_END_SLOT_REASON_TIME;      }
        else if( resumed         ) { done_at = fd_ulong_max( seen.resume_at, at_t );  reason = FD_PACK_END_SLOT_REASON_TIME;      }
        else if( killed          ) { done_at = fd_ulong_max( at_a, seen.drained_at ); reason = FD_PACK_END_SLOT_REASON_ABANDONED; }
        else                       { done_at = at_a;                                  reason = FD_PACK_END_SLOT_REASON_ABANDONED; }
        if( FD_UNLIKELY( seen.done_at!=done_at || seen.done_reason!=reason ) )
          FD_LOG_ERR(( "order %s: done packing at event %lu reason %d, expected %lu reason %d", order, seen.done_at, seen.done_reason, done_at, reason ));

        FD_TEST( ctx->leader_slot==ULONG_MAX && ctx->parent_switch==FD_PACK_PARENT_SWITCH_NONE );
        FD_TEST( !ctx->switch_abandoned && !ctx->slot_end_held && ctx->update_parent_bank->slot==ULONG_MAX );
        case_cnt++;
      }
    }
  }

  FD_LOG_NOTICE(( "pass: test_switch_orders (%lu orders)", case_cnt ));
}

/* While the slot's parent is unconfirmed, every txn and bundle pack
   sends to an execle is copied to the prefix, with the expires_at it
   was inserted with and a bundle's metadata.  Pack's own initializer
   bundle is not kept.  KILL stops recording but keeps the prefix,
   CONFIRM drops it, a full prefix stops recording, and a slot on a
   confirmed parent records nothing. */

static void
fill_txn( fd_txn_e_t * e,
          ulong        payload_sz,
          uchar        alt_cnt,
          uchar        tag ) {
  memset( e, 0, sizeof(fd_txn_e_t) );
  fd_txn_t * txn = TXN( e->txnp );
  txn->transaction_version   = FD_TXN_V0;
  txn->instr_cnt             = 1;
  txn->addr_table_lookup_cnt = (uchar)!!alt_cnt;
  txn->addr_table_adtl_cnt   = alt_cnt;
  e->txnp->payload_sz = (ushort)payload_sz;
  memset( e->txnp->payload, tag, payload_sz );
  for( ulong i=0UL; i<alt_cnt; i++ ) memset( e->alt_accts[ i ].b, tag+1, 32UL );
  e->txnp->first_seen_nanos = (long)tag;
  e->txnp->source_ipv4      = tag;
}

static void
test_prefix_record( fd_wksp_t * wksp ) {
  static fd_txn_e_t txns[ 3 ];
  fd_pack_sched_info_t info[1];
  memset( info, 0, sizeof(info) );

  /* Confirmed parent: nothing is recorded. */
  fd_pack_ctx_t * ctx = test_pack_new( wksp );
  long far = fd_log_wallclock() + (long)3600e9;
  fd_became_leader_t start = became_leader( TEST_OLD_SEQ, 0, far, 0x11 );
  deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
  FD_TEST( !ctx->prefix_recording && !ctx->prefix_txn_cnt );

  /* Unconfirmed parent: a txn, then a 2 txn bundle, are recorded. */
  ctx   = test_pack_new( wksp );
  start = became_leader( TEST_OLD_SEQ, 1, far, 0x11 );
  deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
  FD_TEST( ctx->prefix_recording && !ctx->prefix_txn_cnt );

  fill_txn( &txns[ 0 ], 300UL, 2, 0x40 );
  info->expires_at[ 0 ] = 77UL;
  prefix_record( ctx, txns, 1UL, info );

  fill_txn( &txns[ 0 ], 1000UL, 0, 0x50 ); txns[ 0 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  fill_txn( &txns[ 1 ], 4096UL, 3, 0x60 ); txns[ 1 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  info->expires_at[ 0 ] = 55UL; info->expires_at[ 1 ] = 55UL;
  for( ulong j=0UL; j<sizeof(block_builder_info_t); j++ ) info->bundle_meta[ j ] = (uchar)(0xA0UL+j);
  prefix_record( ctx, txns, 2UL, info );
  FD_TEST( ctx->prefix_txn_cnt==3UL );

  FD_TEST( ctx->prefix[ 0 ].expires_at==77UL && !ctx->prefix[ 0 ].bundle_txn_cnt );
  FD_TEST( ctx->prefix[ 0 ].txn->txnp->payload_sz==300 && ctx->prefix[ 0 ].txn->txnp->payload[ 299 ]==0x40 );
  FD_TEST( ctx->prefix[ 0 ].txn->txnp->source_ipv4==0x40 && ctx->prefix[ 0 ].txn->alt_accts[ 1 ].b[ 0 ]==0x41 );
  FD_TEST( TXN( ctx->prefix[ 0 ].txn->txnp )->addr_table_adtl_cnt==2 );

  FD_TEST( ctx->prefix[ 1 ].expires_at==55UL && ctx->prefix[ 1 ].bundle_txn_cnt==2UL );
  uchar const * meta = (uchar const *)ctx->prefix[ 1 ].bundle_meta;
  FD_TEST( meta[ 0 ]==0xA0 && meta[ sizeof(block_builder_info_t)-1UL ]==(uchar)(0xA0UL+sizeof(block_builder_info_t)-1UL) );
  FD_TEST( ctx->prefix[ 1 ].txn->txnp->payload_sz==1000 && ctx->prefix[ 1 ].txn->txnp->flags==FD_TXN_P_FLAGS_BUNDLE );
  FD_TEST( ctx->prefix[ 2 ].expires_at==55UL && !ctx->prefix[ 2 ].bundle_txn_cnt );
  FD_TEST( ctx->prefix[ 2 ].txn->txnp->payload_sz==4096 && ctx->prefix[ 2 ].txn->alt_accts[ 2 ].b[ 31 ]==0x61 );

  /* Pack's initializer bundle is not kept. */
  fill_txn( &txns[ 0 ], 200UL, 0, 0x70 ); txns[ 0 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE | FD_TXN_P_FLAGS_INITIALIZER_BUNDLE;
  prefix_record( ctx, txns, 1UL, info );
  FD_TEST( ctx->prefix_txn_cnt==3UL );

  /* KILL stops recording and keeps the prefix. */
  fd_replay_update_parent_kill_t kill = { .slot = TEST_SLOT, .parent_slot = TEST_SLOT-2UL, .slot_end_ns = far };
  deliver( ctx, REPLAY_SIG_UPDATE_PARENT_KILL, &kill, sizeof(kill) );
  FD_TEST( !ctx->prefix_recording && ctx->prefix_txn_cnt==3UL );

  /* CONFIRM drops it. */
  ctx   = test_pack_new( wksp );
  start = became_leader( TEST_OLD_SEQ, 1, far, 0x11 );
  deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
  fill_txn( &txns[ 0 ], 300UL, 0, 0x40 );
  prefix_record( ctx, txns, 1UL, info );
  FD_TEST( ctx->prefix_txn_cnt==1UL );
  fd_replay_leader_slot_t confirm = { .slot = TEST_SLOT };
  deliver( ctx, REPLAY_SIG_CONFIRM_LEADER, &confirm, sizeof(confirm) );
  FD_TEST( !ctx->prefix_recording && !ctx->prefix_txn_cnt );

  /* A full prefix stops recording, and a bundle is all or nothing. */
  ctx   = test_pack_new( wksp );
  start = became_leader( TEST_OLD_SEQ, 1, far, 0x11 );
  deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
  ctx->prefix_txn_cnt = FD_PACK_PREFIX_TXN_MAX-1UL;
  fill_txn( &txns[ 0 ], 10UL, 0, 0x50 ); txns[ 0 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  fill_txn( &txns[ 1 ], 10UL, 0, 0x60 ); txns[ 1 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  prefix_record( ctx, txns, 2UL, info );
  FD_TEST( !ctx->prefix_recording && ctx->prefix_txn_cnt==FD_PACK_PREFIX_TXN_MAX-1UL );

  FD_LOG_NOTICE(( "pass: test_prefix_record" ));
}

/* make_txn builds a real legacy txn, a fee payer signing with a
   distinct signature and one writable account, with no instructions,
   which pack's cost model accepts. */

static void
make_txn( fd_txn_e_t * e,
          uchar        sig_tag,
          uchar        writable_tag ) {
  memset( e, 0, sizeof(fd_txn_e_t) );
  uchar * p = e->txnp->payload;
  *p++ = 1;                                        /* signature count */
  memset( p, sig_tag, 64 );               p += 64;  /* signature */
  *p++ = 1; *p++ = 0; *p++ = 0;                    /* header: 1 signer, 0 readonly */
  *p++ = 2;                                        /* account count */
  memset( p, sig_tag,      32 );          p += 32;  /* fee payer */
  memset( p, writable_tag, 32 );          p += 32;
  memset( p, 0x7B,         32 );          p += 32;  /* recent blockhash */
  *p++ = 0;                                        /* instruction count */
  ulong sz = (ulong)(p - e->txnp->payload);
  FD_TEST( fd_txn_parse( e->txnp->payload, sz, TXN( e->txnp ), NULL ) );
  e->txnp->payload_sz = (ushort)sz;
}

/* A slot that switches parent inserts its prefix again on the new bank:
   a txn and a bundle pack sent to the old bank are pending again, the
   bundle with its metadata, and an expired one is rejected. */

static void
test_prefix_reinsert( fd_wksp_t * wksp ) {
  fd_pack_ctx_t * ctx = test_pack_new( wksp );
  long far = fd_log_wallclock() + (long)3600e9;
  fd_became_leader_t start = became_leader( TEST_OLD_SEQ, 1, far, 0x11 );
  start.block_height = 1000UL;
  deliver( ctx, REPLAY_SIG_BECAME_LEADER, &start, sizeof(start) );
  FD_TEST( ctx->prefix_recording );

  /* The old bank got a txn and a 2 txn bundle, and one long expired. */
  static fd_txn_e_t txns[ 2 ];
  fd_pack_sched_info_t info[1];
  memset( info, 0, sizeof(info) );
  make_txn( &txns[ 0 ], 0x01, 0xC1 ); txns[ 0 ].txnp->flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS; /* nothing set carries over */
  info->expires_at[ 0 ] = 2000UL;
  prefix_record( ctx, txns, 1UL, info );

  make_txn( &txns[ 0 ], 0x02, 0xC2 ); txns[ 0 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  make_txn( &txns[ 1 ], 0x03, 0xC3 ); txns[ 1 ].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  info->expires_at[ 0 ] = 2000UL; info->expires_at[ 1 ] = 2000UL;
  block_builder_info_t meta = { .commission = 7UL };
  memset( meta.commission_pubkey->b, 0x5A, 32 );
  memcpy( info->bundle_meta, &meta, sizeof(meta) );
  prefix_record( ctx, txns, 2UL, info );

  make_txn( &txns[ 0 ], 0x04, 0xC4 );
  info->expires_at[ 0 ] = 1UL; /* far below the new bank's cutoff */
  prefix_record( ctx, txns, 1UL, info );
  FD_TEST( ctx->prefix_txn_cnt==4UL );

  /* KILL, the old bank drains, the new bank comes in. */
  fd_replay_update_parent_kill_t kill = { .slot = TEST_SLOT, .parent_slot = TEST_SLOT-2UL, .slot_end_ns = far };
  deliver( ctx, REPLAY_SIG_UPDATE_PARENT_KILL, &kill, sizeof(kill) );
  settle( ctx );
  FD_TEST( ctx->parent_switch==FD_PACK_PARENT_SWITCH_DRAINED && ctx->prefix_txn_cnt==4UL );

  /* Both execles busy, so the new bank schedules nothing and every
     txn inserted again stays pending. */
  for( ulong i=0UL; i<TEST_EXECLE_CNT; i++ ) ctx->execle_expect[ i ] = TEST_BUSY_SEQ;
  ctx->execle_idle_bitset = 0UL;
  ulong pending0 = fd_pack_avail_txn_cnt( ctx->pack );
  ulong expired0 = ctx->insert_result[ FD_PACK_INSERT_REJECT_EXPIRED + FD_PACK_INSERT_RETVAL_OFF ];
  fd_became_leader_t bank = became_leader( TEST_NEW_SEQ, 0, far, 0x22 );
  bank.block_height = 1000UL;
  deliver( ctx, REPLAY_SIG_UPDATE_PARENT_BANK, &bank, sizeof(bank) );
  settle( ctx );
  FD_TEST( ctx->parent_switch==FD_PACK_PARENT_SWITCH_NONE && ctx->leader_bank_seq==TEST_NEW_SEQ );
  FD_TEST( !ctx->prefix_txn_cnt );

  /* The txn and the bundle are pending again, the expired one was
     rejected.  Deleting by signature finds each, a whole bundle by
     any member. */
  FD_TEST( ctx->insert_result[ FD_PACK_INSERT_REJECT_EXPIRED + FD_PACK_INSERT_RETVAL_OFF ]==expired0+1UL );
  FD_TEST( !out_seq[ 0 ] && !out_seq[ 1 ] );
  FD_TEST( fd_pack_avail_txn_cnt( ctx->pack )==pending0+3UL );
  fd_ed25519_sig_t sig;
  memset( sig, 0x01, 64 ); FD_TEST( fd_pack_delete_transaction( ctx->pack, (fd_ed25519_sig_t const *)sig )==1UL );
  memset( sig, 0x03, 64 ); FD_TEST( fd_pack_delete_transaction( ctx->pack, (fd_ed25519_sig_t const *)sig )==2UL ); /* the bundle */
  memset( sig, 0x04, 64 ); FD_TEST( fd_pack_delete_transaction( ctx->pack, (fd_ed25519_sig_t const *)sig )==0UL ); /* expired */
  FD_TEST( fd_pack_avail_txn_cnt( ctx->pack )==pending0 );

  FD_LOG_NOTICE(( "pass: test_prefix_reinsert" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1UL<<15, fd_shmem_cpu_idx( 0UL ), "pack_tile_test", 0UL );
  FD_TEST( wksp );

  test_switch_orders( wksp );
  test_prefix_record( wksp );
  test_prefix_reinsert( wksp );

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
