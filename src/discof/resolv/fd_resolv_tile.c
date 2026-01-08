#include "fd_resolv_tile.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/topo/fd_topo.h"
#include "../replay/fd_replay_tile.h"
#include "generated/fd_resolv_tile_seccomp.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/runtime/fd_alut_interp.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../util/pod/fd_pod_format.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

#define IN_KIND_DEDUP  (0)
#define IN_KIND_REPLAY (1)

struct blockhash {
  uchar b[ 32 ];
};

typedef struct blockhash blockhash_t;

struct blockhash_map {
  blockhash_t key;
  ulong       block_height;
};

typedef struct blockhash_map blockhash_map_t;

static const blockhash_t null_blockhash = { 0 };

/* The blockhash ring holds recent blockhashes, so we can identify when
   a transaction arrives, what slot it will expire (and can no longer be
   packed) in.  This is useful so we don't send transactions to pack
   that are no longer packable.

   Unfortunately, poorly written transaction senders frequently send
   transactions from millions of slots ago, so we need a large ring to
   be able to determine and evict these.  The highest practically useful
   value here is around 22, which works out to 19 days of blockhash
   history.  Beyond this, the validator is likely to be restarted, and
   lose the history anyway. */

#define BLOCKHASH_LG_RING_CNT 22UL
#define BLOCKHASH_RING_LEN   (1UL<<BLOCKHASH_LG_RING_CNT)

#define MAP_NAME              map
#define MAP_T                 blockhash_map_t
#define MAP_KEY_T             blockhash_t
#define MAP_LG_SLOT_CNT       (BLOCKHASH_LG_RING_CNT+1UL)
#define MAP_KEY_NULL          null_blockhash
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_blockhash)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, 32UL))
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     fd_uint_load_4( (key).b )
#define MAP_QUERY_OPT         1

#include "../../util/tmpl/fd_map.c"

typedef struct {
  union {
    ulong pool_next; /* Used when it's released */
    ulong lru_next;  /* Used when it's acquired */
  };                 /* .. so it's okay to store them in the same memory */
  ulong lru_prev;

  ulong map_next;
  ulong map_prev;

  blockhash_t * blockhash;
  uchar _[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));
} fd_stashed_txn_m_t;

#define POOL_NAME      pool
#define POOL_T         fd_stashed_txn_m_t
#define POOL_NEXT      pool_next
#define POOL_IDX_T     ulong

#include "../../util/tmpl/fd_pool.c"

/* We'll push at the head, which means the tail is the oldest. */
#define DLIST_NAME  lru_list
#define DLIST_ELE_T fd_stashed_txn_m_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next

#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME          map_chain
#define MAP_ELE_T         fd_stashed_txn_m_t
#define MAP_KEY_T         blockhash_t *
#define MAP_KEY           blockhash
#define MAP_IDX_T         ulong
#define MAP_NEXT          map_next
#define MAP_PREV          map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (*(k))->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((*(k0))->b, (*(k1))->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI         1

#include "../../util/tmpl/fd_map_chain.c"

typedef struct {
  int         kind;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} fd_resolv_in_ctx_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_resolv_out_ctx_t;

typedef struct {
  ulong round_robin_idx;
  ulong round_robin_cnt;

  int   bundle_failed;
  ulong bundle_id;

  blockhash_map_t * blockhash_map;

  ulong flushing_block_height;
  ulong flush_pool_idx;

  /* In the full client, the resolv tile is passed only a rooted bank
     index from replay whenever the root is advanced.

     This is enough to query the accounts database for that bank and
     retrieve the address lookup tables.  Because of lifetime concerns
     around bank ownership, the replay tile is solely responsible for
     freeing the bank when it is no longer needed.  To facilitate this,
     the resolv tile sends a message to replay when it is done with a
     rooted bank (after exchanging it for a new rooted bank). */
  fd_banks_t * banks;
  fd_bank_t *  bank;

  fd_accdb_user_t accdb[1];

  fd_stashed_txn_m_t * pool;
  map_chain_t *        map_chain;
  lru_list_t           lru_list[1];

  ulong completed_block_height;
  ulong root_block_height;
  ulong blockhash_ring_idx;
  blockhash_t blockhash_ring[ BLOCKHASH_RING_LEN ];

  fd_replay_root_advanced_t  _rooted_slot_msg;
  fd_replay_slot_completed_t _completed_slot_msg;

  struct {
    ulong lut[ FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT ];
    ulong blockhash_expired;
    ulong bundle_peer_failure;
    ulong stash[ FD_METRICS_COUNTER_RESOLV_STASH_OPERATION_CNT ];
    ulong db_race;
  } metrics;

  fd_resolv_in_ctx_t in[ 64UL ];

  fd_resolv_out_ctx_t out_pack[ 1UL ];
  fd_resolv_out_ctx_t out_replay[ 1UL ];
} fd_resolv_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_resolv_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t )        );
  l = FD_LAYOUT_APPEND( l, pool_align(),               pool_footprint     ( 1UL<<16UL ) );
  l = FD_LAYOUT_APPEND( l, map_chain_align(),          map_chain_footprint( 8192UL    ) );
  l = FD_LAYOUT_APPEND( l, map_align(),                map_footprint()                  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_resolv_ctx_t * ctx ) {
  FD_MCNT_SET(       RESOLF, BLOCKHASH_EXPIRED,               ctx->metrics.blockhash_expired );
  FD_MCNT_ENUM_COPY( RESOLF, LUT_RESOLVED,                    ctx->metrics.lut );
  FD_MCNT_ENUM_COPY( RESOLF, STASH_OPERATION,                 ctx->metrics.stash );
  FD_MCNT_SET(       RESOLF, TRANSACTION_BUNDLE_PEER_FAILURE, ctx->metrics.bundle_peer_failure );
  FD_MCNT_SET(       RESOLF, DB_RACES,                        ctx->metrics.db_race );
}

static int
before_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)sig;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==IN_KIND_REPLAY ) ) return 0;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static inline void
during_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz,
             ulong             ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in[in_idx].kind ) {
    case IN_KIND_DEDUP: {
      uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
      uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_pack->mem, ctx->out_pack->chunk );
      fd_memcpy( dst, src, sz );
      break;
    }
    case IN_KIND_REPLAY: {
      if( FD_UNLIKELY( sig==REPLAY_SIG_ROOT_ADVANCED ) ) {
        ctx->_rooted_slot_msg = *(fd_replay_root_advanced_t *)fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_SLOT_COMPLETED ) ) {
        ctx->_completed_slot_msg = *(fd_replay_slot_completed_t *)fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );
      }
      break;
    }
    default:
      FD_LOG_ERR(( "unknown in kind %d", ctx->in[in_idx].kind ));
  }
}

/* peek_alut reads a single address lookup table from database cache. */

static int
peek_alut( fd_resolv_ctx_t *  ctx,
           fd_txn_m_t *       txnm,
           fd_alut_interp_t * interp,
           ulong              alut_idx ) {
  fd_funk_txn_xid_t const xid = { .ul = { fd_bank_slot_get( ctx->bank ), fd_bank_slot_get( ctx->bank ) } };

  ulong ro_indir_cnt_old = interp->ro_indir_cnt;
  ulong rw_indir_cnt_old = interp->rw_indir_cnt;
  ulong alut_idx_old     = interp->alut_idx;

  fd_txn_t const * txn         = fd_txn_m_txn_t_const  ( txnm );
  uchar const *    txn_payload = fd_txn_m_payload_const( txnm );
  fd_txn_acct_addr_lut_t const * addr_lut =
      &fd_txn_get_address_tables_const( txn )[ alut_idx ];
  fd_pubkey_t addr_lut_acc = FD_LOAD( fd_pubkey_t, txn_payload+addr_lut->addr_off );

  int err = 0;
  for(;;) {
    fd_accdb_peek_t _peek[1];
    fd_accdb_peek_t * peek = fd_accdb_peek(
        ctx->accdb, _peek, &xid, &addr_lut_acc );
    if( FD_UNLIKELY( !peek ) ) {
      err = FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
      break;
    }

    err = fd_alut_interp_next(
        interp,
        &addr_lut_acc,
        fd_accdb_ref_owner     ( peek->acc ),
        fd_accdb_ref_data_const( peek->acc ),
        fd_accdb_ref_data_sz   ( peek->acc ) );

    int peek_ok = fd_accdb_peek_test( peek );
    fd_accdb_peek_drop( peek );
    if( FD_LIKELY( peek_ok ) ) break;

    /* Restore old interp state and retry */
    FD_SPIN_PAUSE();
    ctx->metrics.db_race++;
    interp->ro_indir_cnt = ro_indir_cnt_old;
    interp->rw_indir_cnt = rw_indir_cnt_old;
    interp->alut_idx     = alut_idx_old;
  }

  return err;
}

/* peek_aluts reads address lookup tables from database cache.
   Gracefully recovers from data races and missing accounts. */

static int
peek_aluts( fd_resolv_ctx_t * ctx,
            fd_txn_m_t *      txnm ) {

  /* Unpack context */
  fd_txn_t const *          txn          = fd_txn_m_txn_t_const  ( txnm );
  uchar const *             txn_payload  = fd_txn_m_payload_const( txnm );
  ulong const               alut_cnt     = txn->addr_table_lookup_cnt;
  ulong const               slot         = fd_bank_slot_get( ctx->bank );
  fd_sysvar_cache_t const * sysvar_cache = fd_bank_sysvar_cache_query( ctx->bank ); FD_TEST( sysvar_cache );
  fd_slot_hash_t const *    slot_hashes  = fd_sysvar_cache_slot_hashes_join_const( sysvar_cache );

  /* Write indirect addrs into here */
  fd_acct_addr_t * indir_addrs = fd_txn_m_alut( txnm );

  int err = FD_RUNTIME_EXECUTE_SUCCESS;
  fd_alut_interp_t interp[1];
  fd_alut_interp_new( interp, indir_addrs, txn, txn_payload, slot_hashes, slot );
  for( ulong i=0UL; i<alut_cnt; i++ ) {
    err = peek_alut( ctx, txnm, interp, i );
    if( FD_UNLIKELY( err ) ) break;
  }
  fd_alut_interp_delete( interp );
  fd_sysvar_cache_slot_hashes_leave_const( sysvar_cache, slot_hashes );

  ulong ctr_idx;
  switch( err ) {
  case FD_RUNTIME_EXECUTE_SUCCESS:                            ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_SUCCESS_IDX;               break;
  case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND:     ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_ACCOUNT_NOT_FOUND_IDX;     break;
  case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER: ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_INVALID_ACCOUNT_OWNER_IDX; break;
  case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA:  ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_INVALID_ACCOUNT_DATA_IDX;  break;
  case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX: ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_INVALID_LOOKUP_INDEX_IDX;  break;
  default:                                                    ctr_idx = FD_METRICS_ENUM_LUT_RESOLVE_RESULT_V_ACCOUNT_UNINITIALIZED_IDX; break;
  }
  ctx->metrics.lut[ ctr_idx ]++;
  return err;
}

static int
publish_txn( fd_resolv_ctx_t *          ctx,
             fd_stem_context_t *        stem,
             fd_stashed_txn_m_t const * stashed ) {
  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->out_pack->mem, ctx->out_pack->chunk );
  fd_memcpy( txnm, stashed->_, fd_txn_m_realized_footprint( (fd_txn_m_t *)stashed->_, 1, 0 ) );

  fd_txn_t const * txnt = fd_txn_m_txn_t( txnm );

  txnm->reference_block_height = ctx->flushing_block_height;

  if( FD_UNLIKELY( txnt->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->bank ) ) {
      FD_MCNT_INC( RESOLF, NO_BANK_DROP, 1 );
      return 0;
    }
    int err = peek_aluts( ctx, txnm );
    if( FD_UNLIKELY( err ) ) return 0;
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, ctx->root_block_height, ctx->out_pack->chunk, realized_sz, 0UL, 0UL, tspub );
  ctx->out_pack->chunk = fd_dcache_compact_next( ctx->out_pack->chunk, realized_sz, ctx->out_pack->chunk0, ctx->out_pack->wmark );

  return 1;
}

static inline void
after_credit( fd_resolv_ctx_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_LIKELY( ctx->flush_pool_idx==ULONG_MAX ) ) return;

  *charge_busy = 1;
  *opt_poll_in = 0;

  ulong next = map_chain_idx_next_const( ctx->flush_pool_idx, ULONG_MAX, ctx->pool );
  map_chain_idx_remove_fast( ctx->map_chain, ctx->flush_pool_idx, ctx->pool );
  if( FD_LIKELY( publish_txn( ctx, stem, pool_ele( ctx->pool, ctx->flush_pool_idx ) ) ) ) {
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_PUBLISHED_IDX ]++;
  } else {
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_REMOVED_IDX ]++;
  }
  lru_list_idx_remove( ctx->lru_list, ctx->flush_pool_idx, ctx->pool );
  pool_idx_release( ctx->pool, ctx->flush_pool_idx );
  ctx->flush_pool_idx = next;
}

/* Returns 0 if not a durable nonce transaction and 1 if it may be a
   durable nonce transaction */

FD_FN_PURE static inline int
fd_resolv_is_durable_nonce( fd_txn_t const * txn,
                            uchar    const * payload ) {
  if( FD_UNLIKELY( txn->instr_cnt==0 ) ) return 0;

  fd_txn_instr_t const * ix0 = &txn->instr[ 0 ];
  fd_acct_addr_t const * prog0 = fd_txn_get_acct_addrs( txn, payload ) + ix0->program_id;
  /* First instruction must be SystemProgram nonceAdvance instruction */
  fd_acct_addr_t const system_program[1] = { { { SYS_PROG_ID } } };
  if( FD_LIKELY( memcmp( prog0, system_program, sizeof(fd_acct_addr_t) ) ) )        return 0;

  /* instruction with three accounts and a four byte instruction data, a
     little-endian uint value 4 */
  if( FD_UNLIKELY( (ix0->data_sz!=4) | (ix0->acct_cnt!=3) ) ) return 0;

  return fd_uint_load_4( payload + ix0->data_off )==4U;
}

static inline void
after_frag( fd_resolv_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)_tspub;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==IN_KIND_REPLAY ) ) {
    switch( sig ) {
      case REPLAY_SIG_SLOT_COMPLETED: {
        fd_replay_slot_completed_t const * msg = &ctx->_completed_slot_msg;

        /* blockhash_ring is initalized to all zeros. blockhash=0 is an illegal map query */
        if( FD_UNLIKELY( memcmp( &ctx->blockhash_ring[ ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN ], (uchar[ 32UL ]){ 0UL }, sizeof(blockhash_t) ) ) ) {
          blockhash_map_t * entry = map_query( ctx->blockhash_map, ctx->blockhash_ring[ ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN ], NULL );
          if( FD_LIKELY( entry ) ) map_remove( ctx->blockhash_map, entry );
        }

        memcpy( ctx->blockhash_ring[ ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN ].b, msg->block_hash.uc, 32UL );
        ctx->blockhash_ring_idx++;

        blockhash_map_t * blockhash = map_insert( ctx->blockhash_map, *(blockhash_t *)msg->block_hash.uc );
        blockhash->block_height = msg->block_height;

        blockhash_t * hash = (blockhash_t *)msg->block_hash.uc;
        ctx->flush_pool_idx  = map_chain_idx_query_const( ctx->map_chain, &hash, ULONG_MAX, ctx->pool );
        ctx->flushing_block_height   = msg->block_height;

        ctx->completed_block_height = msg->block_height;
        break;
      }
      case REPLAY_SIG_ROOT_ADVANCED: {
        fd_replay_root_advanced_t const * msg = &ctx->_rooted_slot_msg;

        /* Replace current bank with new bank */
        fd_bank_t * prev_bank = ctx->bank;

        ctx->bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
        FD_TEST( ctx->bank );

        /* Send slot completed message back to replay, so it can
           decrement the reference count of the previous bank. */
        if( FD_LIKELY( prev_bank ) ) {
          ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
          fd_resolv_slot_exchanged_t * slot_exchanged =
            fd_type_pun( fd_chunk_to_laddr( ctx->out_replay->mem, ctx->out_replay->chunk ) );
          slot_exchanged->bank_idx = prev_bank->idx;
          fd_stem_publish( stem, 1UL, 0UL, ctx->out_replay->chunk, sizeof(fd_resolv_slot_exchanged_t), 0UL, tsorig, tspub );
          ctx->out_replay->chunk = fd_dcache_compact_next( ctx->out_replay->chunk, sizeof(fd_resolv_slot_exchanged_t), ctx->out_replay->chunk0, ctx->out_replay->wmark );
        }

        break;
      }
      default: break;
    }
    return;
  }

  fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_pack->mem, ctx->out_pack->chunk );
  FD_TEST( txnm->payload_sz<=FD_TPU_MTU );
  FD_TEST( txnm->txn_t_sz<=FD_TXN_MAX_SZ );
  fd_txn_t const * txnt = fd_txn_m_txn_t( txnm );

  /* If we find the recent blockhash, life is simple.  We drop
     transactions that couldn't possibly execute any more, and forward
     to pack ones that could.

     If we can't find the recent blockhash ... it means one of four
     things,

     (1) The blockhash is really old (more than 19 days) or just
         non-existent.
     (2) The blockhash is not that old, but was created before this
         validator was started.
     (3) It's really new (we haven't seen the bank yet).
     (4) It's a durable nonce transaction, or part of a bundle (just let
         it pass).

    For durable nonce transactions, there isn't much we can do except
    pass them along and see if they execute.

    For the other three cases ... we don't want to flood pack with what
    might be junk transactions, so we accumulate them into a local
    buffer.  If we later see the blockhash come to exist, we forward any
    buffered transactions to back. */

  if( FD_UNLIKELY( txnm->block_engine.bundle_id && (txnm->block_engine.bundle_id!=ctx->bundle_id) ) ) {
    ctx->bundle_failed = 0;
    ctx->bundle_id     = txnm->block_engine.bundle_id;
  }

  if( FD_UNLIKELY( txnm->block_engine.bundle_id && ctx->bundle_failed ) ) {
    ctx->metrics.bundle_peer_failure++;
    return;
  }

  txnm->reference_block_height = ctx->completed_block_height;
  blockhash_map_t const * blockhash = map_query_const( ctx->blockhash_map, *(blockhash_t*)( fd_txn_m_payload( txnm )+txnt->recent_blockhash_off ), NULL );
  if( FD_LIKELY( blockhash ) ) {
    txnm->reference_block_height = blockhash->block_height;
    if( FD_UNLIKELY( txnm->reference_block_height+FD_TXN_MAX_BLOCK_HEIGHT<ctx->root_block_height ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      ctx->metrics.blockhash_expired++;
      return;
    }
  }

  int is_bundle_member = !!txnm->block_engine.bundle_id;
  int is_durable_nonce = fd_resolv_is_durable_nonce( txnt, fd_txn_m_payload( txnm ) );

  if( FD_UNLIKELY( !is_bundle_member && !is_durable_nonce && !blockhash ) ) {
    ulong pool_idx;
    if( FD_UNLIKELY( !pool_free( ctx->pool ) ) ) {
      pool_idx = lru_list_idx_pop_tail( ctx->lru_list, ctx->pool );
      map_chain_idx_remove_fast( ctx->map_chain, pool_idx, ctx->pool );
      ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_OVERRUN_IDX ]++;
    } else {
      pool_idx = pool_idx_acquire( ctx->pool );
    }

    fd_stashed_txn_m_t * stash_txn = pool_ele( ctx->pool, pool_idx );
    /* There's a compiler bug in GCC version 12 (at least 12.1, 12.3 and
       12.4) that cause it to think stash_txn is a null pointer.  It
       then complains that the memcpy is bad and refuses to compile the
       memcpy below.  It is possible for pool_ele to return NULL, but
       that can't happen because if pool_free is 0, then all the pool
       elements must be in the LRU list, so idx_pop_tail won't return
       IDX_NULL; and if pool_free returns non-zero, then
       pool_idx_acquire won't return POOL_IDX_NULL. */
    FD_COMPILER_FORGET( stash_txn );
    fd_memcpy( stash_txn->_, txnm, fd_txn_m_realized_footprint( txnm, 1, 0 ) );
    stash_txn->blockhash = (blockhash_t *)(fd_txn_m_payload( (fd_txn_m_t *)(stash_txn->_) ) + txnt->recent_blockhash_off);
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_INSERTED_IDX ]++;

    map_chain_ele_insert( ctx->map_chain, stash_txn, ctx->pool );
    lru_list_idx_push_head( ctx->lru_list, pool_idx, ctx->pool );

    return;
  }

  if( FD_UNLIKELY( txnt->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->bank ) ) {
      FD_MCNT_INC( RESOLF, NO_BANK_DROP, 1 );
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }

    int result = peek_aluts( ctx, txnm );
    if( FD_UNLIKELY( result ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, ctx->root_block_height, ctx->out_pack->chunk, realized_sz, 0UL, tsorig, tspub );
  ctx->out_pack->chunk = fd_dcache_compact_next( ctx->out_pack->chunk, realized_sz, ctx->out_pack->chunk0, ctx->out_pack->wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolv_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->bundle_failed = 0;
  ctx->bundle_id     = 0UL;

  ctx->completed_block_height = 0UL;
  ctx->root_block_height = 0UL;
  ctx->blockhash_ring_idx = 0UL;

  ctx->flush_pool_idx = ULONG_MAX;

  ctx->pool = pool_join( pool_new( FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( 1UL<<16UL ) ), 1UL<<16UL ) );
  FD_TEST( ctx->pool );

  ctx->map_chain = map_chain_join( map_chain_new( FD_SCRATCH_ALLOC_APPEND( l, map_chain_align(), map_chain_footprint( 8192ULL ) ), 8192UL , 0UL ) );
  FD_TEST( ctx->map_chain );

  FD_TEST( ctx->lru_list==lru_list_join( lru_list_new( ctx->lru_list ) ) );

  memset( ctx->blockhash_ring, 0, sizeof( ctx->blockhash_ring ) );
  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->blockhash_map = map_join( map_new( FD_SCRATCH_ALLOC_APPEND( l, map_align(), map_footprint() ) ) );
  FD_TEST( ctx->blockhash_map );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "replay_out"   ) ) ) ctx->in[ i ].kind = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "dedup_resolv" ) ) ) ctx->in[ i ].kind = IN_KIND_DEDUP;
    else FD_LOG_ERR(( "unknown in link name '%s'", link->name ));

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    ctx->in[i].mtu    = link->mtu;
  }

  ctx->out_pack->mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_pack->chunk0 = fd_dcache_compact_chunk0( ctx->out_pack->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_pack->wmark  = fd_dcache_compact_wmark ( ctx->out_pack->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_pack->chunk  = ctx->out_pack->chunk0;

  ctx->out_replay->mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 1 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_replay->chunk0 = fd_dcache_compact_chunk0( ctx->out_replay->mem, topo->links[ tile->out_link_id[ 1 ] ].dcache );
  ctx->out_replay->wmark  = fd_dcache_compact_wmark ( ctx->out_replay->mem, topo->links[ tile->out_link_id[ 1 ] ].dcache, topo->links[ tile->out_link_id[ 1 ] ].mtu );
  ctx->out_replay->chunk  = ctx->out_replay->chunk0;

  FD_TEST( fd_accdb_user_v1_init( ctx->accdb, fd_topo_obj_laddr( topo, tile->resolv.funk_obj_id ) ) );

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );
  ctx->bank = NULL;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_resolv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_resolv_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_resolv_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_resolv_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_resolv = {
  .name                     = "resolv",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
