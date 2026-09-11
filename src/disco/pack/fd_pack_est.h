#ifndef HEADER_fd_src_disco_pack_fd_pack_est_h
#define HEADER_fd_src_disco_pack_fd_pack_est_h

/* fd_pack_est_txn computes what fd_pack_insert_txn_fini needs from a
   transaction alone: its cost, fee and allocation estimates and the
   validation checks that depend only on the transaction bytes, the
   parsed fd_txn_t and the resolved address lookup table accounts.  It
   runs upstream of pack (the resolv tile) so the single-threaded pack
   insert only reads the fd_pack_est_t it produces.  Checks that depend
   on pack state (block limits, nonce map, expiry) stay in pack. */

#include "fd_pack_cost.h"
#include "fd_chkdup.h"
#include "fd_pack_unwritable.h"
#include "fd_pack_tip_prog_blacklist.h"
#include "../fd_txn_m.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

typedef struct {
  fd_acct_addr_t key;
} fd_pack_est_blocklist_ele_t;

static const fd_acct_addr_t fd_pack_est_null_addr = { 0 };

#define MAP_NAME              fd_pack_est_blocklist
#define MAP_T                 fd_pack_est_blocklist_ele_t
/* Add 1 to the slot cnt to ensure the map is sparse even at capacity */
#define MAP_LG_SLOT_CNT       (FD_PACK_ACCT_BLOCKLIST_LG_MAX+1)
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          fd_pack_est_null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, fd_pack_est_null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
/* Unseeded: the insert process is trusted, since it comes from
   operator config. */
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_QUERY_OPT         2 /* rare hits */
#include "../../util/tmpl/fd_map.c"

/* fd_pack_est_ctx_t: scratch for duplicate account detection and the
   operator's account blocklist.  Safe to embed in a struct. */
struct fd_pack_est_ctx {
  fd_chkdup_t                 chkdup[ 1 ];
  fd_pack_est_blocklist_ele_t blocklist[ 1UL<<(FD_PACK_ACCT_BLOCKLIST_LG_MAX+1) ];
};

typedef struct fd_pack_est_ctx fd_pack_est_ctx_t;

/* fd_pack_est_ctx_init formats ctx.  acct_blocklist[ i ] for i in [0,
   acct_blocklist_cnt) are the accounts no transaction may use; NULL is
   okay if acct_blocklist_cnt==0.  rng is a local join used by chkdup.
   Returns ctx, or NULL (logs) if the blocklist has more than
   FD_PACK_ACCT_BLOCKLIST_MAX entries, a duplicate, or the zero
   address. */
static inline fd_pack_est_ctx_t *
fd_pack_est_ctx_init( fd_pack_est_ctx_t *    ctx,
                      fd_acct_addr_t const * acct_blocklist,
                      ulong                  acct_blocklist_cnt,
                      fd_rng_t *             rng ) {
  fd_chkdup_new( ctx->chkdup, rng );
  fd_pack_est_blocklist_new( ctx->blocklist );
  int ins_failed = acct_blocklist_cnt>FD_PACK_ACCT_BLOCKLIST_MAX;
  for( ulong i=0UL; (!ins_failed) & (i<acct_blocklist_cnt); i++ ) {
    ins_failed |= fd_pack_est_blocklist_key_inval( acct_blocklist[i] ) ||
                  (NULL==fd_pack_est_blocklist_insert( ctx->blocklist, acct_blocklist[i] ));
  }
  if( FD_UNLIKELY( ins_failed ) ) {
    FD_LOG_WARNING(( "constructing the account blocklist failed.  Ensure the list contains no more than %lu "
                     "entries, and does not contain duplicates or the System Program (11...111)", FD_PACK_ACCT_BLOCKLIST_MAX ));
    return NULL;
  }
  return ctx;
}

/* fd_pack_est_txn fills est for the transaction with parsed form txn,
   bytes payload, and address lookup table accounts alt[ i ] for i in
   [0, txn->addr_table_adtl_cnt).  est->cost is 0 if cost estimation
   failed (malformed compute budget or precompile instruction, too many
   precompile signatures); the other fields are still filled.
   est->flags carries FD_TXN_P_FLAGS_IS_SIMPLE_VOTE, _DURABLE_NONCE and
   the FD_TXN_P_FLAGS_EST_* checks that failed. */
static inline void
fd_pack_est_txn( fd_pack_est_ctx_t *    ctx,
                 fd_txn_t const *       txn,
                 uchar const *          payload,
                 fd_acct_addr_t const * alt,
                 fd_pack_est_t *        est ) {
  fd_acct_addr_t const * accts   = fd_txn_get_acct_addrs( txn, payload );
  ulong                  imm_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  ulong                  alt_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALT );
  /* alt_adj[ i ] is account i for i>=imm_cnt */
  fd_acct_addr_t const * alt_adj = alt - imm_cnt;
#define ACCT_ITER_TO_PTR( iter ) (__extension__( {                                \
      ulong __idx = fd_txn_acct_iter_idx( iter );                                 \
      fd_ptr_if( __idx<imm_cnt, accts, alt_adj )+__idx;                           \
      }))

  uint  flags = 0U;
  ulong requested_execution_cus = 0UL;
  ulong priority_rewards        = 0UL;
  ulong precompile_sigs         = 0UL;
  ulong requested_loaded_accounts_data_cost = 0UL;
  ulong allocated_data          = 0UL;
  ulong cost = fd_pack_compute_cost( txn, payload, &flags, &requested_execution_cus, &priority_rewards, &precompile_sigs, &requested_loaded_accounts_data_cost, &allocated_data );

  /* precompile_sigs <= 16320, so after the addition,
     sig_rewards < 83,000,000 */
  ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * (txn->signature_cnt + precompile_sigs);
  sig_rewards = sig_rewards * FD_PACK_TXN_FEE_BURN_PCT / 100UL;

  est->cost     = (uint)cost;
  est->exec_cus = (uint)(requested_execution_cus + requested_loaded_accounts_data_cost);
  est->rewards  = (priority_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + priority_rewards) : UINT_MAX;
  est->alloc    = (uint)allocated_data;

  /* Durable nonce: first instruction invokes the system program with 4
     bytes of instruction data with the little-endian value 4 and at
     least 3 accounts: the nonce account, recent blockhashes sysvar,
     and the nonce authority, which must have signed. */
  if( FD_UNLIKELY( txn->instr_cnt && txn->instr[ 0 ].data_sz>=4UL && txn->instr[ 0 ].acct_cnt>=3UL &&
                   fd_uint_load_4( payload + txn->instr[ 0 ].data_off )==4U &&
                   fd_memeq( accts[ txn->instr[ 0 ].program_id ].b, fd_pack_est_null_addr.b, 32UL ) ) ) {
    flags |= fd_uint_if( fd_txn_is_signer( txn, payload[ txn->instr[ 0 ].acct_off+2 ] ), FD_TXN_P_FLAGS_DURABLE_NONCE, FD_TXN_P_FLAGS_EST_INVALID_NONCE );
  }

  int writes_to_sysvar = 0;
  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    writes_to_sysvar |= fd_pack_unwritable_contains( ACCT_ITER_TO_PTR( iter ) );
  }

  int bundle_blacklist = 0;
  int acct_blocklist   = 0;
  for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_ALL );
      iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    bundle_blacklist |= (3==fd_pack_tip_prog_check_blacklist( ACCT_ITER_TO_PTR( iter ) ));
    /* querying for the inval key is a violation of the fd_map
       contract, even though it's actually fine... */
    acct_blocklist   |= (!fd_pack_est_blocklist_key_inval( *ACCT_ITER_TO_PTR( iter ) )) &&
                        !!fd_pack_est_blocklist_query( ctx->blocklist, *ACCT_ITER_TO_PTR( iter ), NULL );
  }

  /* chkdup requires at most 128 accounts; the parser guarantees 64 */
  int too_many_accts = imm_cnt+alt_cnt>64UL;
  int dup_acct       = !too_many_accts && fd_chkdup_check( ctx->chkdup, accts, imm_cnt, alt, alt_cnt );

  flags |= fd_uint_if( too_many_accts,   FD_TXN_P_FLAGS_EST_ACCOUNT_CNT,      0U );
  flags |= fd_uint_if( dup_acct,         FD_TXN_P_FLAGS_EST_DUPLICATE_ACCT,   0U );
  flags |= fd_uint_if( writes_to_sysvar, FD_TXN_P_FLAGS_EST_WRITES_SYSVAR,    0U );
  flags |= fd_uint_if( bundle_blacklist, FD_TXN_P_FLAGS_EST_BUNDLE_BLACKLIST, 0U );
  flags |= fd_uint_if( acct_blocklist,   FD_TXN_P_FLAGS_EST_ACCT_BLOCKLIST,   0U );
  est->flags = flags;
#undef ACCT_ITER_TO_PTR
}

#endif /* HEADER_fd_src_disco_pack_fd_pack_est_h */
