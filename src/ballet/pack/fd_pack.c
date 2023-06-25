#include "fd_pack.h"
#include "fd_compute_budget_program.h"
#include <math.h> /* for sqrt */

#define MAX_SEARCH_DEPTH (7UL)
#define FD_PACK_MIN_COMPUTE (100UL)


/* Declare a bunch of helper structs used for pack-internal data
   structures. */

struct fd_pack_private_orderable_txn {
  /* We want rewards*compute_est to fit in a ulong so that r1/c1 < r2/c2 can be
     computed as r1*c2 < r2*c1, with the product fitting in a ulong.
     compute_est has a small natural limit of mid-20 bits. rewards doesn't have
     a natural limit, so there is some argument to be made for raising the
     limit for rewards to 40ish bits. The struct has better packing with
     uint/uint though. */
  uint         rewards; /* in Lamports */
  uint         compute_est; /* in compute units */
  uint         compute_max;
  float        compute_var; /* An estimate of the variance associated with compute_est */
  fd_txn_p_t * txnp;
  ulong        __padding_reserved;
};
typedef struct fd_pack_private_orderable_txn fd_pack_orderable_txn_t;



struct fd_pack_private_addr_use_record {
  uchar * key; /* Pointer to account address */
  uint    hash; /* First 32 bits of account address */
  uint    in_use_until;
  ulong   in_use_until_var; /* FIXME: Test if 64bit hash, float var is better */
  uchar   in_use_for_bank;
  uchar   _padding[7];
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;




struct fd_pack_private_bank_status {
  int                     done;
  uint                    in_use_until;
  ulong                   in_use_until_var;
  fd_pack_orderable_txn_t last_scheduled[1];
};
typedef struct fd_pack_private_bank_status fd_pack_bank_status_t;


/* Finally, we can now declare the main pack data structure */
struct fd_pack_private {
  ulong           bank_cnt;
  ulong           bank_depth;
  ulong           pack_depth;
  ulong           cu_limit;
  fd_est_tbl_t *  est_tbl;
  fd_rng_t     *  rng;

  /* The actual footprint for the following data structures is allocated
     in the same order in which they are declared immediately following
     the struct.  I.e. these pointers point to memory not far after the
     struct. */
  fd_pack_bank_status_t   * bank_status;       /* indexed [0, bank_cnt) */
  fd_pack_scheduled_txn_t * outq;              /* an fd_prq. Use outq_* to access */
  fd_pack_orderable_txn_t * txnq;              /* an fd_prq. Use txnq_* to access */
  fd_txn_p_t            * * freelist;          /* an fd_deque_dynamic. Use freelist_* to access */
  fd_pack_addr_use_t      * acct_uses_read;    /* an fd_map_dynamic. Use acct_uses_* to access */
  fd_pack_addr_use_t      * acct_uses_write;   /* an fd_map_dynamic. Use acct_uses_* to access */
};

typedef struct fd_pack_private fd_pack_t;

/* Declare all the data structures */

#define DEQUE_NAME freelist
#define DEQUE_T    fd_txn_p_t *
#include "../../util/tmpl/fd_deque_dynamic.c"

/* Define the big max-heap that we pull transactions off to schedule. The
   priority is given by reward/compute.  We may want to add in some additional
   terms at a later point. */

/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(x,y) ( ((ulong)((x).rewards)*(ulong)((y).compute_est)) < ((ulong)((y).rewards)*(ulong)((x).compute_est)) )

#define PRQ_NAME             txnq
#define PRQ_T                fd_pack_orderable_txn_t
#define PRQ_EXPLICIT_TIMEOUT 0
#define PRQ_AFTER(x,y)       COMPARE_WORSE(x,y)
#include "../../util/tmpl/fd_prq.c"

/* Define a small min-heap for transactions we've scheduled but not
   outputted yet. */
#define PRQ_NAME        outq
#define PRQ_T           fd_pack_scheduled_txn_t
#define PRQ_TIMEOUT_T   uint
#define PRQ_TIMEOUT     start
#include "../../util/tmpl/fd_prq.c"


#define MAP_NAME              acct_uses
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             uchar *
#define MAP_KEY_NULL          NULL
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_KEY_EQUAL(k0,k1)  (((!!(k0))&(!!(k1)))&&(!memcmp((k0),(k1), FD_TXN_ACCT_ADDR_SZ)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     (*(uint*)(key))
#include "../../util/tmpl/fd_map_dynamic.c"

ulong
fd_pack_footprint( ulong bank_cnt,
                   ulong bank_depth,
                   ulong pack_depth ) {
  if( FD_UNLIKELY( bank_cnt>=256UL ) ) { FD_LOG_WARNING(( "bank_cnt too large" )); return 0UL; }

  ulong l;
  int lg_uses_tbl_sz  = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );
  ulong freelist_cnt = bank_depth*bank_cnt + pack_depth + bank_cnt;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PACK_ALIGN,                  sizeof(fd_pack_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(fd_pack_bank_status_t), sizeof(fd_pack_bank_status_t)*bank_cnt );
  l = FD_LAYOUT_APPEND( l, outq_align(),                   outq_footprint( bank_cnt )             );
  l = FD_LAYOUT_APPEND( l, txnq_align(),                   txnq_footprint( pack_depth )           );
  l = FD_LAYOUT_APPEND( l, freelist_align(),               freelist_footprint( freelist_cnt )     );
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz )  );
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz )  );
  return FD_LAYOUT_FINI( l, FD_PACK_ALIGN );
}

ulong
fd_pack_txnmem_footprint( ulong bank_cnt,
                          ulong bank_depth,
                          ulong pack_depth ) {
  ulong freelist_cnt = bank_depth*bank_cnt + pack_depth + bank_cnt;
  /* Harmonized with the way dcache allocates chunks */
  return freelist_cnt * fd_ulong_align_up( sizeof(fd_txn_p_t), fd_pack_txnmem_align() );
}

void *
fd_pack_new( void         * mem,
             void         * txnmem,
             fd_est_tbl_t * est_tbl,
             ulong          bank_cnt,
             ulong          bank_depth,
             ulong          pack_depth,
             ulong          cu_limit,
             fd_rng_t     * rng ) {
  ulong freelist_cnt   = bank_depth*bank_cnt + pack_depth + bank_cnt;
  int   lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack   = FD_SCRATCH_ALLOC_APPEND( l, FD_PACK_ALIGN,                  sizeof(fd_pack_t)                      );
  void * _bank_status= FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pack_bank_status_t), sizeof(fd_pack_bank_status_t)*bank_cnt );
  void * _outq       = FD_SCRATCH_ALLOC_APPEND( l, outq_align(),                   outq_footprint( bank_cnt )             );
  void * _txnq       = FD_SCRATCH_ALLOC_APPEND( l, txnq_align(),                   txnq_footprint( pack_depth )           );
  void * _freelist   = FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),               freelist_footprint( freelist_cnt )     );
  void * _uses_read  = FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz )  );
  void * _uses_write = FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz )  );

  pack->bank_cnt   = bank_cnt;
  pack->bank_depth = bank_depth;
  pack->pack_depth = pack_depth;
  pack->cu_limit   = cu_limit;
  pack->est_tbl    = est_tbl;
  pack->rng        = rng;

  fd_memset( _bank_status, 0, sizeof(fd_pack_bank_status_t)*bank_cnt );

  outq_new(      _outq,       bank_cnt       );
  txnq_new(      _txnq,       pack_depth     );
  freelist_new(  _freelist,   freelist_cnt   );
  acct_uses_new( _uses_read,  lg_uses_tbl_sz );
  acct_uses_new( _uses_write, lg_uses_tbl_sz );


  /* Populate the freelist */
  fd_txn_p_t * * freelist = freelist_join( _freelist );
  ulong ptr = (ulong)txnmem;
  for( ulong i=0UL; i<freelist_cnt; i++ ) {
    ptr = fd_ulong_align_up( ptr, fd_pack_txnmem_align() );
    freelist_push_tail( freelist, (fd_txn_p_t *)ptr );
    ptr += sizeof(fd_txn_p_t);
  }
  freelist_leave( freelist );

  return mem;
}

fd_pack_t *
fd_pack_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack  = FD_SCRATCH_ALLOC_APPEND( l, FD_PACK_ALIGN, sizeof(fd_pack_t) );
  ulong bank_cnt   = pack->bank_cnt;
  ulong bank_depth = pack->bank_depth;
  ulong pack_depth = pack->pack_depth;

  ulong freelist_cnt   = bank_depth*bank_cnt + pack_depth + bank_cnt;
  int   lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );

  const ulong bank_status_align = alignof(fd_pack_bank_status_t);
  pack->bank_status     =                 FD_SCRATCH_ALLOC_APPEND( l, bank_status_align, sizeof(fd_pack_bank_status_t)*bank_cnt );
  pack->outq            = outq_join(      FD_SCRATCH_ALLOC_APPEND( l, outq_align(),      outq_footprint( bank_cnt )           ) );
  pack->txnq            = txnq_join(      FD_SCRATCH_ALLOC_APPEND( l, txnq_align(),      txnq_footprint( pack_depth )         ) );
  pack->freelist        = freelist_join(  FD_SCRATCH_ALLOC_APPEND( l, freelist_align(),  freelist_footprint( freelist_cnt )   ) );
  pack->acct_uses_read  = acct_uses_join( FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(), acct_uses_footprint( lg_uses_tbl_sz )) );
  pack->acct_uses_write = acct_uses_join( FD_SCRATCH_ALLOC_APPEND( l, acct_uses_align(), acct_uses_footprint( lg_uses_tbl_sz )) );

  return pack;
}

ulong fd_pack_bank_cnt( fd_pack_t * pack ) { return pack->bank_cnt; }

ulong fd_pack_avail_txn_cnt( fd_pack_t * pack ) { return outq_cnt( pack->outq ); }


/* Helper function that determines whether a transaction is considered a
   "simple vote" transaction.  Simple vote transactions are scheduled to a
   special vote banking thread and don't go through the normal prioritization
   logic.  A simple vote transaction has exactly 1 instruction that invokes the
   vote program and has "Vote" in its name.  This function is designed for high
   performance and does very minimal validation that the vote instruction is
   well-formed.  Returns 1 if the transaction is a simple vote transaction and
   0 otherwise. */
/* FIXME: This function does not belong here, but where does it belong? */
// static int
// fd_pack_is_simple_vote( fd_txn_t  * txn,
//                         uchar     * payload ) {
//   /* "Vote" is the smallest instruction.  It has a 4B tag, a vector (8B length
//      prefix), a 32B hash, and an optional ulong timestamp.  The minimum size is
//      when the vector is empty and the timestamp is not present.  Thus,
//      4+8+32+1=45. */
//   const ulong min_simple_vote_instr_data_len = 45UL;
//   /* base58 decode of Vote111111111111111111111111111111111111111 */
//   const uchar FD_VOTE_PROGRAM_ID[FD_TXN_ACCT_ADDR_SZ] = {
//     0x07,0x61,0x48,0x1d,0x35,0x74,0x74,0xbb,0x7c,0x4d,0x76,0x24,0xeb,0xd3,0xbd,0xb3,
//     0xd8,0x35,0x5e,0x73,0xd1,0x10,0x43,0xfc,0x0d,0xa3,0x53,0x80,0x00,0x00,0x00,0x00
//   };
//   if( FD_UNLIKELY( txn->transaction_version != FD_TXN_VLEGACY )                     ) return 0;
//   if( FD_UNLIKELY( txn->instr_cnt != 1 )                                            ) return 0;
//   uchar * program_id = payload + txn->acct_addr_cnt + FD_TXN_ACCT_ADDR_SZ*txn->instr[ 0 ].program_id;
//   if( FD_UNLIKELY( !memcmp( program_id, FD_VOTE_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) ) return 0;
//   if( FD_UNLIKELY( txn->instr[ 0 ].data_sz < min_simple_vote_instr_data_len )       ) return 0;
//   uint instr_tag = *(uint*)(payload + txn->instr[ 0 ].data_off);
//   if( FD_LIKELY( instr_tag == 2U ) ) /* Corresponds to Vote */                        return 1;
//   /* All the other exotic variants that are still recognized as simple votes */
// /* FIXME: Replace these magic numbers with constants when we write the full
//    vote parsing code. */
//   return (int)FD_UNLIKELY( (instr_tag==6U) | (instr_tag==8U) | (instr_tag==9U) | (instr_tag==12U) | (instr_tag==13U) );
// }

#define ITERATE_WRITABLE_ACCOUNTS( acct_addr, txnp, body )                                                                    \
  do {                                                                                                                        \
    fd_txn_p_t * _txnp = (txnp);                                                                                              \
    fd_txn_t   * _txn  = TXN(_txnp);                                                                                          \
    for( ulong i=0UL; i<(((ulong)(_txn->signature_cnt))-((ulong)(_txn->readonly_signed_cnt))); i++ ) {                        \
      uchar * acct_addr = _txnp->payload + _txn->acct_addr_off + i*FD_TXN_ACCT_ADDR_SZ;                                       \
      body                                                                                                                    \
    }                                                                                                                         \
    for( ulong i=(ulong)(_txn->signature_cnt); i<((ulong)(_txn->acct_addr_cnt)-(ulong)(_txn->readonly_unsigned_cnt)); i++ ) { \
      uchar * acct_addr = _txnp->payload + _txn->acct_addr_off + i*FD_TXN_ACCT_ADDR_SZ;                                       \
      body                                                                                                                    \
    }                                                                                                                         \
  } while( 0 )

#define ITERATE_READONLY_ACCOUNTS( acct_addr, txnp, body )                                                                      \
  do {                                                                                                                          \
    fd_txn_p_t * _txnp = (txnp);                                                                                                \
    fd_txn_t   * _txn  = TXN(_txnp);                                                                                            \
    for( ulong i=(ulong)(_txn->signature_cnt)-(ulong)(_txn->readonly_signed_cnt); i<((ulong)(_txn->signature_cnt)); i++ ) {     \
      uchar * acct_addr = _txnp->payload + _txn->acct_addr_off + i*FD_TXN_ACCT_ADDR_SZ;                                         \
      body                                                                                                                      \
    }                                                                                                                           \
    for( ulong i=((ulong)(_txn->acct_addr_cnt)-(ulong)(_txn->readonly_unsigned_cnt)); i<((ulong)(_txn->acct_addr_cnt)); i++ ) { \
      uchar * acct_addr = _txnp->payload + _txn->acct_addr_off + i*FD_TXN_ACCT_ADDR_SZ;                                         \
      body                                                                                                                      \
    }                                                                                                                           \
  } while( 0 )

static int
fd_pack_estimate_rewards_and_compute( fd_txn_p_t              * txnp,
                                      ulong                     lamports_per_signature,
                                      fd_est_tbl_t const      * cu_estimation_tbl,
                                      fd_pack_orderable_txn_t * out ) {
  fd_txn_t * txn = TXN(txnp);
  ulong sig_rewards = lamports_per_signature * txn->signature_cnt;
  fd_compute_budget_program_state_t cb_prog_st = {0};
  ulong compute_expected = 0UL;
  float compute_variance = 0.0f;
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    uchar prog_id_idx = txn->instr[ i ].program_id;
    if( FD_UNLIKELY( prog_id_idx>=txn->acct_addr_cnt ) ) return 0; /* FIXME: Support txn v0 and address tables */
    uchar* acct_addr = txnp->payload + txn->acct_addr_off + (ulong)prog_id_idx*FD_TXN_ACCT_ADDR_SZ;
    if( FD_UNLIKELY( !memcmp( acct_addr, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) ) {
      /* Parse the compute budget program instruction */
      if( FD_UNLIKELY( !fd_compute_budget_program_parse( txnp->payload+txn->instr[ i ].data_off, txn->instr[ i ].data_sz, &cb_prog_st )))
        return 0;
    } else {
      /* Lookup (first 15 bytes of program ID followed by first byte of instr data) in hash table */
      ulong word1 = *(ulong*)acct_addr;
      ulong word2 = (*(ulong*)(acct_addr + sizeof(ulong))) & 0xFFFFFFFFFFFFFF00UL;
      /* Set last byte of word2 to first byte of instruction data (or 0 if there's no instruction data). */
      if( FD_LIKELY( txn->instr[ i ].data_sz ) ) word2 ^= (ulong)txnp->payload[ txn->instr[ i ].data_off ];
      ulong hash = (fd_ulong_hash( word1 ) ^ fd_ulong_hash( word2 ));
      double out_var = 0.0;
      compute_expected += (ulong)(0.5 + fd_est_tbl_estimate( cu_estimation_tbl, hash, &out_var ));
      /* Assuming statistical independence, so Var[a+b] = Var[a]+Var[b] */
      compute_variance += (float)out_var;
    }
  }
  compute_expected = fd_ulong_max( compute_expected, FD_PACK_MIN_COMPUTE );
  ulong adtl_rewards = 0UL;
  uint  compute_max  = 0UL;
  fd_compute_budget_program_finalize( &cb_prog_st, txn->instr_cnt, &adtl_rewards, &compute_max );
  out->rewards     = (adtl_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + adtl_rewards) : UINT_MAX;
  out->compute_est = (uint)compute_expected;
  out->compute_var = compute_variance;
  out->compute_max = compute_max;
  out->txnp        = txnp;

#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "TXN estimated compute %lu+-%f. Rewards: %lu + %lu", compute_expected, (double)compute_variance, sig_rewards, adtl_rewards ));
#endif

  return 1;
}

/* Can the fee payer afford to pay a transaction with the specified price?
   Returns 1 if so, 0 otherwise.  This is just a stub that always returns 1 for
   now.  In general, this function can't be totally accurate, because the
   transactions immediately prior to this one can affect the balance of this
   fee payer, but a simple check here may be helpful for reducing spam. */
static int
fd_pack_can_fee_payer_afford( uchar const * acct_addr,
                              ulong         price /* in lamports */) {
  (void)acct_addr;
  (void)price;
  return 1;
}





fd_txn_p_t * fd_pack_insert_txn_init(   fd_pack_t * pack                   ) { return freelist_pop_head( pack->freelist ); }
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_p_t * txn ) { freelist_push_head( pack->freelist, txn );  }

void
fd_pack_insert_txn_fini( fd_pack_t  * pack,
                         fd_txn_p_t * txnp ) {
  ulong lamports_per_signature = 5000UL;

  ulong                     cu_limit   = pack->cu_limit;
  fd_est_tbl_t            * cu_est_tbl = pack->est_tbl;
  fd_txn_p_t            * * freelist   = pack->freelist;
  fd_pack_orderable_txn_t * txnq       = pack->txnq;
  fd_rng_t                * rng        = pack->rng;

  fd_txn_t * txn = TXN(txnp);
  uchar * payload  = txnp->payload;

  fd_pack_orderable_txn_t to_insert;

  if( FD_UNLIKELY( !fd_pack_estimate_rewards_and_compute( txnp, lamports_per_signature, cu_est_tbl, &to_insert) ) )
    return;
  /* Throw out transactions ... */
  /*           ... that are unfunded */
  if( FD_UNLIKELY( !fd_pack_can_fee_payer_afford( payload + txn->acct_addr_off, to_insert.rewards )) ) return;
  /*           ... that are so big they'll never run */
  if( FD_UNLIKELY( to_insert.compute_est >= cu_limit                                               ) ) return;

  /* Add a random perturbation to prevent some worst-case scenarios */
  int delta = (int)(0.5f + fd_rng_float_norm( rng ) * 0.25f * sqrtf( to_insert.compute_var ));
  /* Clamp delta to the range [-compute_est + 1, compute_max - compute_est ]
     so that compute_est in [1, compute_max]. */
  delta = fd_int_max( 1-(int)to_insert.compute_est, fd_int_min( (int)to_insert.compute_max-(int)to_insert.compute_est, delta ));
  to_insert.compute_est = (uint)((int)to_insert.compute_est + delta);


  if( FD_UNLIKELY( txnq_cnt( txnq ) == txnq_max( txnq ) ) ) {
    /* If the heap is full, we'll pick a random element from near the bottom
       of the heap. If the new transaction is better than that one, we'll
       delete it and insert the new transaction. Otherwise, we'll throw away
       this transaction. */
    /* TODO: Increment a counter to mark this is happening */
    ulong txnq_sz = txnq_max( txnq );
    ulong victim_idx = txnq_sz/2UL + fd_rng_ulong_roll( rng, txnq_sz/2UL ); /* in [txnq_sz/2, txnq_sz) */
    if( FD_UNLIKELY( !COMPARE_WORSE( txnq[ victim_idx ], to_insert ) ) ) {
      /* What we have in the queue is better than this transaction, so just
         pretend this transaction never happened */
      freelist_push_head( freelist, txnp );
      return;
    }
    freelist_push_head( freelist, txnq[ victim_idx ].txnp );
    txnq_remove( txnq, victim_idx );
  }
  txnq_insert( txnq, &to_insert );
}


fd_pack_scheduled_txn_t
fd_pack_schedule_next( fd_pack_t * pack ) {

  ulong bank_cnt = pack->bank_cnt;
  ulong cu_limit = pack->cu_limit;

  fd_pack_bank_status_t   * bank_status       = pack->bank_status;
  fd_pack_scheduled_txn_t * outq              = pack->outq;
  fd_pack_orderable_txn_t * txnq              = pack->txnq;
  fd_txn_p_t            * * freelist          = pack->freelist;
  fd_pack_addr_use_t      * acct_uses_read  = pack->acct_uses_read;
  fd_pack_addr_use_t      * acct_uses_write = pack->acct_uses_write;

  /* Find first non-done thread */
  /* TODO: Consider replacing this with another small heap */
  ulong t = bank_cnt;
  ulong t_score = cu_limit;
  for( ulong i = 0; i<bank_cnt; i++ ) {
    if( !bank_status[ i ].done & (bank_status[ i ].in_use_until<t_score) ) {
      t = i;
      t_score = bank_status[ i ].in_use_until;
    }
  }
  ulong now = t_score;

  /* Emit any transactions that are scheduled to start in the past */
  if( FD_UNLIKELY( outq_cnt( outq ) > 0UL ) && FD_LIKELY( outq->start <= now ) ) {
    fd_pack_scheduled_txn_t to_return = *outq;
    freelist_push_tail( freelist, to_return.txn );
    outq_remove_min( outq );
    return to_return;
  }

  /* Find the best transaction, sorted by rewards/(compute + stall time). We
     assume stall time is normally small so that we are likely to find the
     best by looking at the transactions sorted by rewards/compute. */
  ulong best_found_at = MAX_SEARCH_DEPTH;
  fd_pack_orderable_txn_t best = { .rewards = 0U, .compute_est = 2U, .txnp = NULL };
  ulong best_stall = 0U; /* Stall time for the best transaction (already added
                            into compute_est */
  int best_would_read_after_write = 0;
  for( ulong q = 0; q<fd_ulong_min(MAX_SEARCH_DEPTH, txnq_cnt( txnq )); q++ ) {
    ulong start_at = now;
    /* Check the accounts that txnq[ q ] uses to see when they are
       first available */
    fd_pack_orderable_txn_t temp = txnq[ q ];
    /* Can't aquire a write lock while another transaction has either a read
       or write lock */
    ITERATE_WRITABLE_ACCOUNTS( acct_addr, temp.txnp,
      fd_pack_addr_use_t * in_w_table = acct_uses_query( acct_uses_write, acct_addr, NULL );
      if( in_w_table ) start_at = fd_ulong_max( start_at, in_w_table->in_use_until );
      fd_pack_addr_use_t * in_r_table = acct_uses_query( acct_uses_read, acct_addr, NULL );
      if( in_r_table ) start_at = fd_ulong_max( start_at, in_r_table->in_use_until );
    );
    /* If this transaction reads an account that another transaction is
       reading, it's fine except for in one case: if we've scheduled a write
       transaction for the future and this transaction won't finish before
       the write transaction is scheduled to start.  We know that we're in
       this case if the account is in the read list and the write list.  The
       read/write "in use until" table structure is not flexible enough to
       describe arbitrtary patterns of read and write, so this (read followed
       by write) is the only one we allow.  In the problem case, we just
       stall the thread until it would start.  Next time this thread is up
       for scheduling, it can revisit the situation. */
    int would_read_after_write = 0;
    ITERATE_READONLY_ACCOUNTS( acct_addr, temp.txnp,
      fd_pack_addr_use_t * in_w_table = acct_uses_query( acct_uses_write, acct_addr, NULL );
      if( in_w_table && (in_w_table->in_use_until > start_at) ) {
        fd_pack_addr_use_t * in_r_table = acct_uses_query( acct_uses_read, acct_addr, NULL );
        /* Is there no "read shadow" or does this not fit in it? */
        if( !in_r_table || ((start_at + temp.compute_est) > in_r_table->in_use_until) ) {
          would_read_after_write = 1;
          start_at = fd_ulong_max( start_at, in_w_table->in_use_until );
        }
      }
    );
    if( FD_UNLIKELY( start_at + temp.compute_est > cu_limit ) ) continue;
    temp.compute_est += (uint)(start_at - now); /* Charge it for stall */
    if( COMPARE_WORSE(best, temp) ) {
      best = temp;
      best_found_at = q;
      best_would_read_after_write = would_read_after_write;
      best_stall = start_at - now;
    }
  }
  fd_pack_scheduled_txn_t null_return = {
    .txn   = NULL,
    .bank  = 0U,
    .start = 0U,
  };
  /* Were any valid transactions found? */
  if( FD_UNLIKELY( best_found_at == MAX_SEARCH_DEPTH ) ) {
    return null_return;
  }
  if( FD_UNLIKELY( best_would_read_after_write ) ) {
    bank_status[ t ].in_use_until += (uint)best_stall;
    return null_return;
    /* Don't actually schedule the transaction */
  }

  txnq_remove( txnq, best_found_at );

  fd_pack_scheduled_txn_t scheduled = {
    .txn   = best.txnp,
    .bank  = (uint)t,
    .start = (uint)(now+best_stall),
  };
  if( FD_LIKELY( !best_stall ) ) {
    freelist_push_tail( freelist, best.txnp );
  } else {
    outq_insert( outq, &scheduled );
    scheduled = null_return; /* don't actually return it */
  }

  /* Schedule txn on thread t, ending at now+best.compute_est */
  uint txn_end_time = (uint)(now + best.compute_est);
  bank_status[ t ].in_use_until = txn_end_time;
  /* iterate over accounts it uses and update to txn_end_time */
  ITERATE_WRITABLE_ACCOUNTS( acct_addr, best.txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( acct_uses_write, acct_addr, NULL );
      if( !in_table ) { in_table = acct_uses_insert( acct_uses_write, acct_addr ); in_table->in_use_until = 0UL; }
      in_table->in_use_until = fd_uint_max( in_table->in_use_until, txn_end_time );
  );
  /* Iterate over accounts that last_scheduled[ t ] used that are
     prior to now and delete them from the hash table. */
  if( FD_LIKELY( bank_status[ t ].last_scheduled->txnp ) ) {
    ITERATE_WRITABLE_ACCOUNTS( acct_addr, bank_status[ t ].last_scheduled->txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( acct_uses_write, acct_addr, NULL );
      if( FD_LIKELY(in_table && in_table->in_use_until<=now ) ) acct_uses_remove( acct_uses_write, in_table );
    );
  }
  /* Same for readonly accounts */
  ITERATE_READONLY_ACCOUNTS( acct_addr, best.txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( acct_uses_read, acct_addr, NULL );
      if( !in_table ) { in_table = acct_uses_insert( acct_uses_read, acct_addr ); in_table->in_use_until = 0UL; }
      in_table->in_use_until = fd_uint_max( in_table->in_use_until, txn_end_time );
  );
  /* Iterate over accounts that state->last_scheduled[ t ] used that are
     prior to now and delete them from the hash table. */
  if( FD_LIKELY( bank_status[ t ].last_scheduled->txnp ) ) {
    ITERATE_READONLY_ACCOUNTS( acct_addr, bank_status[ t ].last_scheduled->txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( acct_uses_read, acct_addr, NULL );
      if( FD_LIKELY(in_table && in_table->in_use_until<=now ) ) acct_uses_remove( acct_uses_read, in_table );
    );
  }
  bank_status[ t ].last_scheduled[ 0 ] = best;
  return scheduled;
}

fd_pack_scheduled_txn_t
fd_pack_drain_block( fd_pack_t * pack ) {
  if( FD_LIKELY( outq_cnt( pack->outq ) > 0UL ) ) {
    fd_pack_scheduled_txn_t to_return = *pack->outq;
    freelist_push_tail( pack->freelist, to_return.txn );
    outq_remove_min( pack->outq );
    return to_return;
  }

  fd_pack_scheduled_txn_t null_return = {
    .txn   = NULL,
    .bank  = 0U,
    .start = 0U,
  };
  return null_return;
}

void
fd_pack_clear( fd_pack_t * pack,
               int         full_reset ) {

  ulong                     bank_cnt          = pack->bank_cnt;
  fd_pack_bank_status_t   * bank_status       = pack->bank_status;
  fd_pack_scheduled_txn_t * outq              = pack->outq;
  fd_pack_orderable_txn_t * txnq              = pack->txnq;
  fd_txn_p_t            * * freelist          = pack->freelist;
  fd_pack_addr_use_t      * acct_uses_read  = pack->acct_uses_read;
  fd_pack_addr_use_t      * acct_uses_write = pack->acct_uses_write;

  fd_memset( bank_status, 0, sizeof(fd_pack_bank_status_t)*bank_cnt );

  /* Easiest way to clear the accts_in_use tables... */
  int lg_slot_cnt;
  lg_slot_cnt = acct_uses_lg_slot_cnt( acct_uses_read );
  acct_uses_join( acct_uses_new( acct_uses_leave( acct_uses_read  ), lg_slot_cnt ) ); /* Documented to return acct_uses_read */
  lg_slot_cnt = acct_uses_lg_slot_cnt( acct_uses_write );
  acct_uses_join( acct_uses_new( acct_uses_leave( acct_uses_write ), lg_slot_cnt ) );

  ulong cnt = outq_cnt( outq );
  for( ulong i=0UL; i<cnt; i++ ) {
    freelist_push_head( freelist, outq[ i ].txn );
  }
  outq_remove_all( outq );

  if( FD_LIKELY( !full_reset ) ) return;


  cnt = txnq_cnt( txnq );
  for( ulong i=0UL; i<cnt; i++ ) {
    freelist_push_head( freelist, txnq[ i ].txnp );
  }
  txnq_remove_all( txnq );
}


void * fd_pack_leave ( fd_pack_t * pack ) { FD_COMPILER_MFENCE(); return (void *)pack; }
void * fd_pack_delete( void      * mem  ) { FD_COMPILER_MFENCE(); return mem;          }
