#include "../../tango/mcache/fd_mcache.h"
#include "fd_pack.h"
#include "fd_compute_budget_program.h"
#include <math.h> /* for sqrt */

#define MAX_SEARCH_DEPTH (7UL)
#define FD_PACK_MIN_COMPUTE (100UL)

ulong
fd_pack_tile_scratch_align( void ) {
  return FD_PACK_TILE_SCRATCH_ALIGN;
}

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))


ulong
fd_pack_tile_scratch_footprint( ulong bank_cnt,
                                ulong txnq_sz,
                                ulong lg_cu_est_tbl_sz) {
  /* FIXME: Limits for these? */
  /* TODO: Should some of these be passed in and not allocated by the tile? */
  ulong scratch_top = 0UL;
  int lg_tbl_sz  = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );
  SCRATCH_ALLOC( alignof(fd_pack_bank_status_t),    bank_cnt*sizeof(fd_pack_bank_status_t)   ); /* bank_in_use_until */
  SCRATCH_ALLOC( alignof(fd_pack_orderable_txn_t),  bank_cnt*sizeof(fd_pack_orderable_txn_t) ); /* last_scheduled */
  SCRATCH_ALLOC( outq_align(),                      outq_footprint( bank_cnt )               );
  SCRATCH_ALLOC( txnq_align(),                      txnq_footprint( txnq_sz )                );
  SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )         ); /* read */
  SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )         ); /* write */
  SCRATCH_ALLOC( fd_est_tbl_align(),                fd_est_tbl_footprint( lg_cu_est_tbl_sz ) );
  return fd_ulong_align_up( scratch_top, fd_pack_tile_scratch_align() );
}

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
int
fd_pack_can_fee_payer_afford( uchar const * acct_addr,
                              ulong         price /* in lamports */) {
  (void)acct_addr;
  (void)price;
  return 1;
}

void fd_pack_next_block(
    ulong                     bank_cnt,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    fd_frag_meta_t *          outq,
    fd_frag_meta_t *          out_mcache,
    ulong *                   out_seq,
    ulong                     out_depth,
    ulong *                   freelist
    ) {
  /* Send any pending transactions on the mcache */
  while( FD_UNLIKELY( outq_cnt( outq ) > 0UL ) ) {
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( out_mcache, out_depth, *out_seq, outq->sig, outq->chunk, outq->sz, outq->ctl, outq->tsorig, tspub );
    freelist_push_tail( freelist, outq->chunk );
    *out_seq = fd_seq_inc( *out_seq, 1UL );
    outq_remove_min( outq );
  }

  for( ulong i=0UL; i<bank_cnt; i++ ) {
    bank_status[    i ] = (fd_pack_bank_status_t  ){0};
    last_scheduled[ i ] = (fd_pack_orderable_txn_t){0};
  }
  /* Easiest way to clear the accts_in_use tables... */
  int lg_slot_cnt;
  lg_slot_cnt = acct_uses_lg_slot_cnt( r_accts_in_use );
  acct_uses_join( acct_uses_new( acct_uses_leave( r_accts_in_use ), lg_slot_cnt ) ); /* Documented to return r_accts_in_use */
  lg_slot_cnt = acct_uses_lg_slot_cnt( w_accts_in_use );
  acct_uses_join( acct_uses_new( acct_uses_leave( w_accts_in_use ), lg_slot_cnt ) ); /* Documented to return w_accts_in_use */
}

void fd_pack_reset(
    ulong                     bank_cnt,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    fd_frag_meta_t *          outq,
    ulong *                   freelist,
    fd_pack_orderable_txn_t * txnq,
    void *                    dcache_base
  ){

  ulong cnt = txnq_cnt( txnq );
  for( ulong i=0UL; i<cnt; i++ ) {
    freelist_push_head( freelist, fd_laddr_to_chunk( dcache_base, txnq[ i ].txnp ) );
  }
  txnq_remove_all( txnq );
  cnt = outq_cnt( outq );
  for( ulong i=0UL; i<cnt; i++ ) {
    freelist_push_head( freelist, outq[ i ].chunk );
  }
  outq_remove_all( outq );


  fd_pack_next_block( bank_cnt, bank_status, last_scheduled, r_accts_in_use, w_accts_in_use, outq,
      NULL, NULL, 0, /* Because we just cleared outq, we know these aren't needed */
      freelist
  );
}

/* insert incoming transactions into prq, sorted by rewards/compute, descending.
   To get slot, call freelist_pop_head( freelist ), then copy the data into the
   chunk it returns.  If overrun, call freelist_push_head( freelist, slot )
   instead of this function. */
void fd_pack_insert_transaction(
    ulong                     slot_chunk,
    void *                    dcache_base,
    ulong                     lamports_per_signature,
    uint                      cu_limit,
    fd_rng_t *                rng,
    fd_est_tbl_t *            cu_est_tbl,
    fd_pack_orderable_txn_t * txnq,
    ulong *                   freelist
  ) {

    fd_txn_p_t * txnp = fd_chunk_to_laddr( dcache_base, slot_chunk );
    fd_txn_t * txn = TXN(txnp);
    uchar * payload  = txnp->payload;

    fd_pack_orderable_txn_t to_insert;
    /* if( FD_LIKELY( fd_pack_is_simple_vote( txn, payload ) ) ) {
      // FIXME: Handle separately
      return;
    }*/
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
        freelist_push_head( freelist, slot_chunk );
        return;
      }
      freelist_push_head( freelist, fd_laddr_to_chunk( dcache_base, txnq[ victim_idx ].txnp ) );
      txnq_remove( txnq, victim_idx );
    }
    txnq_insert( txnq, &to_insert );
}
fd_pack_schedule_return_t
fd_pack_schedule_transaction(
    ulong                     bank_cnt,
    uint                      cu_limit,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_orderable_txn_t * txnq,
    fd_frag_meta_t *          outq,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    ulong *                   freelist,
    void *                    dcache_base,
    fd_frag_meta_t *          out_mcache,
    ulong *                   out_seq,
    ulong                     out_depth
    ) {

  fd_pack_schedule_return_t to_return = { 0 };

  /* Find first non-done thread */
  /* TODO: Consider replacing this with another small heap */
  ulong t = bank_cnt;
  uint  t_score = cu_limit;
  for( ulong i = 0; i<bank_cnt; i++ ) {
    if( !bank_status[ i ].done & (bank_status[ i ].in_use_until<t_score) ) {
      t = i;
      t_score = bank_status[ i ].in_use_until;
    }
  }
  uint now = t_score;

  /* Emit any transactions that are scheduled to start in the past */
  while( FD_UNLIKELY( outq_cnt( outq ) > 0UL ) && FD_LIKELY( outq->tspub <= now ) ) {
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( out_mcache, out_depth, *out_seq, outq->sig, outq->chunk, outq->sz, outq->ctl, outq->tsorig, tspub );
    freelist_push_tail( freelist, outq->chunk );
    *out_seq = fd_seq_inc( *out_seq, 1UL );
    outq_remove_min( outq );
    to_return.mcache_emitted_cnt++;
  }

  if( t==bank_cnt ) {
    /* block done. Reset */
    to_return.status = FD_PACK_SCHEDULE_RETVAL_ALLDONE;
    return to_return;
  }
  to_return.banking_thread = (uchar)t;

  /* Find the best transaction, sorted by rewards/(compute + stall time). We
     assume stall time is normally small so that we are likely to find the
     best by looking at the transactions sorted by rewards/compute. */
  ulong best_found_at = MAX_SEARCH_DEPTH;
  fd_pack_orderable_txn_t best = { .rewards = 0U, .compute_est = 2U, .txnp = NULL };
  uint best_stall = 0U; /* Stall time for the best transaction (already added
                           into compute_est */
  int best_would_read_after_write = 0;
  for( ulong q = 0; q<fd_ulong_min(MAX_SEARCH_DEPTH, txnq_cnt( txnq )); q++ ) {
    uint start_at = now;
    /* Check the accounts that txnq[ q ] uses to see when they are
       first available */
    fd_pack_orderable_txn_t temp = txnq[ q ];
    /* Can't aquire a write lock while another transaction has either a read
       or write lock */
    ITERATE_WRITABLE_ACCOUNTS( acct_addr, temp.txnp,
      fd_pack_addr_use_t * in_w_table = acct_uses_query( w_accts_in_use, acct_addr, NULL );
      if( in_w_table ) start_at = fd_uint_max( start_at, in_w_table->in_use_until );
      fd_pack_addr_use_t * in_r_table = acct_uses_query( r_accts_in_use, acct_addr, NULL );
      if( in_r_table ) start_at = fd_uint_max( start_at, in_r_table->in_use_until );
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
      fd_pack_addr_use_t * in_w_table = acct_uses_query( w_accts_in_use, acct_addr, NULL );
      if( in_w_table && (in_w_table->in_use_until > start_at) ) {
        fd_pack_addr_use_t * in_r_table = acct_uses_query( r_accts_in_use, acct_addr, NULL );
        /* Is there no "read shadow" or does this not fit in it? */
        if( !in_r_table || ((start_at + temp.compute_est) > in_r_table->in_use_until) ) {
          would_read_after_write = 1;
          start_at = fd_uint_max( start_at, in_w_table->in_use_until );
        }
      }
    );
    if( FD_UNLIKELY( start_at + temp.compute_est > cu_limit ) ) continue;
    temp.compute_est += (start_at - now); /* Charge it for stall */
    if( COMPARE_WORSE(best, temp) ) {
      best = temp;
      best_found_at = q;
      best_would_read_after_write = would_read_after_write;
      best_stall = start_at - now;
    }
  }
  /* Were any valid transactions found? */
  if( FD_UNLIKELY( best_found_at == MAX_SEARCH_DEPTH ) ) {
    bank_status[ t ].done = 1;
    to_return.status = FD_PACK_SCHEDULE_RETVAL_BANKDONE;
    return to_return;
  }
  if( FD_UNLIKELY( best_would_read_after_write ) ) {
    bank_status[ t ].in_use_until += best_stall;
    to_return.status = FD_PACK_SCHEDULE_RETVAL_STALLING;
    to_return.stall_duration = best_stall;
    return to_return;
    /* Don't actually schedule the transaction */
  }

  txnq_remove( txnq, best_found_at );

  to_return.status = FD_PACK_SCHEDULE_RETVAL_SCHEDULED;
  to_return.start_time = now + best_stall;

  ulong sig = (t << 32) | (now + best_stall);
  ulong tx_idx  = fd_tile_idx(); /* TODO: Hoist outside loop */
  ulong chunk = fd_laddr_to_chunk( dcache_base, best.txnp );
  int ctl_som = 1;
  int ctl_eom = 1;
  int ctl_err = 0;
  ulong   ctl    = fd_frag_meta_ctl( tx_idx, ctl_som, ctl_eom, ctl_err );

  if( FD_LIKELY( !best_stall ) ) {
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( out_mcache, out_depth, *out_seq, sig, chunk, sizeof(fd_txn_p_t), ctl, 0UL, tspub );
    *out_seq = fd_seq_inc( *out_seq, 1UL );
    freelist_push_tail( freelist, chunk );
  } else {
    fd_frag_meta_t to_insert = {
      .seq    = 0UL, /* Not known yet, ignored */
      .sig    =         sig,
      .chunk  = (uint  )chunk,
      .sz     = (ushort)sizeof(fd_txn_p_t),
      .ctl    = (ushort)ctl,
      .tsorig = 0U,
      .tspub  = now+best_stall /* Overloaded for heap use */
    };
    outq_insert( outq, &to_insert );
  }
  /* Schedule txn on thread t, ending at now+best.compute_est */
  uint txn_end_time = now + best.compute_est;
  bank_status[ t ].in_use_until = txn_end_time;
  /* iterate over accounts it uses and update to txn_end_time */
  ITERATE_WRITABLE_ACCOUNTS( acct_addr, best.txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( w_accts_in_use, acct_addr, NULL );
      if( !in_table ) { in_table = acct_uses_insert( w_accts_in_use, acct_addr ); in_table->in_use_until = 0UL; }
      in_table->in_use_until = fd_uint_max( in_table->in_use_until, txn_end_time );
  );
  /* Iterate over accounts that state->last_scheduled[ t ] used that are
     prior to now and delete them from the hash table. */
  if( FD_LIKELY( last_scheduled[ t ].txnp ) ) {
    ITERATE_WRITABLE_ACCOUNTS( acct_addr, last_scheduled[ t ].txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( w_accts_in_use, acct_addr, NULL );
      if( FD_LIKELY(in_table && in_table->in_use_until<=now ) ) acct_uses_remove( w_accts_in_use, in_table );
    );
  }
  /* Same for readonly accounts */
  ITERATE_READONLY_ACCOUNTS( acct_addr, best.txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( r_accts_in_use, acct_addr, NULL );
      if( !in_table ) { in_table = acct_uses_insert( r_accts_in_use, acct_addr ); in_table->in_use_until = 0UL; }
      in_table->in_use_until = fd_uint_max( in_table->in_use_until, txn_end_time );
  );
  /* Iterate over accounts that state->last_scheduled[ t ] used that are
     prior to now and delete them from the hash table. */
  if( FD_LIKELY( last_scheduled[ t ].txnp ) ) {
    ITERATE_READONLY_ACCOUNTS( acct_addr, last_scheduled[ t ].txnp,
      fd_pack_addr_use_t * in_table = acct_uses_query( r_accts_in_use, acct_addr, NULL );
      if( FD_LIKELY(in_table && in_table->in_use_until<=now ) ) acct_uses_remove( r_accts_in_use, in_table );
    );
  }
  last_scheduled[ t ] = best;
  return to_return;
}
