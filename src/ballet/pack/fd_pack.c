#define FD_UNALIGNED_ACCESS_STYLE 0
#include "fd_pack.h"
#include "fd_pack_cost.h"
#include "fd_compute_budget_program.h"
#include <math.h> /* for sqrt */
#include <stddef.h> /* for offsetof */


/* Declare a bunch of helper structs used for pack-internal data
   structures. */


/* fd_pack_ord_txn_t: An fd_txn_p_t with information required to order
   it by priority */
struct fd_pack_private_ord_txn {
  /* It's important that there be no padding here (asserted below)
     because the code casts back and forth from pointers to this element
     to pointers to the whole struct. */
  fd_txn_p_t   txn[1];
  /* We want rewards*compute_est to fit in a ulong so that r1/c1 < r2/c2 can be
     computed as r1*c2 < r2*c1, with the product fitting in a ulong.
     compute_est has a small natural limit of mid-20 bits. rewards doesn't have
     a natural limit, so there is some argument to be made for raising the
     limit for rewards to 40ish bits. The struct has better packing with
     uint/uint though. */
  uint         rewards;     /* in Lamports */
  uint         compute_est; /* in compute units */

  /* The treap fields */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;

  /* Since this struct can be in one of several trees, it's helpful to
     store which tree.  This should be one of the FD_ORD_TXN_ROOT_*
     values. */
  int root;
};
typedef struct fd_pack_private_ord_txn fd_pack_ord_txn_t;

/* What we want is that the payload starts at byte 0 of
   fd_pack_ord_txn_t so that the trick with the signature map works
   properly.  GCC and Clang seem to disagree on the rules of offsetof.
   */
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn )==0UL, fd_pack_ord_txn_t );
#if FD_USING_CLANG
FD_STATIC_ASSERT( offsetof( fd_txn_p_t, payload )==0UL, fd_pack_ord_txn_t );
#else
FD_STATIC_ASSERT( offsetof( fd_pack_ord_txn_t, txn->payload )==0UL, fd_pack_ord_txn_t );
#endif

#define FD_ORD_TXN_ROOT_FREE 0
#define FD_ORD_TXN_ROOT_PENDING 1
#define FD_ORD_TXN_ROOT_PENDING_VOTE 2
#define FD_ORD_TXN_ROOT_DELAYED_BASE 3 /* [3, 3+FD_PACK_MAX_GAP) */

/* fd_pack_addr_use_t: Used for two distinct purposes: to record that an
   address is in use and can't be used again until the nth microblock,
   and to keep track of the cost of all transactions that write to the
   specified account.  If these were different structs, they'd have
   identical shape and result in two fd_map_dynamic sets of functions
   with identical code.  It doesn't seem like the compiler is very good
   at merging code like that, so in order to reduce code bloat, we'll
   just combine them. */
struct fd_pack_private_addr_use_record {
  fd_acct_addr_t key; /* account address */
  union{
    ulong          in_use_until; /* In microblocks */
    ulong          total_cost; /* In cost units/CUs */
  };
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;


/* fd_pack_sig_to_entry_t: An element of an fd_map that maps the first
   transaction signature to the corresponding fd_pack_ord_txn_t so that
   pending transactions can be deleted by signature.  Note: this
   implicitly relies on the fact that for Solana transactions the
   signature_offset is always 1.  If that fact changes, this will need
   to become a real struct. */
struct fd_pack_sig_to_txn {
  fd_ed25519_sig_t const * key;
};
typedef struct fd_pack_sig_to_txn fd_pack_sig_to_txn_t;


/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(x,y) ( ((ulong)((x)->rewards)*(ulong)((y)->compute_est)) < ((ulong)((y)->rewards)*(ulong)((x)->compute_est)) )

/* Declare all the data structures */


/* Define the big max-"heap" that we pull transactions off to schedule.
   The priority is given by reward/compute.  We may want to add in some
   additional terms at a later point.  In order to cheaply remove nodes,
   we actually use a treap.  */
#define POOL_NAME       trp_pool
#define POOL_T          fd_pack_ord_txn_t
#define POOL_NEXT       parent
#include "../../util/tmpl/fd_pool.c"

#define TREAP_T         fd_pack_ord_txn_t
#define TREAP_NAME      treap
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(a,b)  (__extension__({ (void)(a); (void)(b); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_LT        COMPARE_WORSE
#include "../../util/tmpl/fd_treap.c"


/* Define a strange map where key and value are kind of the same
   variable.  Essentially, it maps the contents to which the pointer
   points to the value of the pointer. */
#define MAP_NAME              sig2txn
#define MAP_T                 fd_pack_sig_to_txn_t
#define MAP_KEY_T             fd_ed25519_sig_t const *
#define MAP_KEY_NULL          NULL
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL(k0,k1)  (((!!(k0))&(!!(k1)))&&(!memcmp((k0),(k1), FD_TXN_SIGNATURE_SZ)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     fd_uint_load_4( (key) ) /* first 4 bytes of signature */
#include "../../util/tmpl/fd_map_dynamic.c"


static const fd_acct_addr_t null_addr = { 0 };

#define MAP_NAME              acct_uses
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, null_addr)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#include "../../util/tmpl/fd_map_dynamic.c"


/* Finally, we can now declare the main pack data structure */
struct fd_pack_private {
  ulong      pack_depth;
  ulong      gap;
  ulong      max_txn_per_microblock;

  ulong      pending_txn_cnt;
  ulong      microblock_cnt; /* How many microblocks have we
                                generated in this block? */
  fd_rng_t * rng;

  ulong      cumulative_block_cost;
  ulong      cumulative_vote_cost;

  /* The actual footprint for the pool and maps is allocated
     in the same order in which they are declared immediately following
     the struct.  I.e. these pointers point to memory not far after the
     struct.  The trees are just pointers into the pool so don't take up
     more space. */

  fd_pack_ord_txn_t * pool;

  /* Transactions in the pool can be in one of various trees.  The
     default situation is that the transaction is in pending
     pending_votes, depending on whether it is a vote or not.

     If this were the only storage for transactions though, in the case
     that there are a lot of transactions that conflict, we'd end up
     going through transactions a bunch of times.  To optimize that,
     when we know that we won't be able to consider a transaction until
     at least the kth microblock in the future, we stick it in a "data
     structure" like a bucket queue based on when it will become
     available.

     This is just a performance optimization and done on a best effort
     basis; a transaction coming out of delayed might still not be
     available because of new conflicts.  Transactions in pending might
     have conflicts we just haven't discovered yet.  The authoritative
     source for conflicts is acct_uses_{read,write}.

     Unlike typical bucket queues, the buckets here form a ring, and
     each element of the ring is a tree. */

  treap_t pending[1];
  treap_t pending_votes[1];
  treap_t delayed[ FD_PACK_MAX_GAP ]; /* bucket queue */

  fd_pack_addr_use_t   * read_in_use; /* Map from account address to microblock when it can be used */
  fd_pack_addr_use_t   * write_in_use;
  fd_pack_addr_use_t   * writer_costs;
  fd_pack_sig_to_txn_t * signature_map; /* Stores pointers into pool for deleting by signature */
};

typedef struct fd_pack_private fd_pack_t;

ulong
fd_pack_footprint( ulong pack_depth,
                   ulong gap,
                   ulong max_txn_per_microblock ) {
  if( FD_UNLIKELY( (gap==0) | (gap>FD_PACK_MAX_GAP) ) ) return 0UL;

  ulong l;
  ulong max_acct_in_flight = FD_TXN_ACCT_ADDR_MAX * (gap+1UL) * max_txn_per_microblock;
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );

  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PACK_ALIGN,      sizeof(fd_pack_t)                      );
  l = FD_LAYOUT_APPEND( l, trp_pool_align (),  trp_pool_footprint ( pack_depth+1UL )  );
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_uses_tbl_sz )  );
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_uses_tbl_sz )  );
  l = FD_LAYOUT_APPEND( l, acct_uses_align(),  acct_uses_footprint( lg_max_txn     )  );
  l = FD_LAYOUT_APPEND( l, sig2txn_align  (),  sig2txn_footprint  ( lg_depth       )  );
  return FD_LAYOUT_FINI( l, FD_PACK_ALIGN );
}


void *
fd_pack_new( void *     mem,
             ulong      pack_depth,
             ulong      gap,
             ulong      max_txn_per_microblock,
             fd_rng_t * rng                     ) {

  ulong max_acct_in_flight = FD_TXN_ACCT_ADDR_MAX * (gap+1UL) * max_txn_per_microblock;
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;

  /* log base 2, but with a 2* so that the hash table stays sparse */
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /* The pool has one extra element that is used between insert_init and
     cancel/fini. */
  fd_pack_t * pack   = FD_SCRATCH_ALLOC_APPEND( l,  FD_PACK_ALIGN,                  sizeof(fd_pack_t)                     );
  void * _pool       = FD_SCRATCH_ALLOC_APPEND( l,  trp_pool_align(),               trp_pool_footprint ( pack_depth+1UL ) );
  void * _uses_read  = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz ) );
  void * _uses_write = FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),              acct_uses_footprint( lg_uses_tbl_sz ) );
  void * _writer_cost= FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(),              acct_uses_footprint( lg_max_txn     ) );
  void * _sig_map    = FD_SCRATCH_ALLOC_APPEND( l,  sig2txn_align(),                sig2txn_footprint  ( lg_depth       ) );

  pack->pack_depth             = pack_depth;
  pack->gap                    = gap;
  pack->max_txn_per_microblock = max_txn_per_microblock;
  pack->pending_txn_cnt        = 0UL;
  pack->microblock_cnt         = 0UL;
  pack->rng                    = rng;
  pack->cumulative_block_cost  = 0UL;
  pack->cumulative_vote_cost   = 0UL;

  treap_new( (void*)pack->pending,       pack_depth );
  treap_new( (void*)pack->pending_votes, pack_depth );
  for( ulong i=0UL; i<FD_PACK_MAX_GAP; i++ ) treap_new( (void*)(pack->delayed+i), pack_depth );


  trp_pool_new(  _pool,        pack_depth+1UL );
  acct_uses_new( _uses_read,   lg_uses_tbl_sz );
  acct_uses_new( _uses_write,  lg_uses_tbl_sz );
  acct_uses_new( _writer_cost, lg_max_txn     );
  sig2txn_new(   _sig_map,     lg_depth       );

  fd_pack_ord_txn_t * pool = trp_pool_join( _pool );
  treap_seed( pool, pack_depth+1UL, fd_rng_ulong( rng ) );
  (void)trp_pool_leave( pool );

  return mem;
}

fd_pack_t *
fd_pack_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pack_t * pack  = FD_SCRATCH_ALLOC_APPEND( l, FD_PACK_ALIGN, sizeof(fd_pack_t) );

  ulong pack_depth             = pack->pack_depth;
  ulong gap                    = pack->gap;
  ulong max_txn_per_microblock = pack->max_txn_per_microblock;

  ulong max_acct_in_flight = FD_TXN_ACCT_ADDR_MAX * (gap+1UL) * max_txn_per_microblock;
  ulong max_txn_per_block  = FD_PACK_MAX_COST_PER_BLOCK / FD_PACK_MIN_TXN_COST;
  int lg_uses_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_acct_in_flight ) );
  int lg_max_txn     = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*max_txn_per_block  ) );
  int lg_depth       = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*pack_depth         ) );


  pack->pool          = trp_pool_join(  FD_SCRATCH_ALLOC_APPEND( l,  trp_pool_align(),  trp_pool_footprint ( pack_depth+1UL ) ) );
  pack->read_in_use   = acct_uses_join( FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(), acct_uses_footprint( lg_uses_tbl_sz ) ) );
  pack->write_in_use  = acct_uses_join( FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(), acct_uses_footprint( lg_uses_tbl_sz ) ) );
  pack->writer_costs  = acct_uses_join( FD_SCRATCH_ALLOC_APPEND( l,  acct_uses_align(), acct_uses_footprint( lg_max_txn     ) ) );
  pack->signature_map = sig2txn_join(   FD_SCRATCH_ALLOC_APPEND( l,  sig2txn_align(),   sig2txn_footprint  ( lg_depth       ) ) );

  return pack;
}



static int
fd_pack_estimate_rewards_and_compute( fd_txn_p_t        * txnp,
                                      fd_pack_ord_txn_t * out ) {
  fd_txn_t * txn = TXN(txnp);
  ulong sig_rewards = FD_PACK_FEE_PER_SIGNATURE * txn->signature_cnt;

  ulong cost = fd_pack_compute_cost( txnp, &txnp->is_simple_vote );

  if( FD_UNLIKELY( !cost ) ) return 0;

  fd_compute_budget_program_state_t cb_prog_st = {0};

  /* TODO: Refactor so that this doesn't scan all the instructions a
     second time after scanning them in fd_pack_compute_cost. */
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    uchar prog_id_idx = txn->instr[ i ].program_id;
    fd_acct_addr_t const * acct_addr = fd_txn_get_acct_addrs( txn, txnp->payload ) + (ulong)prog_id_idx;

    if( FD_UNLIKELY( !memcmp( acct_addr, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) ) {
      /* Parse the compute budget program instruction */
      if( FD_UNLIKELY( !fd_compute_budget_program_parse( txnp->payload+txn->instr[ i ].data_off, txn->instr[ i ].data_sz, &cb_prog_st )))
        return 0;
    } else {
      /* No fancy CU estimation in this version of pack */
    }
  }
  ulong adtl_rewards = 0UL;
  uint  compute_max  = 0UL;
  fd_compute_budget_program_finalize( &cb_prog_st, txn->instr_cnt, &adtl_rewards, &compute_max );
  out->rewards     = (adtl_rewards < (UINT_MAX - sig_rewards)) ? (uint)(sig_rewards + adtl_rewards) : UINT_MAX;
  out->compute_est = (uint)cost;

  out->root = txnp->is_simple_vote ? FD_ORD_TXN_ROOT_PENDING_VOTE : FD_ORD_TXN_ROOT_PENDING;

#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "TXN estimated compute %lu+-%f. Rewards: %lu + %lu", compute_expected, (double)compute_variance, sig_rewards, adtl_rewards ));
#endif

  return 1;
}

/* Can the fee payer afford to pay a transaction with the specified
   price?  Returns 1 if so, 0 otherwise.  This is just a stub that
   always returns 1 for now.  In general, this function can't be totally
   accurate, because the transactions immediately prior to this one can
   affect the balance of this fee payer, but a simple check here may be
   helpful for reducing spam. */
static int
fd_pack_can_fee_payer_afford( fd_acct_addr_t const * acct_addr,
                              ulong                  price /* in lamports */) {
  (void)acct_addr;
  (void)price;
  return 1;
}





fd_txn_p_t * fd_pack_insert_txn_init(   fd_pack_t * pack                   ) { return trp_pool_ele_acquire( pack->pool )->txn; }
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_p_t * txn ) { trp_pool_ele_release( pack->pool, (fd_pack_ord_txn_t*)txn ); }

void
fd_pack_insert_txn_fini( fd_pack_t  * pack,
                         fd_txn_p_t * txnp ) {

  fd_pack_ord_txn_t * ord = (fd_pack_ord_txn_t *)txnp;

  fd_txn_t * txn   = TXN(txnp);
  uchar * payload  = txnp->payload;

  fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, payload );

  if( FD_UNLIKELY( !fd_pack_estimate_rewards_and_compute( txnp, ord ) ) ) {
    trp_pool_ele_release( pack->pool, ord );
    return;
  }
  /* Throw out transactions ... */
  /*           ... that are unfunded */
  if( FD_UNLIKELY( !fd_pack_can_fee_payer_afford( accts, ord->rewards ) ) ) { trp_pool_ele_release( pack->pool, ord ); return; }
  /*           ... that are so big they'll never run */
  if( FD_UNLIKELY( ord->compute_est >= FD_PACK_MAX_COST_PER_BLOCK       ) ) { trp_pool_ele_release( pack->pool, ord ); return; }

  /* TODO: Add recent blockhash based expiry here */

  if( FD_UNLIKELY( pack->pending_txn_cnt == pack->pack_depth ) ) {
    /* If the tree is full, we'll double check to make sure this is
       better than the worst element in the tree before inserting.  If
       the new transaction is better than that one, we'll delete it and
       insert the new transaction. Otherwise, we'll throw away this
       transaction. */
    /* TODO: Increment a counter to mark this is happening */
    fd_pack_ord_txn_t * worst = treap_fwd_iter_ele( treap_fwd_iter_init( pack->pending, pack->pool ), pack->pool );
    if( FD_UNLIKELY( !worst ) ) {
      /* We have nothing to sacrifice because they're all in other
         trees. */
      trp_pool_ele_release( pack->pool, ord );
      return;
    }
    else if( !COMPARE_WORSE( worst, ord ) ) {
      /* What we have in the tree is better than this transaction, so just
         pretend this transaction never happened */
      trp_pool_ele_release( pack->pool, ord );
      return;
    } else {
      /* Remove the worst from the tree */
      fd_ed25519_sig_t const * worst_sig = fd_txn_get_signatures( TXN( worst->txn ), worst->txn->payload );
      sig2txn_remove( pack->signature_map, sig2txn_query( pack->signature_map, worst_sig, NULL ) );

      treap_ele_remove    ( pack->pending, worst, pack->pool );
      trp_pool_ele_release( pack->pool,    worst             );
      pack->pending_txn_cnt--;
    }
  }

  pack->pending_txn_cnt++;

  sig2txn_insert( pack->signature_map, fd_txn_get_signatures( txn, payload ) );

  if( FD_LIKELY( ord->root == FD_ORD_TXN_ROOT_PENDING_VOTE ) )
    treap_ele_insert( pack->pending_votes, ord, pack->pool );
  else
    treap_ele_insert( pack->pending,       ord, pack->pool );
}

typedef struct {
  ulong cus_scheduled;
  ulong txns_scheduled;
} sched_return_t;

static inline sched_return_t
fd_pack_schedule_next_microblock_impl( fd_pack_t  * pack,
                                       treap_t    * sched_from,
                                       int          move_delayed,
                                       ulong        cu_limit,
                                       ulong        txn_limit,
                                       fd_txn_p_t * out ) {

  ulong                gap          = pack->gap;
  fd_pack_ord_txn_t  * pool         = pack->pool;
  fd_pack_addr_use_t * read_in_use  = pack->read_in_use;
  fd_pack_addr_use_t * write_in_use = pack->write_in_use;
  fd_pack_addr_use_t * writer_costs = pack->writer_costs;

  ulong txns_scheduled = 0UL;
  ulong cus_scheduled  = 0UL;

  treap_rev_iter_t prev;
  for( treap_rev_iter_t _cur=treap_rev_iter_init( sched_from, pool );
      (cu_limit>=FD_PACK_MIN_TXN_COST) & (txn_limit>0) & !treap_rev_iter_done( _cur ); _cur=prev ) {
    prev = treap_rev_iter_next( _cur, pool );

    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );

    fd_txn_t * txn = TXN(cur->txn);
    fd_acct_addr_t const * acct = fd_txn_get_acct_addrs( txn, cur->txn->payload );

    ulong delay_until = pack->microblock_cnt;

    if( cur->compute_est>cu_limit ) {
      /* Too big to be scheduled at the moment, but might be okay for
         the next microblock, so we don't want to delay it. */
      continue;
    }

    fd_txn_acct_iter_t ctrl[1];
    /* Check conflicts between this transactions's writable accounts and
       current readers */
    for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
        i=fd_txn_acct_iter_next( i, ctrl ) ) {

      fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct[i], NULL );
      if( in_wcost_table && in_wcost_table->total_cost+cur->compute_est > FD_PACK_MAX_WRITE_COST_PER_ACCT ) {
        /* Can't be scheduled until the next block */
        delay_until = ULONG_MAX;
        break;
      }

      fd_pack_addr_use_t * in_r_table = acct_uses_query( read_in_use, acct[i], NULL );
      if( in_r_table ) { delay_until = fd_ulong_max( delay_until, in_r_table->in_use_until );
#if DETAILED_LOGGING
        FD_LOG_NOTICE(( "Stalling transaction until >= %lu because it writes %i which another transaction taken reads", delay_until, (int)acct[i].b[0] ));
#endif
      }
    }

    /* Check conflicts between all of this transactions's accounts and
       current writers */
    for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
        i=fd_txn_acct_iter_next( i, ctrl ) ) {

      fd_pack_addr_use_t * in_w_table = acct_uses_query( write_in_use,  acct[i], NULL );
      if( in_w_table ) { delay_until = fd_ulong_max( delay_until, in_w_table->in_use_until );
#if DETAILED_LOGGING
        FD_LOG_NOTICE(( "Stalling transaction until >= %lu because it reads or writes %i which another transaction taken writes", delay_until, (int)acct[i].b[0] ));
#endif
      }
    }

    if( delay_until==pack->microblock_cnt ) {
      /* Include this transaction in the microblock! */
      txns_scheduled++;
      cus_scheduled += cur->compute_est;
      cu_limit -= cur->compute_est;
      txn_limit--;

      *out++ = *cur->txn; /* TODO: this copies more bytes than necessary in most cases */

      ulong in_use_until = pack->microblock_cnt + gap;

      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {
        fd_acct_addr_t acct_addr = acct[i];

        fd_pack_addr_use_t * in_wcost_table = acct_uses_query( writer_costs, acct_addr, NULL );
        if( !in_wcost_table ) { in_wcost_table = acct_uses_insert( writer_costs, acct_addr );   in_wcost_table->total_cost = 0UL; }
        in_wcost_table->total_cost += cur->compute_est;

        fd_pack_addr_use_t * in_w_table = acct_uses_query( write_in_use,  acct_addr, NULL );
        if( !in_w_table ) in_w_table = acct_uses_insert( write_in_use, acct_addr );
        in_w_table->in_use_until = in_use_until;

      }
      for( ulong i=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY & FD_TXN_ACCT_CAT_IMM, ctrl ); i<fd_txn_acct_iter_end();
          i=fd_txn_acct_iter_next( i, ctrl ) ) {
        fd_acct_addr_t acct_addr = acct[i];

        fd_pack_addr_use_t * in_r_table = acct_uses_query( read_in_use, acct_addr, NULL );
        if( !in_r_table ) in_r_table = acct_uses_insert( read_in_use, acct_addr );
        in_r_table->in_use_until = in_use_until;
      }

      fd_ed25519_sig_t const * sig0 = fd_txn_get_signatures( txn, cur->txn->payload );
      fd_pack_sig_to_txn_t * in_tbl = sig2txn_query( pack->signature_map, sig0, NULL );
      sig2txn_remove( pack->signature_map, in_tbl );

      treap_ele_remove( sched_from, cur, pool );
      trp_pool_ele_release( pool, cur );
      pack->pending_txn_cnt--;

    } else if( move_delayed ) {
      delay_until = fd_ulong_min( delay_until, pack->microblock_cnt+FD_PACK_MAX_GAP );
      cur->root = FD_ORD_TXN_ROOT_DELAYED_BASE + (int)delay_until;

      treap_ele_remove( sched_from,                                    cur, pool );
      treap_ele_insert( pack->delayed+(delay_until % FD_PACK_MAX_GAP), cur, pool );
    }
  }


  sched_return_t to_return = { .cus_scheduled = cus_scheduled, .txns_scheduled = txns_scheduled };
  return to_return;
}



ulong
fd_pack_schedule_next_microblock( fd_pack_t *  pack,
                                  ulong        total_cus,
                                  float        vote_fraction,
                                  fd_txn_p_t * out ) {


  /* Move all the transactions that were delayed until now back into
     pending so they'll be reconsidered. */
  treap_merge( pack->pending, pack->delayed+(pack->microblock_cnt % FD_PACK_MAX_GAP), pack->pool );


  /* TODO: Decide if these are exactly how we want to handle limits */
  total_cus = fd_ulong_min( total_cus, FD_PACK_MAX_COST_PER_BLOCK - pack->cumulative_block_cost );
  ulong vote_cus = fd_ulong_min( (ulong)((float)total_cus * vote_fraction), FD_PACK_MAX_VOTE_COST_PER_BLOCK - pack->cumulative_vote_cost );
  ulong vote_reserved_txns = fd_ulong_min( vote_cus/FD_PACK_TYPICAL_VOTE_COST,
                                           (ulong)((float)pack->max_txn_per_microblock * vote_fraction) );

  ulong cu_limit  = total_cus - vote_cus;
  ulong txn_limit = pack->max_txn_per_microblock - vote_reserved_txns;
  ulong scheduled = 0UL;

  sched_return_t status;

  /* Try to schedule non-vote transactions */
  status = fd_pack_schedule_next_microblock_impl( pack, pack->pending,       1, cu_limit, txn_limit,          out+scheduled );

  scheduled += status.txns_scheduled;
  txn_limit -= status.txns_scheduled;
  cu_limit  -= status.cus_scheduled;
  pack->cumulative_block_cost += status.cus_scheduled;


  /* Schedule vote transactions */
  status = fd_pack_schedule_next_microblock_impl( pack, pack->pending_votes, 0, vote_cus, vote_reserved_txns, out+scheduled );

  scheduled                   += status.txns_scheduled;
  pack->cumulative_vote_cost  += status.cus_scheduled;
  pack->cumulative_block_cost += status.cus_scheduled;
  /* Add any remaining CUs/txns to the non-vote limits */
  txn_limit += vote_reserved_txns - status.txns_scheduled;
  cu_limit  += vote_cus - status.cus_scheduled;


  /* Fill any remaining space with non-vote transactions */
  status = fd_pack_schedule_next_microblock_impl( pack, pack->pending,       1, cu_limit, txn_limit,          out+scheduled );

  scheduled                   += status.txns_scheduled;
  pack->cumulative_block_cost += status.cus_scheduled;

  pack->microblock_cnt++;

  return scheduled;
}

ulong fd_pack_avail_txn_cnt( fd_pack_t * pack ) { return pack->pending_txn_cnt; }
ulong fd_pack_gap          ( fd_pack_t * pack ) { return pack->gap;             }

void
fd_pack_end_block( fd_pack_t * pack ) {
  pack->microblock_cnt        = 0UL;
  pack->cumulative_block_cost = 0UL;
  pack->cumulative_vote_cost  = 0UL;

  for( ulong i=0UL; i<FD_PACK_MAX_GAP; i++ ) treap_merge( pack->pending, pack->delayed+i, pack->pool );

  acct_uses_clear( pack->read_in_use  );
  acct_uses_clear( pack->write_in_use );
  acct_uses_clear( pack->writer_costs );
}

static void
release_tree( treap_t           * treap,
              fd_pack_ord_txn_t * pool ) {
  treap_fwd_iter_t next;
  for( treap_fwd_iter_t it=treap_fwd_iter_init( treap, pool ); !treap_fwd_iter_idx( it ); it=next ) {
    next = treap_fwd_iter_next( it, pool );
    ulong idx = treap_fwd_iter_idx( it );
    treap_idx_remove    ( treap, idx, pool );
    trp_pool_idx_release( pool,  idx       );
  }
}

void
fd_pack_clear_all( fd_pack_t * pack ) {
  pack->pending_txn_cnt       = 0UL;
  pack->microblock_cnt        = 0UL;
  pack->cumulative_block_cost = 0UL;
  pack->cumulative_vote_cost  = 0UL;

  release_tree( pack->pending,       pack->pool );
  release_tree( pack->pending_votes, pack->pool );
  for( ulong i=0UL; i<FD_PACK_MAX_GAP; i++ ) { release_tree( pack->delayed+i, pack->pool ); }

  acct_uses_clear( pack->read_in_use  );
  acct_uses_clear( pack->write_in_use );
  acct_uses_clear( pack->writer_costs );

  sig2txn_clear( pack->signature_map );
}

int
fd_pack_delete_transaction( fd_pack_t              * pack,
                            fd_ed25519_sig_t const * txn ) {
  fd_pack_sig_to_txn_t * in_tbl = sig2txn_query( pack->signature_map, txn, NULL );

  if( !in_tbl )
    return 0;

  /* The static asserts enforce that the payload of the transaction is
     the first element of the fd_pack_ord_txn_t struct.  The signature
     we insert is 1 byte into the start of the payload. */
  fd_pack_ord_txn_t * containing = (fd_pack_ord_txn_t *)( (uchar*)in_tbl->key - 1UL );
  treap_t * root = NULL;
  int root_idx = containing->root;
  switch( root_idx ) {
    case FD_ORD_TXN_ROOT_FREE:          /* Should be impossible */                                    return 0;
    case FD_ORD_TXN_ROOT_PENDING:       root = pack->pending;                                        break;
    case FD_ORD_TXN_ROOT_PENDING_VOTE:  root = pack->pending_votes;                                  break;
    default:                            root = pack->delayed+(root_idx-FD_ORD_TXN_ROOT_DELAYED_BASE); break;
  }
  treap_ele_remove( root, containing, pack->pool );
  trp_pool_ele_release( pack->pool, containing );
  sig2txn_remove( pack->signature_map, in_tbl );
  pack->pending_txn_cnt--;

  return 1;
}


void * fd_pack_leave ( fd_pack_t * pack ) { FD_COMPILER_MFENCE(); return (void *)pack; }
void * fd_pack_delete( void      * mem  ) { FD_COMPILER_MFENCE(); return mem;          }
