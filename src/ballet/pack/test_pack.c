#include "../fd_ballet.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"
#include "fd_pack.h"
#include "fd_compute_budget_program.h"
#include "../txn/fd_txn.h"
#include <math.h>

#define MAX_TEST_TXNS (1024UL)
#define DUMMY_PAYLOAD_MAX_SZ (FD_TXN_ACCT_ADDR_SZ * 256UL + 64UL)
uchar txn_scratch[ MAX_TEST_TXNS ][ FD_TXN_MAX_SZ ];
uchar payload_scratch[ MAX_TEST_TXNS ][ DUMMY_PAYLOAD_MAX_SZ ];
ulong payload_sz[ MAX_TEST_TXNS ];

#define PACK_SCRATCH_SZ (128UL*1024UL*1024UL)
uchar pack_scratch[ PACK_SCRATCH_SZ ];


const char SIGNATURE_SUFFIX[ FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint) ] = ": this is the fake signature of transaction number ";
const char WORK_PROGRAM_ID[ FD_TXN_ACCT_ADDR_SZ ] = "Work Program Id Consumes 1<<j CU";

fd_rng_t _rng[1];
fd_rng_t * rng;

typedef struct {
    fd_pack_bank_status_t *   bank_status;
    fd_pack_orderable_txn_t * last_scheduled;
    fd_pack_orderable_txn_t * txnq;
    fd_frag_meta_t *          outq;
    fd_pack_addr_use_t *      r_accts_in_use;
    fd_pack_addr_use_t *      w_accts_in_use;
    fd_est_tbl_t *            cu_est_tbl;
    ulong *                   freelist;
    uchar *                   dcache;
    fd_frag_meta_t *          mcache;
    fd_rng_t *                rng;
    uint                      cu_limit;
    ulong                     bank_cnt;
    uchar *                   dcache_base;
    ulong                     seq;
    ulong                     mcache_depth;
} pack_state;

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))
void init_all( ulong bank_cnt, ulong txnq_sz, ulong cu_est_tbl_sz, uint cu_limit, pack_state * out ) {
  /* packing state */
  fd_pack_bank_status_t *   bank_status;
  fd_pack_orderable_txn_t * last_scheduled;
  fd_pack_orderable_txn_t * txnq;
  fd_frag_meta_t *          outq;
  fd_pack_addr_use_t *      r_accts_in_use;
  fd_pack_addr_use_t *      w_accts_in_use;
  fd_est_tbl_t *            cu_est_tbl;
  ulong *                   freelist;
  uchar *                   dcache;
  fd_frag_meta_t *          mcache;


  memset( pack_scratch, 0, PACK_SCRATCH_SZ );
  /* Allocate the structures packing needs */

  int lg_tbl_sz  = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );
  /* We need for the freelist always to have at least txnq_sz free elements.
     Since each chunk is in exactly one of:
   * freelist
   * txnq (at most txnq_sz)
   * outq (at most 1 per bank thread)
   Then we should initialize freelist with 2*txnq_sz+bank_cnt elements. */
  ulong freelist_sz = 2UL*txnq_sz+bank_cnt;

  ulong scratch_top = (ulong)pack_scratch;
  ulong dcache_data_sz = fd_dcache_req_data_sz( sizeof(fd_txn_p_t), txnq_sz, 1UL, 1 );
  void * outq_shmem;
  void * txnq_shmem;
  void * r_accts_iu_shmem;
  void * w_accts_iu_shmem;
  void * cu_est_tbl_shmem;
  void * freelist_shmem;
  void * dcache_shmem;
  void * mcache_shmem;
  bank_status      = SCRATCH_ALLOC( alignof(fd_pack_bank_status_t),    bank_cnt*sizeof(fd_pack_bank_status_t)     );
  last_scheduled   = SCRATCH_ALLOC( alignof(fd_pack_orderable_txn_t),  bank_cnt*sizeof(fd_pack_orderable_txn_t)   );
  outq_shmem       = SCRATCH_ALLOC( outq_align(),                      outq_footprint( bank_cnt )                 );
  txnq_shmem       = SCRATCH_ALLOC( txnq_align( ),                     txnq_footprint( txnq_sz )                  );
  r_accts_iu_shmem = SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
  w_accts_iu_shmem = SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
  cu_est_tbl_shmem = SCRATCH_ALLOC( fd_est_tbl_align( ),               fd_est_tbl_footprint( cu_est_tbl_sz )      );
  freelist_shmem   = SCRATCH_ALLOC( freelist_align( ),                 freelist_footprint( freelist_sz)           );
  dcache_shmem     = SCRATCH_ALLOC( fd_dcache_align( ),                fd_dcache_footprint( dcache_data_sz, 0UL ) );
  mcache_shmem     = SCRATCH_ALLOC( fd_mcache_align( ),                fd_mcache_footprint( txnq_sz, 0UL )        );

  ulong consumed = scratch_top-(ulong)pack_scratch;
  if( consumed>PACK_SCRATCH_SZ ) FD_LOG_ERR(( "Test required %lu bytes, but scratch was only %lu", consumed, PACK_SCRATCH_SZ ));
#if DETAILED_STATUS_MESSAGES
  else                        FD_LOG_NOTICE(( "Test required %lu bytes of %lu available bytes",    consumed, PACK_SCRATCH_SZ ));
#endif

  outq             = outq_join(             outq_new( outq_shmem,       bank_cnt            ) );
  txnq             = txnq_join(             txnq_new( txnq_shmem,       txnq_sz             ) );
  r_accts_in_use   = acct_uses_join(   acct_uses_new( r_accts_iu_shmem, lg_tbl_sz           ) );
  w_accts_in_use   = acct_uses_join(   acct_uses_new( w_accts_iu_shmem, lg_tbl_sz           ) );
  cu_est_tbl       = fd_est_tbl_join( fd_est_tbl_new( cu_est_tbl_shmem, cu_est_tbl_sz, 1000UL,
        FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT ) );
  freelist         = freelist_join(     freelist_new( freelist_shmem,   freelist_sz         ) );
  dcache           = fd_dcache_join(   fd_dcache_new( dcache_shmem,     dcache_data_sz, 0UL ) );
  mcache           = fd_mcache_join(   fd_mcache_new( mcache_shmem,     txnq_sz, 0UL, 1UL   ) );

  /* Init free list */
  uchar * dcache_base = dcache_shmem;
  ulong   chunk0      = fd_dcache_compact_chunk0( dcache_base, dcache );
  ulong   wmark       = fd_dcache_compact_wmark ( dcache_base, dcache, sizeof(fd_txn_p_t) );
  ulong   chunk       = chunk0;
  for( ulong i=0UL; i<2UL*txnq_sz+bank_cnt; i++ ) {
    freelist_push_tail( freelist, chunk );
    chunk = fd_dcache_compact_next( chunk, sizeof(fd_txn_p_t), chunk0, wmark );
  }

  /* Train cu_est_tbl in accordance with the way make_transaction will use it,
     i.e. calling WORK_PROGRAM_ID with 1 byte of instruction data, k, where
     0<=k<32, takes 2^k CUs. */
  ulong word1 = *(ulong*)WORK_PROGRAM_ID;
  ulong word2 = (*(ulong*)(WORK_PROGRAM_ID + sizeof(ulong)));
  int maxpos = 0;
  /* How many bits do we need to prevent collisions? */
  for( ulong kA=0UL; kA<32; kA++ ) {
    ulong word2A = (word2 & ~(ulong)0xFF) | kA;
    ulong hashA = (fd_ulong_hash( word1 ) ^ fd_ulong_hash( word2A ));
    for( ulong kB=kA+1; kB<32; kB++ ) {
      ulong word2B = (word2 & ~(ulong)0xFF) | kB;
      ulong hashB = (fd_ulong_hash( word1 ) ^ fd_ulong_hash( word2B ));
      ulong differ_mask = (hashA ^ hashB); /* 1 where they differ */
      int pos = fd_ulong_find_lsb( differ_mask );
      if( pos>maxpos ) {
        maxpos = pos;
      }
    }
  }
  FD_TEST( cu_est_tbl_sz > (1UL<<maxpos) );
  for( ulong k=0UL; k<32; k++ ) {
    word2 = (word2 & ~(ulong)0xFF) | k;
    ulong hash = (fd_ulong_hash( word1 ) ^ fd_ulong_hash( word2 ));
    for( ulong l=0UL; l<2000UL; l++ ) {
      fd_est_tbl_update( cu_est_tbl, hash, 1U<<(int)k );
    }
    double var = 0.0;
    /* If these fail, the cu_est_tbl is too small */
    FD_TEST( (ulong)(fd_est_tbl_estimate( cu_est_tbl, hash, &var ) + 0.5) == (1UL<<k) );
    FD_TEST( var<1.0 );
  }

  out->bank_status      = bank_status;
  out->last_scheduled   = last_scheduled;
  out->txnq             = txnq;
  out->outq             = outq;
  out->r_accts_in_use   = r_accts_in_use;
  out->w_accts_in_use   = w_accts_in_use;
  out->cu_est_tbl       = cu_est_tbl;
  out->freelist         = freelist;
  out->dcache           = dcache;
  out->mcache           = mcache;
  out->cu_limit         = cu_limit;
  out->bank_cnt         = bank_cnt;
  out->dcache_base      = dcache_base;
  out->seq              = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcache ) );
  out->mcache_depth     = txnq_sz;
}


/* Makes enough of a transaction to schedule that reads one account for each
   character in reads and writes one account for each character in writes.
   The characters before the nul-terminator in reads and writes should be in
   [0x30, 0x70), basically numbers and uppercase letters.  Adds a unique
   signer.  Packing should estimate compute usage near the specified value.
   Fee will be set to 5^priority, so that even with a large stall, it should
   still schedule in decreasing priority order. priority should be in (0,
   13.5].  Stores the created transaction in txn_scratch[ i ] and
   payload_scratch[ i ]. */
void make_transaction( ulong i, uint compute, double priority, const char * writes, const char * reads ) {
  uchar * p = payload_scratch[ i ];
  uchar * p_base = p;
  fd_txn_t * t = (fd_txn_t*) txn_scratch[ i ];

  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p += FD_TXN_SIGNATURE_SZ;
  t->transaction_version = FD_TXN_VLEGACY;
  t->signature_cnt = 1;
  t->signature_off = 0;
  t->message_off = FD_TXN_SIGNATURE_SZ;
  t->readonly_signed_cnt = 0;
  ulong programs_to_include = 2UL; /* 1 for compute budget, 1 for "work" program */
  t->readonly_unsigned_cnt = (uchar)(strlen( reads ) + programs_to_include);
  t->acct_addr_cnt = (ushort)(1UL + strlen( reads ) + programs_to_include + strlen( writes ));

  t->acct_addr_off = FD_TXN_SIGNATURE_SZ;

  /* Add the signer */
  *p = 's' + 0x80; fd_memcpy( p+1, &i, sizeof(ulong) ); memset( p+9, 'S', 32-9 ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the writable accounts */
  for( ulong i = 0UL; writes[i] != '\0'; i++ ) {
    memset( p, writes[i], FD_TXN_ACCT_ADDR_SZ );
    p += FD_TXN_ACCT_ADDR_SZ;
  }
  /* Add the compute budget */
  fd_memcpy( p, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the work program */
  fd_memcpy( p, WORK_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;
  /* Add the readonly accounts */
  for( ulong i = 0UL; reads[i] != '\0'; i++ ) {
    memset( p, reads[i], FD_TXN_ACCT_ADDR_SZ );
    p += FD_TXN_ACCT_ADDR_SZ;
  }

  t->recent_blockhash_off = 0;
  t->addr_table_lookup_cnt = 0;
  t->addr_table_adtl_writable_cnt = 0;
  t->addr_table_adtl_cnt = 0;
  t->instr_cnt = (ushort)(1UL + (ulong)fd_uint_popcnt( compute ));

  uchar prog_start = (uchar)(1UL+strlen( writes ));

  t->instr[ 0 ].program_id = prog_start;
  t->instr[ 0 ].acct_cnt = 0;
  t->instr[ 0 ].data_sz = 9;
  t->instr[ 0 ].acct_off = (ushort)(p - p_base);
  t->instr[ 0 ].data_off = (ushort)(p - p_base);


  /* Write instruction data */
  uint rewards = (uint) pow( 5.0, priority );
  *p = '\0'; fd_memcpy( p+1, &compute, sizeof(uint) ); fd_memcpy( p+5, &rewards, sizeof(uint) );
  p += 9UL;

  ulong j = 1UL;
  for( uint i = 0U; i<32U; i++ ) {
    if( compute & (1U << i) ) {
      *p = (uchar)i;
      t->instr[ j ].program_id = (uchar)(prog_start + 1);
      t->instr[ j ].acct_cnt = 0;
      t->instr[ j ].data_sz = 1;
      t->instr[ j ].acct_off = (ushort)(p - p_base);
      t->instr[ j ].data_off = (ushort)(p - p_base);
      j++;
      p++;
    }
  }

  payload_sz[ i ] = (ulong)(p-p_base);
}

void insert_and_schedule( ulong i, pack_state * state ) {
  ulong        slot_chunk = freelist_pop_head( state->freelist );
  fd_txn_p_t * slot       = fd_chunk_to_laddr( state->dcache_base, slot_chunk );
  fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ i ];
  fd_memcpy( slot->payload, payload_scratch[ i ], payload_sz[ i ] );
  fd_memcpy( TXN(slot),     txn,     fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

  fd_pack_insert_transaction( slot_chunk, state->dcache_base, 0UL, state->cu_limit, rng, state->cu_est_tbl, state->txnq, state->freelist );

  fd_pack_schedule_return_t result;
  do {
    result = fd_pack_schedule_transaction( state->bank_cnt, state->cu_limit, state->bank_status,
        state->last_scheduled, state->txnq, state->outq, state->r_accts_in_use, state->w_accts_in_use,
        state->freelist, state->dcache_base, state->mcache, &state->seq, txnq_max( state->txnq) );
#if DETAILED_STATUS_MESSAGES
    if     ( result.status==FD_PACK_SCHEDULE_RETVAL_BANKDONE )
      FD_LOG_NOTICE(( "Banking thread %hhu done", result.banking_thread ));
    else if( result.status==FD_PACK_SCHEDULE_RETVAL_STALLING )
      FD_LOG_NOTICE(( "Banking thread %hhu stalling %u.", result.banking_thread, result.stall_duration ));
    else
      FD_LOG_NOTICE(( "Transaction scheduled to banking thread %hhu at time %u", result.banking_thread, result.start_time ));
#endif
  } while( result.status==FD_PACK_SCHEDULE_RETVAL_STALLING );
}
#define SET_NAME aset
#include "../../util/tmpl/fd_smallset.c"

#define MAX_BANKING_THREADS 64
ulong in_use_until[ MAX_BANKING_THREADS ];
aset_t  r_accts_in_use[ MAX_BANKING_THREADS ];
aset_t  w_accts_in_use[ MAX_BANKING_THREADS ];
void validate_all( ulong max_end, ulong min_rewards, ulong min_txns, ulong start_sequence, int end_block, pack_state * state ) {
  if( end_block )
    fd_pack_next_block( state->bank_cnt, state->bank_status, state->last_scheduled,
        state->r_accts_in_use, state->w_accts_in_use, state->outq, state->mcache,
        &(state->seq), txnq_max( state->txnq ), state->freelist );
  for( ulong i=0UL; i<state->bank_cnt; i++ ) {
    in_use_until[ i ] = 0UL;
    r_accts_in_use[ i ] = aset_null( );
    w_accts_in_use[ i ] = aset_null( );
  }
  ulong total_rewards = 0UL;
  ulong txn_cnt = 0UL;

  ulong read_seq = start_sequence;
  fd_frag_meta_t const * mline = state->mcache + fd_mcache_line_idx( read_seq, state->mcache_depth );
  ulong last_start = 0UL;
  for(;;) {
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, read_seq );
    if( FD_UNLIKELY( diff ) ) break;
    fd_txn_p_t * txnp = fd_chunk_to_laddr( state->dcache_base, mline->chunk );
    fd_txn_t   * txn  = TXN(txnp);

    fd_compute_budget_program_state_t cbp;
    fd_compute_budget_program_init( &cbp );
    fd_txn_instr_t ix = txn->instr[0]; /* For these transactions, the compute budget instr is always the 1st */
    FD_TEST( fd_compute_budget_program_parse( txnp->payload + ix.data_off, ix.data_sz, &cbp ) );
    ulong rewards = 0UL;
    uint compute = 0U;
    fd_compute_budget_program_finalize( &cbp, txn->instr_cnt, &rewards, &compute );
    ulong start_time = mline->sig & UINT_MAX;
    ulong end_time = start_time + compute;
    ulong banking_thread = mline->sig >> 32;

    FD_TEST( banking_thread<state->bank_cnt );
    FD_TEST( start_time>=last_start         ); /* Check the ordering on the mcache */
    FD_TEST( end_time <= max_end            );
    aset_t  read_accts = aset_null( );
    aset_t write_accts = aset_null( );

    for( ulong j=(ulong)(txn->signature_cnt); j<((ulong)(txn->acct_addr_cnt)-(ulong)(txn->readonly_unsigned_cnt)); j++ ) {
      uchar * acct_addr = txnp->payload + txn->acct_addr_off + j*FD_TXN_ACCT_ADDR_SZ; 
      if( (0x30UL<=*acct_addr) & (*acct_addr<0x70UL) & ((*acct_addr)==*(acct_addr+1UL)) ) 
        write_accts = aset_insert( write_accts, (ulong)*acct_addr-0x30UL );
    }
    for( ulong j=((ulong)(txn->acct_addr_cnt)-(ulong)(txn->readonly_unsigned_cnt)); j<((ulong)(txn->acct_addr_cnt)); j++ ) {
      uchar * acct_addr = txnp->payload + txn->acct_addr_off + j*FD_TXN_ACCT_ADDR_SZ; 
      if( (0x30UL<=*acct_addr) & (*acct_addr<0x70UL) & ((*acct_addr)==*(acct_addr+1UL)) ) 
        read_accts = aset_insert( read_accts, (ulong)*acct_addr-0x30UL );
    }

    for( ulong i=0UL; i<state->bank_cnt; i++ ) {
      if( (i==banking_thread) || (in_use_until[i]<=start_time) ) continue; /* Doesn't overlap in time */
      FD_TEST( aset_is_null( aset_intersect( write_accts, r_accts_in_use[ i ] ) ) );
      FD_TEST( aset_is_null( aset_intersect( write_accts, w_accts_in_use[ i ] ) ) );
      FD_TEST( aset_is_null( aset_intersect( read_accts,  w_accts_in_use[ i ] ) ) );
    }
    r_accts_in_use[ banking_thread ] =  read_accts;
    w_accts_in_use[ banking_thread ] = write_accts;
    in_use_until[   banking_thread ] =    end_time;
    last_start = start_time;
    total_rewards += rewards;
    txn_cnt++;

    read_seq = fd_seq_inc( read_seq, 1UL );
    mline = state->mcache + fd_mcache_line_idx( read_seq, state->mcache_depth );
  }
  FD_TEST( total_rewards >= min_rewards );
  FD_TEST( txn_cnt >= min_txns );
}

void test0( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST 0" ));
  init_all( 4UL, 128UL, 512UL, 10000UL, &state );
  ulong read_seq = state.seq;
  ulong i = 0;
  make_transaction( i,  500U, 11.0, "A", "B" );    insert_and_schedule( i++, &state );
  make_transaction( i,  500U, 10.0, "C", "D" );    insert_and_schedule( i++, &state );
  make_transaction( i,  800U, 10.0, "EFGH", "D" ); insert_and_schedule( i++, &state );
  validate_all(  800UL, 0UL, 3UL, read_seq, 0, &state );
  make_transaction( i,  500U, 10.0, "D", "I" );    insert_and_schedule( i++, &state );
  /* This last transaction can't start until 800, but it's possible another
     independent transaction could start on banking thread 0 or 1 at 500, so it
     stays in the outq.  Force it to be emitted by ending the block. */
  validate_all( 1300UL, 0UL, 4UL, read_seq, 1, &state );
}

/* The original two that broke my first algorithm */
void test1( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST 1" ));
  init_all( 2UL, 128UL, 512UL, 10000UL, &state );
  ulong i = 0;
  ulong read_seq = state.seq;
  make_transaction( i,  500U, 11.0, "A", "B" ); insert_and_schedule( i++, &state );
  make_transaction( i,  500U, 10.0, "B", "A" ); insert_and_schedule( i++, &state );
  validate_all( 1000UL, 0UL, 2UL, read_seq, 1, &state );
}

void test2( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST 2" ));
  init_all( 4UL, 128UL, 512UL, 10000UL, &state );
  ulong i = 0;
  ulong read_seq = state.seq;
  double j = 13.0;
  make_transaction( i,  500U, j--, "B", "A" ); insert_and_schedule( i++, &state );
  make_transaction( i,  500U, j--, "C", "B" ); insert_and_schedule( i++, &state );
  make_transaction( i,  500U, j--, "D", "C" ); insert_and_schedule( i++, &state );
  make_transaction( i,  500U, j--, "A", "D" ); insert_and_schedule( i++, &state );

  /* A smart scheduler that allows read bypass could schedule the first 3 at
   * the same time then #4 after they all finish. */
  validate_all( 2000UL, 0UL, 4UL, read_seq, 1, &state );
}

void performance_test( void ) {
  pack_state state;
  ulong i = 0UL;
  FD_LOG_NOTICE(( "TEST PERFORMANCE" ));
  init_all( 4UL, 1024UL, 512UL, 1000000UL, &state );
  make_transaction( i,   800U, 12.0, "ABC", "DEF" );
  make_transaction( i+1, 500U, 12.0, "GHJ", "KLMNOP" );

  long start = fd_log_wallclock( );
  for( ulong j=0UL; j<1024UL; j++ ) {
    ulong        slot_chunk = freelist_pop_head( state.freelist );
    fd_txn_p_t * slot       = fd_chunk_to_laddr( state.dcache_base, slot_chunk );
    fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ j&1 ];
    fd_memcpy( slot->payload, payload_scratch[ j&1 ], payload_sz[ j&1 ]                                              );
    fd_memcpy( TXN(slot),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

    fd_pack_insert_transaction( slot_chunk, state.dcache_base, 0UL, state.cu_limit, rng, state.cu_est_tbl, state.txnq, state.freelist );
  }
  long end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "Inserting: %f ns", ((double)(end-start))/1024.0 ));
  start = fd_log_wallclock( );
  ulong seq = 0UL;
  for( ulong j=0UL; j<1024UL; j++ ) {
    fd_pack_schedule_transaction( state.bank_cnt, state.cu_limit, state.bank_status,
        state.last_scheduled, state.txnq, state.outq, state.r_accts_in_use, state.w_accts_in_use,
        state.freelist, state.dcache_base, state.mcache, &seq, txnq_max( state.txnq ) );
  }
  end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "Scheduling: %f ns", ((double)(end-start))/1024.0 ));
}

void twogroup_test( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST TWO TRANSACTIONS" ));
  init_all( 2UL, 1024UL, 512UL, 1000000UL, &state );
  ulong read_seq = state.seq;
  /* Weight the transactions so they are approximately equal.  Ideally it will
     schedule 5 copies of transaction 0 on one thread and 8 copies of
     transaction 1 on the other thread.  Transaction 0 has slightly better
     priority than transaction 1, which means that searching the first 7 in the
     heap should include at least one copy of transaction 1 (since there are
     only 5 copies of transaction 0). */
  make_transaction( 0UL, 800U, 10.293, "ABC", "DEF" );
  make_transaction( 1UL, 500U, 10.0, "GHJ", "KLMNOP" );
  const ulong reps = 1UL;

  for( ulong j=0UL; j<13UL*reps; j++ ) {
    ulong        slot_chunk = freelist_pop_head( state.freelist );
    fd_txn_p_t * slot       = fd_chunk_to_laddr( state.dcache_base, slot_chunk );
    int idx = (j%13)>=5; /* [0, 4] -> 0, [5, 12] -> 1 */
    fd_txn_t * txn = (fd_txn_t*) txn_scratch[ idx ];
    fd_memcpy( slot->payload, payload_scratch[ idx ], payload_sz[ idx ]                                              );
    fd_memcpy( TXN(slot),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

    fd_pack_insert_transaction( slot_chunk, state.dcache_base, 0UL, state.cu_limit, rng, state.cu_est_tbl, state.txnq, state.freelist );
  }
  uint last_start = 0U;
  for( ulong j=0UL; j<13UL*reps; j++ ) {
    fd_pack_schedule_return_t result = fd_pack_schedule_transaction( state.bank_cnt, state.cu_limit, state.bank_status,
        state.last_scheduled, state.txnq, state.outq, state.r_accts_in_use, state.w_accts_in_use,
        state.freelist, state.dcache_base, state.mcache, &(state.seq), txnq_max( state.txnq ) );
    FD_TEST( result.status==FD_PACK_SCHEDULE_RETVAL_SCHEDULED );
    last_start = fd_uint_max( last_start, result.start_time );
  }
  validate_all( 4000U*reps, 0, 13UL*reps, read_seq, 1, &state );
  FD_TEST( last_start < 4000U*reps );
}

void heap_overflow_test( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST HEAP OVERFLOW" ));
  init_all( 1UL, 1024UL, 512UL, 1000000UL, &state );
  /* Insert a bunch of low-paying transactions */
  make_transaction( 0UL, 800U, 4.0, "ABC", "DEF" );
  for( ulong j=0UL; j<1024UL; j++ ) {
    ulong        slot_chunk = freelist_pop_head( state.freelist );
    fd_txn_p_t * slot       = fd_chunk_to_laddr( state.dcache_base, slot_chunk );
    fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ 0UL ];
    fd_memcpy( slot->payload, payload_scratch[ 0UL ], payload_sz[ 0UL ]                                              );
    fd_memcpy( TXN(slot),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

    fd_pack_insert_transaction( slot_chunk, state.dcache_base, 0UL, state.cu_limit, rng, state.cu_est_tbl, state.txnq, state.freelist );
  }
  FD_TEST( freelist_cnt( state.freelist ) >= 1024UL );

  /* Now insert higher-paying transactions. They should mostly take the place
     of the low-paying transactions, with only a small amount of stochasticity
     (when the heap is mostly high-paying transactions, we might not kick out
     one of the last few low-paying transactions). */
  make_transaction( 1UL, 500U, 10.0, "GHJ", "KLMNOP" );
  for( ulong j=0UL; j<1024UL; j++ ) {
    ulong        slot_chunk = freelist_pop_head( state.freelist );
    fd_txn_p_t * slot       = fd_chunk_to_laddr( state.dcache_base, slot_chunk );
    fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ 1UL ];
    fd_memcpy( slot->payload, payload_scratch[ 1UL ], payload_sz[ 1UL ]                                              );
    fd_memcpy( TXN(slot),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

    fd_pack_insert_transaction( slot_chunk, state.dcache_base, 0UL, state.cu_limit, rng, state.cu_est_tbl, state.txnq, state.freelist );
  }
  FD_TEST( freelist_cnt( state.freelist ) >= 1024UL );

  ulong read_seq = state.seq;
  for( ulong j=0UL; j<1024UL; j++ ) {
    fd_pack_schedule_return_t result = fd_pack_schedule_transaction( state.bank_cnt, state.cu_limit, state.bank_status,
        state.last_scheduled, state.txnq, state.outq, state.r_accts_in_use, state.w_accts_in_use,
        state.freelist, state.dcache_base, state.mcache, &state.seq, txnq_max( state.txnq ) );
    FD_TEST( result.status==FD_PACK_SCHEDULE_RETVAL_SCHEDULED );
  }
  /* Examine what was scheduled */
  ulong low_cnt = 0UL; ulong high_cnt = 0UL;
#if DETAILED_STATUS_MESSAGES
  FD_LOG_NOTICE(( "Write seq: %lu, read seq: %lu", state.seq, read_seq ));
#endif
  fd_frag_meta_t const * mline = state.mcache + fd_mcache_line_idx( read_seq, state.mcache_depth );
  for(;;) {
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, read_seq );
    if( FD_UNLIKELY( diff ) ) break;
    uchar * txnp = fd_chunk_to_laddr( state.dcache_base, mline->chunk );
    /* txnp is a txn_p_t.  The first member is the payload.  With these
       hacked-up transaction payloads, the first byte is the start of the
       signature, and the first 8B of the signature is the transaction ID, i.e.
       the first argument to make_transaction. */
    if(      *(ulong*)txnp == 0U ) low_cnt++;
    else if( *(ulong*)txnp == 1U ) high_cnt++;
    else FD_TEST( 0 );

    read_seq = fd_seq_inc( read_seq, 1UL );
    mline = state.mcache + fd_mcache_line_idx( read_seq, state.mcache_depth );
  }

  FD_LOG_NOTICE(( "Scheduled %lu high-paying and %lu low-paying", high_cnt, low_cnt ));
  FD_TEST( low_cnt+high_cnt==1024UL );
  FD_TEST( high_cnt>=512UL );
}

void test_read_shadow( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST RS" ));
  init_all( 6UL, 128UL, 512UL, 10000UL, &state );
  ulong read_seq = state.seq;
  ulong i = 0;
  double j = 13.0;
  /* 0       5      10    15    ( x100, not to scale)
     [ B / A ]
             [ BA / ]
     [C/A]
     [ D / A ]   (fits in the read shadow)
                    [  E / A  ]  (doesn't fit in the read shadow) */
  make_transaction( i,  500U, j--, "B", "A" ); insert_and_schedule( i++, &state ); 
  make_transaction( i,  500U, j--, "BA", "" ); insert_and_schedule( i++, &state ); 
  make_transaction( i,  300U, j--, "C", "A" ); insert_and_schedule( i++, &state );
  make_transaction( i,  500U, j--, "D", "A" ); insert_and_schedule( i++, &state );
  validate_all(  500UL, 0UL, 3UL, read_seq, 0, &state ); /* i==1 is in outq */
  make_transaction( i,  800U, j--, "E", "A" ); insert_and_schedule( i++, &state );
  validate_all( 1800UL, 0UL, 5UL, read_seq, 1, &state );
}

void test_delayed_output( void ) {
  pack_state state;
  FD_LOG_NOTICE(( "TEST DELAYED OUTPUT" ));
  init_all( 4UL, 128UL, 512UL, 10000UL, &state );
  ulong read_seq = state.seq;
  ulong i = 0;
  double j = 13.0;
  make_transaction( i,  500U, j--, "B", "A" ); insert_and_schedule( i++, &state ); /* sched at 0 */
  FD_TEST( 0UL == outq_cnt( state.outq ) );
  make_transaction( i,  500U, j--, "BA", "" ); insert_and_schedule( i++, &state ); /* sched at 5 */
  FD_TEST( 1UL == outq_cnt( state.outq ) );
  make_transaction( i,  200U, j--, "D",  "" ); insert_and_schedule( i++, &state ); /* sched at 0 */
  FD_TEST( 1UL == outq_cnt( state.outq ) );
  make_transaction( i,  200U, j--, "D",  "" ); insert_and_schedule( i++, &state ); /* sched at 2 */
  FD_TEST( 2UL == outq_cnt( state.outq ) );

  validate_all( 1000UL, 0UL, 4UL, read_seq, 1, &state );
  FD_TEST( 0UL == outq_cnt( state.outq ) );

  const ulong correct_order[4] = { 0UL, 2UL, 3UL, 1UL };
  fd_frag_meta_t const * mline = state.mcache + fd_mcache_line_idx( read_seq, state.mcache_depth );
  for( ulong j=0UL; j<4UL; j++ ) {
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, read_seq );
    FD_TEST( !diff );
    uchar * txnp = fd_chunk_to_laddr( state.dcache_base, mline->chunk );

    FD_TEST( *(ulong*)txnp == correct_order[ j ] );

    read_seq = fd_seq_inc( read_seq, 1UL );
    mline = state.mcache + fd_mcache_line_idx( read_seq, state.mcache_depth );
  }
  ulong seq_found = fd_frag_meta_seq_query( mline );
  long  diff      = fd_seq_diff( seq_found, read_seq );
  FD_TEST( diff ); /* Assert done */
}
struct flat_status {
  uint       in_use_until;
  float      in_use_until_var;
};
typedef struct flat_status flat_status_t;

struct heap_status {
  uint       in_use_until;
  float      in_use_until_var;
  uchar      t;
};
typedef struct heap_status heap_status_t;

#define PRQ_NAME heap
#define PRQ_T    heap_status_t
#define PRQ_TIMEOUT_T uint
#define PRQ_TIMEOUT   in_use_until
#include "../../util/tmpl/fd_prq.c"

flat_status_t flat[256];
uchar _heap[8192] __attribute__((aligned(8)));
void _flat_vs_heap( ulong bank_cnt ) {

  uint cu_limit = 1000000U;
  const ulong test_count = bank_cnt>=200UL ? 300UL : 1000UL;
  flat_status_t * bank_status = flat;
  fd_rng_idx_set( rng, 7UL );
  ulong flat_duration = 0UL;
  ulong sum1 = 0UL;
  for( ulong z=0UL; z<test_count; z++ ) {
    for( ulong j=0UL; j<bank_cnt; j++ ) {
      flat[j].in_use_until = 0U;
      flat[j].in_use_until_var = 0UL;
    }
    long start = fd_log_wallclock( );
    while( 1 ) {
      ulong t = bank_cnt;
      uint  t_score = cu_limit;
      for( ulong i = 0; i<bank_cnt; i++ ) {
        t = fd_ulong_if( bank_status[ i ].in_use_until<t_score, i, t );
        t_score = fd_uint_min( bank_status[ i ].in_use_until, t_score );
      }
      if( FD_UNLIKELY( t==bank_cnt ) ) {
        break;
      }
      uint v = fd_rng_ushort( rng ) % 2048U;
      if( FD_UNLIKELY( bank_status[ t ].in_use_until + v >= cu_limit ) ) bank_status[ t ].in_use_until = cu_limit;
      else {
        sum1 += bank_status[ t ].in_use_until;
        bank_status[ t ].in_use_until += v;
        bank_status[ t ].in_use_until_var += (float)((v*v)>>2);
      }
    }
    long end = fd_log_wallclock( );
    flat_duration += (ulong)(end - start);
  }

  fd_rng_idx_set( rng, 7UL );
  ulong heap_duration = 0UL;
  ulong sum2 = 0UL;
  FD_TEST( heap_footprint( bank_cnt ) <= 8192 );
  for( ulong z=0UL; z<test_count; z++ ) {
    heap_status_t * q = heap_join( heap_new( _heap, bank_cnt ) );
    for( ulong j=0UL; j<bank_cnt; j++ ) {
      heap_status_t insert = { .in_use_until = 0, .in_use_until_var = 0, .t = (uchar)j };
      heap_insert( q, &insert );
    }
    long start = fd_log_wallclock( );
    while( 1 ) {
      if( FD_UNLIKELY( heap_cnt( q ) == 0UL ) ) break;
      uint v = fd_rng_ushort( rng ) % 2048U;
      if( FD_UNLIKELY( q[ 0 ].in_use_until + v >= cu_limit ) ) heap_remove_min( q );
      else {
        heap_status_t insert = q[ 0 ];
        heap_remove_min( q );
        sum2 += insert.in_use_until;
        insert.in_use_until += v;
        insert.in_use_until_var += (float)((v*v)>>2);
        heap_insert( q, &insert );
      }
    }
    long end = fd_log_wallclock( );
    heap_duration += (ulong)(end - start);
    heap_delete( heap_leave( q ) );
  }
  FD_LOG_NOTICE(( "%lu, %f, %f", bank_cnt, (double)(flat_duration)/(double)test_count, (double)(heap_duration)/(double)test_count ));
  FD_TEST( sum1==sum2 );
}

void flat_vs_heap( void ) {
  _flat_vs_heap(   2UL );
  _flat_vs_heap(   4UL );
  _flat_vs_heap(   8UL );
  _flat_vs_heap(  10UL );
  _flat_vs_heap(  16UL );
  _flat_vs_heap(  32UL );
  _flat_vs_heap(  48UL );
  _flat_vs_heap(  64UL );
  _flat_vs_heap( 128UL );
  _flat_vs_heap( 200UL );
  _flat_vs_heap( 254UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test0();
  test1();
  test2();
  twogroup_test();
  performance_test();
  test_read_shadow();
  heap_overflow_test();
  // flat_vs_heap();
  test_delayed_output();
  /* TODO: Test a mix of transactions */
  /* TODO: Test transactions that all write the same account */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
