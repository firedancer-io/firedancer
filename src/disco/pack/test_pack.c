#include "../../ballet/fd_ballet.h"
#include "fd_pack.h"
#include "fd_pack_cost.h"
#include "fd_compute_budget_program.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../disco/metrics/fd_metrics.h"
#include <math.h>

#if FD_USING_GCC && __GNUC__ >= 15
#pragma GCC diagnostic ignored "-Wunterminated-string-initialization"
#endif

FD_IMPORT_BINARY( sample_vote, "src/disco/pack/sample_vote.bin" );

#define FD_PACK_TEST_MAX_COST_PER_BLOCK 48000000
#define FD_PACK_TEST_MAX_VOTE_COST_PER_BLOCK 36000000
#define FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT 12000000

#define MAX_TEST_TXNS (1024UL)
#define MAX_DATA_PER_BLOCK (5UL*1024UL*1024UL)
fd_txn_p_t txnp_scratch[ MAX_TEST_TXNS ];

/* Dense packing of txnp_scratch for performance */
#define DUMMY_PAYLOAD_MAX_SZ (FD_TXN_ACCT_ADDR_SZ * 256UL + 64UL)
uchar txn_scratch[ MAX_TEST_TXNS ][ FD_TXN_MAX_SZ ];
uchar payload_scratch[ MAX_TEST_TXNS ][ DUMMY_PAYLOAD_MAX_SZ ];
ulong payload_sz[ MAX_TEST_TXNS ];

#define PACK_SCRATCH_SZ (400UL*1024UL*1024UL)
uchar pack_scratch[ PACK_SCRATCH_SZ ] __attribute__((aligned(128)));
uchar pack_verify_scratch[ PACK_SCRATCH_SZ ] __attribute__((aligned(128)));

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

const char SIGNATURE_SUFFIX[ FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint) ] = ": this is the fake signature of transaction number ";
const char WORK_PROGRAM_ID[ FD_TXN_ACCT_ADDR_SZ ] = "Work Program Id Consumes 1<<j CU";

fd_rng_t _rng[1];
fd_rng_t * rng;
int extra_verify;

#define SET_NAME aset
#include "../../util/tmpl/fd_smallset.c"

#define ALL (FD_PACK_SCHEDULE_VOTE | FD_PACK_SCHEDULE_BUNDLE | FD_PACK_SCHEDULE_TXN)

struct pack_outcome {
  ulong microblock_cnt;
  aset_t  r_accts_in_use[ FD_PACK_MAX_BANK_TILES ];
  aset_t  w_accts_in_use[ FD_PACK_MAX_BANK_TILES ];
  fd_txn_p_t results[1024];
};
typedef struct pack_outcome pack_outcome_t;

pack_outcome_t outcome;


static fd_pack_t *
init_all( ulong pack_depth,
          ulong bank_tile_cnt,
          ulong max_txn_per_microblock,
          pack_outcome_t * outcome     ) {
  fd_pack_limits_t limits[1] = { {
    .max_cost_per_block        = FD_PACK_TEST_MAX_COST_PER_BLOCK,
    .max_vote_cost_per_block   = FD_PACK_TEST_MAX_VOTE_COST_PER_BLOCK,
    .max_write_cost_per_acct   = FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT,
    .max_data_bytes_per_block  = MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = max_txn_per_microblock,
    .max_microblocks_per_block = MAX_TEST_TXNS,
  } };
  ulong footprint = fd_pack_footprint( pack_depth, 1UL, bank_tile_cnt, limits );

  if( footprint>PACK_SCRATCH_SZ ) FD_LOG_ERR(( "Test required %lu bytes, but scratch was only %lu", footprint, PACK_SCRATCH_SZ ));
#if DETAILED_STATUS_MESSAGES
  else                         FD_LOG_NOTICE(( "Test required %lu bytes of %lu available bytes",    footprint, PACK_SCRATCH_SZ ));
#endif

  fd_pack_t * pack = fd_pack_join( fd_pack_new( pack_scratch, pack_depth, 1UL, bank_tile_cnt, limits, rng ) );
#define MAX_BANKING_THREADS 64

  outcome->microblock_cnt = 0UL;
  for( ulong i=0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    outcome->r_accts_in_use[ i ] = aset_null( );
    outcome->w_accts_in_use[ i ] = aset_null( );
  }

  return pack;
}


/* Makes enough of a transaction to schedule that reads one account for
   each character in reads and writes one account for each character in
   writes.  The characters before the nul-terminator in reads and writes
   should be in [0x30, 0x70), basically numbers and uppercase letters.
   Adds a unique signer.  A computeBudgetInstruction will be included
   with compute requested cus and another instruction will be added
   requesting loaded_data_sz bytes of accounts data.  Fee will be set to
   5^priority, so that even with a large stall, it should still schedule
   in decreasing priority order.  priority should be in (0, 13.5].
   Stores the created transaction in txn_scratch[ i ] and
   payload_scratch[ i ].  If priority_fees is non-null, it will contain
   the priority fee in lamports. If pack_cost_estimate is non-null, it
   will contain the cost estimate used by pack when packing blocks. */
static void
make_transaction1( fd_txn_p_t * txnp,
                   ulong        i,
                   uint         compute,
                   uint         loaded_data_sz,
                   double       priority,
                   char const * writes,
                   char const * reads,
                   ulong *      priority_fees,
                   ulong *      pack_cost_estimate ) {
  uchar * p = txnp->payload;
  uchar * p_base = p;
  fd_txn_t * t = TXN( txnp );

  *(p++) = (uchar)1;
  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p += FD_TXN_SIGNATURE_SZ;
  t->transaction_version = FD_TXN_VLEGACY;
  t->signature_cnt = 1;
  t->signature_off = 1;
  t->message_off = FD_TXN_SIGNATURE_SZ+1UL;
  t->readonly_signed_cnt = 0;
  ulong programs_to_include = 2UL; /* 1 for compute budget, 1 for "work" program */
  t->readonly_unsigned_cnt = (uchar)(strlen( reads ) + programs_to_include);
  t->acct_addr_cnt = (ushort)(1UL + strlen( reads ) + programs_to_include + strlen( writes ));

  t->acct_addr_off = FD_TXN_SIGNATURE_SZ+1UL;

  /* Add the signer */
  *p = 's' + 0x80; fd_memcpy( p+1, &i, sizeof(ulong) ); memset( p+9, 'S', FD_TXN_ACCT_ADDR_SZ-9 ); p += FD_TXN_ACCT_ADDR_SZ;
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
  t->instr_cnt = (ushort)(3UL + (ulong)fd_uint_popcnt( compute ));

  uchar prog_start = (uchar)(1UL+strlen( writes ));

  t->instr[ 0 ].program_id = prog_start;
  t->instr[ 0 ].acct_cnt = 0;
  t->instr[ 0 ].data_sz = 5;
  t->instr[ 0 ].acct_off = (ushort)(p - p_base);
  t->instr[ 0 ].data_off = (ushort)(p - p_base);

  /* Write instruction data */
  *p = 2; fd_memcpy( p+1, &compute, sizeof(uint) );
  p += 5UL;

  t->instr[ 1 ].program_id = prog_start;
  t->instr[ 1 ].acct_cnt = 0;
  t->instr[ 1 ].data_sz = 9;
  t->instr[ 1 ].acct_off = (ushort)(p - p_base);
  t->instr[ 1 ].data_off = (ushort)(p - p_base);

  /* 3 corresponds to SetComputeUnitPrice */
  ulong rewards_per_cu = (ulong) (pow( 5.0, priority )*10000.0 / (double)compute);
  *p = 3; fd_memcpy( p+1, &rewards_per_cu, sizeof(ulong) );
  p += 9UL;

  t->instr[ 2 ].program_id = prog_start;
  t->instr[ 2 ].acct_cnt = 0;
  t->instr[ 2 ].data_sz = 5;
  t->instr[ 2 ].acct_off = (ushort)(p - p_base);
  t->instr[ 2 ].data_off = (ushort)(p - p_base);

  /* 4 corresponds to SetLoadedAccountsDataSizeLimit */
  *p = 4; fd_memcpy( p+1, &loaded_data_sz, sizeof(uint) );
  p += 5UL;

  ulong j = 3UL;
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

  txnp->payload_sz = (ulong)(p-p_base);
  uint flags;
  fd_ulong_store_if( !!priority_fees, priority_fees, (rewards_per_cu * compute + 999999UL)/1000000UL );
  fd_ulong_store_if( !!pack_cost_estimate, pack_cost_estimate, fd_pack_compute_cost( TXN( txnp ), txnp->payload, &flags, NULL, NULL, NULL, NULL) );
}

static void
make_transaction( ulong        i,
                  uint         compute,
                  uint         loaded_data_sz,
                  double       priority,
                  char const * writes,
                  char const * reads,
                  ulong *      priority_fees,
                  ulong *      pack_cost_estimate ) {
  make_transaction1( &txnp_scratch[ i ], i, compute, loaded_data_sz, priority, writes, reads, priority_fees, pack_cost_estimate );
}

static void
make_vote_transaction1( fd_txn_p_t * txnp,
                        ulong        i ) {
  uchar * p = txnp->payload;
  fd_memcpy( p, sample_vote, sample_vote_sz );
  txnp->payload_sz = sample_vote_sz;

  /* Make signature and the two writable accounts unique */
  p[ 0x01+(i%8) ] = (uchar)(p[ 0x01+(i%8) ] + 1UL + (i/8));
  p[ 0x45+(i%8) ] = (uchar)(p[ 0x45+(i%8) ] + 1UL + (i/8));
  p[ 0x65+(i%8) ] = (uchar)(p[ 0x65+(i%8) ] + 1UL + (i/8));
  FD_TEST( fd_txn_parse( p, sample_vote_sz, TXN( txnp ), NULL ) );
}

static void
make_vote_transaction( ulong i ) {
  make_vote_transaction1( &txnp_scratch[ i ], i );
}

/* Makes enough of a durable nonce transaction to be scheduleable.
   nonce_acct_idx and nonce_auth_idx are in [0, 8).  Accounts 0 and 1
   are writable signers, accounts 2 and 3 are readonly signers, 4 and 5
   are writable non-signers, and 6 and 7 are readonly nonsigners.  The
   recent blockhash is a 32-byte repetition of the specified character.
   i and priority are as in make_transaction. */
static void
make_nonce_transaction1( fd_txn_p_t * txnp,
                         ulong        i,
                         double       priority,
                         uchar        nonce_acct_idx,
                         uchar        nonce_auth_idx,
                         char         recent_blockhash ) {
  uchar * p = txnp->payload;
  uchar * p_base = p;
  fd_txn_t * t = TXN( txnp );

  uint loaded_data_sz = 10000U;
  uint compute        = 10001U;

  *(p++) = (uchar)2;
  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p += FD_TXN_SIGNATURE_SZ;

  fd_memset( p, 'b', 64UL );
  p += FD_TXN_SIGNATURE_SZ;

  t->transaction_version = FD_TXN_VLEGACY;
  t->signature_cnt = 2;
  t->signature_off = 1;
  t->message_off = 2*FD_TXN_SIGNATURE_SZ+1UL;
  t->readonly_signed_cnt = 1;
  t->readonly_unsigned_cnt = 5; /* 2 + compute budget, system program, recent blockhashes */
  t->acct_addr_cnt = 11;


  /* Add the recent blockhash */
  t->recent_blockhash_off = (ushort)(p - p_base);
  fd_memset( p, recent_blockhash, 32UL );         p += 32UL;

  t->acct_addr_off = (ushort)(p - p_base);
  for( ulong i=0UL; i<8UL; i++ ) { fd_memset( p, (char)('c' + i), FD_TXN_ACCT_ADDR_SZ ); p+=FD_TXN_ACCT_ADDR_SZ; }

  static uchar const recent_blockhashes_sysvar[FD_TXN_ACCT_ADDR_SZ] = { SYSVAR_RECENT_BLKHASH_ID };

  fd_memcpy( p, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;
  fd_memset( p, '\0',                         FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ; /* system program */
  fd_memcpy( p, recent_blockhashes_sysvar,    FD_TXN_ACCT_ADDR_SZ ); p += FD_TXN_ACCT_ADDR_SZ;

  t->addr_table_lookup_cnt = 0;
  t->addr_table_adtl_writable_cnt = 0;
  t->addr_table_adtl_cnt = 0;
  t->instr_cnt = 4;

  uchar budget_prog_idx = 8;
  uchar system_prog_idx = 9;

  t->instr[ 0 ].program_id = system_prog_idx;
  t->instr[ 0 ].acct_cnt = 3;
  t->instr[ 0 ].data_sz = 4;
  t->instr[ 0 ].acct_off = (ushort)(p - p_base);
  *(p++) = nonce_acct_idx;
  *(p++) = 10;
  *(p++) = nonce_auth_idx;
  t->instr[ 0 ].data_off = (ushort)(p - p_base);
  FD_STORE( uint, p, 0x4U );  p += sizeof(uint);

  uchar * ptrs[3];
  for( ulong i=0UL; i<3UL; i++ ) {
    ushort data_sz = fd_ushort_if( i==1UL, 9, 5 );
    t->instr[ 1UL+i ].program_id = budget_prog_idx;
    t->instr[ 1UL+i ].acct_cnt = 0;
    t->instr[ 1UL+i ].data_sz = data_sz;
    t->instr[ 1UL+i ].acct_off = (ushort)(p - p_base);
    t->instr[ 1UL+i ].data_off = (ushort)(p - p_base);
    ptrs[i] = p;
    p += data_sz;
  }

  ulong rewards_per_cu = (ulong) (pow( 5.0, priority )*10000.0 / (double)compute);

  *(ptrs[0]) = 2; fd_memcpy( ptrs[0]+1, &compute,        sizeof(uint)  );
  *(ptrs[1]) = 3; fd_memcpy( ptrs[1]+1, &rewards_per_cu, sizeof(ulong) );
  *(ptrs[2]) = 4; fd_memcpy( ptrs[2]+1, &loaded_data_sz, sizeof(uint)  );

  txnp->payload_sz = (ulong)(p-p_base);
}

static void
make_nonce_transaction( ulong        i,
                        double       priority,
                        uchar        nonce_acct_idx,
                        uchar        nonce_auth_idx,
                        char         recent_blockhash ) {
  make_nonce_transaction1( &txnp_scratch[ i ], i, priority, nonce_acct_idx, nonce_auth_idx, recent_blockhash );
}

static int
insert1( fd_txn_p_t * txnp,
         ulong        i,
         fd_pack_t *  pack ) {
  fd_txn_e_t * slot = fd_pack_insert_txn_init( pack );
  memcpy( slot->txnp, txnp, sizeof(fd_txn_p_t) );
  ulong _deleted;
  return fd_pack_insert_txn_fini( pack, slot, i, &_deleted );
}

static int
insert( ulong       i,
        fd_pack_t * pack ) {
  return insert1( &txnp_scratch[ i ], i, pack );
}

static void
schedule_validate_microblock( fd_pack_t * pack,
                              ulong total_cus,
                              float vote_fraction,
                              ulong min_txns,
                              ulong min_rewards,
                              ulong bank_tile,
                              pack_outcome_t * outcome ) {

  ulong pre_txn_cnt  = fd_pack_avail_txn_cnt( pack );
  fd_pack_microblock_complete( pack, bank_tile );
  ulong txn_cnt = fd_pack_schedule_next_microblock( pack, total_cus, vote_fraction, bank_tile, ALL, outcome->results );
  ulong post_txn_cnt = fd_pack_avail_txn_cnt( pack );

#if DETAILED_STATUS_MESSAGES
  FD_LOG_NOTICE(( "Scheduling microblock. %lu avail -> %lu avail. %lu scheduled", pre_txn_cnt, post_txn_cnt, txn_cnt ));
#endif

  FD_TEST( txn_cnt >= min_txns );
  FD_TEST( pre_txn_cnt-post_txn_cnt == txn_cnt );

  ulong total_rewards = 0UL;

  aset_t  read_accts = aset_null( );
  aset_t write_accts = aset_null( );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txnp = outcome->results+i;
    fd_txn_t   * txn  = TXN(txnp);

    fd_compute_budget_program_state_t cbp;
    fd_compute_budget_program_init( &cbp );

    ulong rewards = 0UL;
    uint compute = 0U;
    ulong requested_loaded_accounts_data_cost = 0UL;
    uchar const * addresses = txnp->payload + txn->acct_addr_off;
    ulong non_builtin_cnt = 0UL;
    for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
      if( !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ ) ) {
        FD_TEST( fd_compute_budget_program_parse( txnp->payload + txn->instr[ i ].data_off, txn->instr[ i ].data_sz, &cbp ) );
      }

      int is_builtin =
            !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ VOTE_PROG_ID },            FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ SYS_PROG_ID },             FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ COMPUTE_BUDGET_PROG_ID },  FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ BPF_UPGRADEABLE_PROG_ID }, FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ BPF_LOADER_1_PROG_ID },    FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ BPF_LOADER_2_PROG_ID },    FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ LOADER_V4_PROG_ID },       FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ KECCAK_SECP_PROG_ID },     FD_TXN_ACCT_ADDR_SZ )
        ||  !memcmp( addresses+FD_TXN_ACCT_ADDR_SZ*txn->instr[ i ].program_id, (uchar[]){ ED25519_SV_PROG_ID },      FD_TXN_ACCT_ADDR_SZ );
      non_builtin_cnt += !is_builtin;
    }
    fd_compute_budget_program_finalize( &cbp, txn->instr_cnt, txn->instr_cnt-non_builtin_cnt, &rewards, &compute, &requested_loaded_accounts_data_cost );

    total_rewards += rewards;

    fd_acct_addr_t const * acct = fd_txn_get_acct_addrs( txn, txnp->payload );
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
      ulong j=fd_txn_acct_iter_idx( iter );
      uchar b0 = acct[j].b[0]; uchar b1 = acct[j].b[1];
      if( (0x30UL<=b0) & (b0<0x70UL) & (b0==b1) ) {
        FD_TEST( !aset_test( write_accts, (ulong)b0-0x30 ) );
        write_accts = aset_insert( write_accts, (ulong)b0-0x30UL );
      }
    }
    for( fd_txn_acct_iter_t iter=fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM );
        iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
      ulong j=fd_txn_acct_iter_idx( iter );
      uchar b0 = acct[j].b[0]; uchar b1 = acct[j].b[1];
      if( (0x30UL<=b0) & (b0<0x70UL) & (b0==b1) )
        read_accts = aset_insert( read_accts, (ulong)b0-0x30UL );
    }
  }

  FD_TEST( total_rewards >= min_rewards );

  FD_TEST( aset_is_null( aset_intersect( read_accts, write_accts ) ) );

  /* Check for conflict with microblocks on other bank tiles */
  for( ulong i=0UL; i<fd_pack_bank_tile_cnt( pack ); i++ ) {
    if( i==bank_tile ) continue;

    FD_TEST( aset_is_null( aset_intersect( write_accts, outcome->r_accts_in_use[ i ] ) ) );
    FD_TEST( aset_is_null( aset_intersect( write_accts, outcome->w_accts_in_use[ i ] ) ) );
    FD_TEST( aset_is_null( aset_intersect( read_accts,  outcome->w_accts_in_use[ i ] ) ) );
  }
  outcome->r_accts_in_use[ bank_tile ] =  read_accts;
  outcome->w_accts_in_use[ bank_tile ] = write_accts;

  outcome->microblock_cnt++;
  if( extra_verify ) FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

void test0( void ) {
  FD_LOG_NOTICE(( "TEST 0" ));
  fd_pack_t * pack = init_all( 128UL, 3UL, 128UL, &outcome );
  ulong i = 0UL;
  ulong reward;
  ulong cost_estimate;
  ulong total_rewards = 0UL;
  ulong total_cost_estimate = 0UL;
  make_transaction( i,  500U, 500U, 11.0, "A",    "B", &reward, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate; total_rewards += reward;
  make_transaction( i,  500U, 500U, 10.0, "C",    "D", &reward, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate; total_rewards += reward;
  make_transaction( i,  800U, 500U, 10.0, "EFGH", "D", &reward, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate; total_rewards += reward;
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 3UL, total_rewards, 0UL, &outcome );

  make_transaction( i,  500U, 500U, 10.0, "D", "I", &reward, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate; total_rewards += reward;
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 0UL, 0UL, 1UL, &outcome ); /* Can't schedule because conflict*/
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 0UL, 0UL, 2UL, &outcome ); /* conflict continues ... */
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 1UL, 0UL, 0UL, &outcome ); /* conflict gone.*/
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

/* The original two that broke my first algorithm */
void test1( void ) {
  FD_LOG_NOTICE(( "TEST 1" ));
  fd_pack_t * pack = init_all( 128UL, 1UL, 128UL, &outcome );
  ulong i = 0;
  ulong cost_estimate;
  ulong total_cost_estimate = 0UL;
  ulong reward1, reward2;
  make_transaction( i,  500U, 500U, 11.0, "A", "B", &reward1, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i,  500U, 500U, 10.0, "B", "A", &reward2, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 1UL, reward1, 0UL, &outcome );
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 1UL, reward2, 0UL, &outcome );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

void test2( void ) {
  FD_LOG_NOTICE(( "TEST 2" ));
  fd_pack_t * pack = init_all( 128UL, 1UL, 128UL, &outcome );
  ulong i = 0;
  double j = 13.0;
  ulong cost_estimate;
  ulong total_cost_estimate = 0UL;
  ulong r0, r1, r2, r3;
  make_transaction( i,  500U, 500U, j--, "B", "A", &r0, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i,  500U, 500U, j--, "C", "B", &r1, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i,  500U, 500U, j--, "D", "C", &r2, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i,  500U, 500U, j--, "A", "D", &r3, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 2UL, r0+r2, 0UL, &outcome );
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 2UL, r1+r3, 0UL, &outcome );

  /* A smart scheduler that allows read bypass could schedule the first 3 at
     the same time then #4 after they all finish. */
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

void test_vote( void ) {
  FD_LOG_NOTICE(( "TEST VOTE" ));
  fd_pack_t * pack = init_all( 128UL, 1UL, 4UL, &outcome );
  ulong i = 0;
  ulong pack_cost_estimate = 0UL;
  uint flags = 0UL;

  make_vote_transaction( i ); pack_cost_estimate += fd_pack_compute_cost( TXN( &txnp_scratch[ i ] ), txnp_scratch[ i ].payload, &flags, NULL, NULL, NULL, NULL ); insert( i++, pack );
  make_vote_transaction( i ); pack_cost_estimate += fd_pack_compute_cost( TXN( &txnp_scratch[ i ] ), txnp_scratch[ i ].payload, &flags, NULL, NULL, NULL, NULL ); insert( i++, pack );
  make_vote_transaction( i ); pack_cost_estimate += fd_pack_compute_cost( TXN( &txnp_scratch[ i ] ), txnp_scratch[ i ].payload, &flags, NULL, NULL, NULL, NULL ); insert( i++, pack );
  make_vote_transaction( i ); pack_cost_estimate += fd_pack_compute_cost( TXN( &txnp_scratch[ i ] ), txnp_scratch[ i ].payload, &flags, NULL, NULL, NULL, NULL ); insert( i++, pack );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 4UL );
  schedule_validate_microblock( pack, pack_cost_estimate, 0.0f, 0UL, 0UL, 0UL, &outcome );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 4UL );

  schedule_validate_microblock( pack, pack_cost_estimate, 0.25f, 1UL, 0UL, 0UL, &outcome );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );

  schedule_validate_microblock( pack, pack_cost_estimate, 1.0f, 3UL, 0UL, 0UL, &outcome );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  for( ulong j=0UL; j<3UL; j++ ) FD_TEST( outcome.results[ j ].flags==FD_TXN_P_FLAGS_IS_SIMPLE_VOTE );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static fd_ed25519_sig_t const *
txnp_get_signatures( fd_txn_p_t const * txnp ) {
  return fd_txn_get_signatures( TXN( txnp ), txnp->payload );
}

static void
test_delete( void ) {
  ulong i = 0UL;
  FD_LOG_NOTICE(( "TEST DELETE" ));
  fd_pack_t * pack = init_all( 10240UL, 4UL, 128UL, &outcome );
  ulong cost_estimate;
  ulong total_cost_estimate = 0UL;

  make_transaction( i, 800U, 500U, 12.0, "A", "B", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 700U, 500U, 11.0, "C", "D", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 600U, 500U, 10.0, "E", "F", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 500U, 500U,  9.0, "G", "H", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 400U, 500U,  8.0, "I", "J", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 300U, 500U,  7.0, "K", "L", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 6UL );

  fd_ed25519_sig_t const * sig0 = txnp_get_signatures( &txnp_scratch[0] );
  fd_ed25519_sig_t const * sig2 = txnp_get_signatures( &txnp_scratch[2] );
  fd_ed25519_sig_t const * sig4 = txnp_get_signatures( &txnp_scratch[4] );

  FD_TEST( fd_pack_delete_transaction( pack, sig0 ) );  FD_TEST( !fd_pack_delete_transaction( pack, sig0 ) );
  FD_TEST( fd_pack_delete_transaction( pack, sig2 ) );  FD_TEST( !fd_pack_delete_transaction( pack, sig2 ) );
  FD_TEST( fd_pack_delete_transaction( pack, sig4 ) );  FD_TEST( !fd_pack_delete_transaction( pack, sig4 ) );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );

  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 3UL, 0UL, 0UL, &outcome );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  fd_ed25519_sig_t const * sig1 = txnp_get_signatures( &txnp_scratch[1] );
  fd_ed25519_sig_t const * sig3 = txnp_get_signatures( &txnp_scratch[3] );
  fd_ed25519_sig_t const * sig5 = txnp_get_signatures( &txnp_scratch[5] );

  /* transactions 1,3,5 were scheduled so now deleting them fails */
  FD_TEST( !fd_pack_delete_transaction( pack, sig1 ) );
  FD_TEST( !fd_pack_delete_transaction( pack, sig3 ) );
  FD_TEST( !fd_pack_delete_transaction( pack, sig5 ) );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  i=0UL;
  ulong r0, r2;
  ulong cost0, cost1, cost5;
  make_transaction( i, 800U, 500U, 12.0, "A", "B", &r0,   &cost0 );  insert( i++, pack ); total_cost_estimate += cost0;
  make_transaction( i, 700U, 500U, 11.0, "A", "D", NULL, &cost1 );  insert( i++, pack ); total_cost_estimate += cost1;
  make_transaction( i, 600U, 500U, 10.0, "A", "F", &r2,   &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 500U, 500U,  9.0, "A", "H", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 400U, 500U,  8.0, "A", "J", NULL, &cost_estimate );  insert( i++, pack ); total_cost_estimate += cost_estimate;
  make_transaction( i, 300U, 500U,  7.0, "A", "L", NULL, &cost5 );  insert( i++, pack ); total_cost_estimate += cost5;

  /* They all conflict now */

  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 1UL, r0, 1UL, &outcome );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 5UL );

  total_cost_estimate -= cost0 + cost1 + cost5;
  FD_TEST( !fd_pack_delete_transaction( pack, sig0 ) );
  FD_TEST(  fd_pack_delete_transaction( pack, sig1 ) );
  FD_TEST(  fd_pack_delete_transaction( pack, sig5 ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );

  /* wait the gap */
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 0UL, 0, 2UL, &outcome );
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 0UL, 0, 3UL, &outcome );
  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 0UL, 0, 0UL, &outcome );

  schedule_validate_microblock( pack, total_cost_estimate, 0.0f, 1UL, r2, 1UL, &outcome );
  FD_TEST(  fd_pack_delete_transaction( pack, sig3 ) );
  FD_TEST(  fd_pack_delete_transaction( pack, sig4 ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static void
test_expiration( void ) {
  ulong i = 0UL;
  FD_LOG_NOTICE(( "TEST EXPIRATION" ));
  fd_pack_t * pack = init_all( 10240UL, 4UL, 128UL, &outcome );

  make_transaction( i, 800U, 500U, 12.0, "A", "B", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 700U, 500U, 11.0, "C", "D", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 600U, 500U, 10.0, "E", "F", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 500U, 500U,  9.0, "G", "H", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 400U, 500U,  8.0, "I", "J", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 300U, 500U,  7.0, "K", "L", NULL, NULL ); insert( i++, pack );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 6UL );

  FD_TEST( fd_pack_expire_before( pack, 2UL ) == 2UL ); /* expire 0, 1 */

  fd_ed25519_sig_t const * sig1 = txnp_get_signatures( &txnp_scratch[1] );
  /* transaction 1 was expired, so now deleting it fails */
  FD_TEST( !fd_pack_delete_transaction( pack, sig1 ) );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 4UL );

  schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 4UL, 0UL, 0UL, &outcome );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  FD_TEST( fd_pack_expire_before( pack, 10UL ) == 0UL );

  /* These 4 get rejected because they are expired */
  make_transaction( i, 800U, 500U, 12.0, "A", "B", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 700U, 500U, 11.0, "C", "D", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 600U, 500U, 10.0, "E", "F", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 500U, 500U,  9.0, "G", "H", NULL, NULL ); insert( i++, pack );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  make_transaction( i, 500U, 500U,  9.0, "A", "H", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 400U, 500U,  8.0, "A", "J", NULL, NULL ); insert( i++, pack );
  make_transaction( i, 300U, 500U,  7.0, "A", "L", NULL, NULL ); insert( i++, pack );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );

  schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );
  schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, 0UL, 1UL, &outcome );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 2UL );
  /* Even though txn 10 is expired, it was already scheduled, so account
     A is still in use. */
  FD_TEST( fd_pack_expire_before( pack, 12UL ) == 1UL );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 1UL );
  schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, 0UL, 1UL, &outcome );
  schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  /* Insert enough to cause them to go in the penalty treap */
  for( ulong j=0UL; j<200UL; j++ ) {
    make_transaction( i, 800U, 500U, 12.0, "A", "B", NULL, NULL ); insert( i++, pack );
  }
  FD_TEST( fd_pack_expire_before( pack, i-100UL ) == 100UL );
  for( ulong i=100UL; i<200UL; i++ ) {
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );
  }
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static void
performance_test2( void ) {
  FD_LOG_NOTICE(( "TEST INDEPENDENT PERFORMANCE" ));

  fd_pack_limits_t limits[ 1 ] = { {
      .max_cost_per_block        = 1000000000,
      .max_vote_cost_per_block   = 0UL,
      .max_write_cost_per_acct   = FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT,
      .max_data_bytes_per_block  = ULONG_MAX/2UL,
      .max_txn_per_microblock    = MAX_TXN_PER_MICROBLOCK,
      .max_microblocks_per_block = 10000000UL,
  } };
  /* Make 1024 transaction with different fee payers, no instructions,
     no other accounts. */
  for( ulong i=0UL; i<MAX_TEST_TXNS; i++ ) {
    uchar    * p      = payload_scratch[ i ];
    uchar    * p_base = p;
    fd_txn_t * t      = (fd_txn_t*) txn_scratch[ i ];

    *(p++) = (uchar)1;
    fd_memcpy( p,               &i,               sizeof(ulong)                                    );
    fd_memcpy( p+sizeof(ulong), SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );

    /* Just enough of a transaction to satisfy pack */
    p += FD_TXN_SIGNATURE_SZ;
    t->transaction_version   = FD_TXN_VLEGACY;
    t->signature_cnt         = 1;
    t->signature_off         = 1;
    t->message_off           = FD_TXN_SIGNATURE_SZ+1UL;
    t->readonly_signed_cnt   = 0;
    t->readonly_unsigned_cnt = 0;
    t->acct_addr_cnt         = 1;
    t->acct_addr_off         = FD_TXN_SIGNATURE_SZ+1UL;

    t->recent_blockhash_off         = 0;
    t->addr_table_lookup_cnt        = 0;
    t->addr_table_adtl_writable_cnt = 0;
    t->addr_table_adtl_cnt          = 0;
    t->instr_cnt                    = 0;

    /* Add the signer */
    *p = 's' + 0x80; fd_memcpy( p+1, &i, sizeof(ulong) ); memset( p+9, 'S', 32-9 ); p += FD_TXN_ACCT_ADDR_SZ;

    payload_sz[ i ] = (ulong)(p-p_base);
  }
  FD_TEST( fd_pack_footprint( 1024UL, 0UL, 4UL, limits )<PACK_SCRATCH_SZ );
#define INNER_ROUNDS (FD_PACK_TEST_MAX_COST_PER_BLOCK/(1020UL * 1024UL))
#define OUTER_ROUNDS 88
  long elapsed = 0L;

  fd_pack_t * pack = fd_pack_join( fd_pack_new( pack_scratch, 1024UL, 0UL, 4UL, limits, rng ) );

  for( ulong outer=0UL; outer<OUTER_ROUNDS; outer++ ) {
    elapsed -= fd_log_wallclock();
    for( ulong j=0UL; j<INNER_ROUNDS; j++ ) {
      for( ulong i=0UL; i<1024UL; i++ ) {
        fd_txn_e_t * slot      = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn       = (fd_txn_t *)txn_scratch[ i ];
        slot->txnp->payload_sz = payload_sz[ i ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ i ], payload_sz[ i ]                                                );
        fd_memcpy( TXN(slot->txnp),     txn,                  fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
        ulong _deleted;
        fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
      }
      ulong scheduled = 0UL;
      for( ulong i=0UL; i<1024UL/MAX_TXN_PER_MICROBLOCK+1UL; i++ ) {
        scheduled += fd_pack_schedule_next_microblock( pack, MAX_TXN_PER_MICROBLOCK*26000UL, 0.0f, i&3UL, ALL, outcome.results );
        fd_pack_microblock_complete( pack, i&3UL );
      }
      FD_TEST( scheduled==1024UL );
    }
    elapsed += fd_log_wallclock();
    fd_pack_end_block( pack );
  }

  ulong txns = OUTER_ROUNDS*INNER_ROUNDS*1024UL;
  FD_LOG_NOTICE(( "Inserted and scheduled %lu minimal transactions in %li ns. %f ns/txn", txns, elapsed,
                                                                                          (double)elapsed/(double)txns ));
#undef OUTER_ROUNDS
#undef INNER_ROUNDS
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

void performance_test( int extra_bench ) {
  FD_LOG_NOTICE(( "TEST PERFORMANCE" ));
  ulong tx1_cost, tx2_cost;
  make_transaction( 0, 700U, 500U, 12.0, "ABC", "DEF",    NULL, &tx1_cost ); /* Total cost 11634 */
  make_transaction( 1, 500U, 500U, 12.0, "GHJ", "KLMNOP", NULL, &tx2_cost ); /* Total cost 11434 */

  /* Move txnp to dense array */
  memcpy( txn_scratch[ 0 ], TXN( &txnp_scratch[ 0 ] ), FD_TXN_MAX_SZ );
  memcpy( txn_scratch[ 1 ], TXN( &txnp_scratch[ 1 ] ), FD_TXN_MAX_SZ );
  memcpy( payload_scratch[ 0 ], txnp_scratch[ 0 ].payload, txnp_scratch[ 0 ].payload_sz );
  memcpy( payload_scratch[ 1 ], txnp_scratch[ 1 ].payload, txnp_scratch[ 1 ].payload_sz );
  payload_sz[ 0 ] = txnp_scratch[ 0 ].payload_sz;
  payload_sz[ 1 ] = txnp_scratch[ 1 ].payload_sz;

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, 0UL, "test_pack", 0UL );

  /* Above 8192, we start running into MAX_WRITE_COST_PER_ACCT.
     Obviously, calling end_block fixes that, but it muddies the
     performance measurements. */
  ulong max_heap_sz = fd_ulong_if( (!!wksp) & extra_bench, 8192UL, 2048UL );
  ulong linear_inc  = fd_ulong_if( extra_bench, 256UL, 9999999UL );

  FD_LOG_NOTICE(( "All columns in units ns/txn except depth and End block (ns/call)" ));
  FD_LOG_NOTICE(( "Depth\tPreinsert\tInsert\tEnd block\tSchedule\tSkip fast\tSkip normal 1\tSkip normal 2" ));

#define ITER_CNT 10UL
#define WARMUP    2UL
  for( ulong heap_sz=16UL; heap_sz<=max_heap_sz; heap_sz = fd_ulong_min( heap_sz*2UL, heap_sz+linear_inc ) ) {
    fd_pack_limits_t limits[ 1 ] = { {
        .max_cost_per_block        = FD_PACK_TEST_MAX_COST_PER_BLOCK,
        .max_vote_cost_per_block   = 0UL,
        .max_write_cost_per_acct   = FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT,
        .max_data_bytes_per_block  = ULONG_MAX/2UL,
        .max_txn_per_microblock    = 3UL,
        .max_microblocks_per_block = heap_sz
    } };

    ulong footprint = fd_pack_footprint( heap_sz, 0UL, 1UL, limits );
    void * _mem;
    if( FD_LIKELY( wksp ) ) _mem = fd_wksp_alloc_laddr( wksp, fd_pack_align(), footprint, 4UL );
    else                    { FD_TEST( footprint<PACK_SCRATCH_SZ ); _mem = pack_scratch; }

    long preinsert = 0L;
    long insert    = 0L;
    long end_block = 0L;
    long skip0     = 0L;
    long skip1     = 0L;
    long skip2     = 0L;
    long schedule  = 0L;

    for( ulong iter=0UL; iter<ITER_CNT; iter++ ) {
      fd_pack_t * pack = fd_pack_join( fd_pack_new( _mem, heap_sz, 0UL, 1UL, limits, rng ) );

      FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );

      if( FD_LIKELY( iter>=WARMUP ) ) preinsert -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz; j++ ) {
        memcpy( payload_scratch[j&1]+1UL, &j, sizeof(ulong) );
        fd_txn_e_t * slot       = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ j&1 ];
        slot->txnp->payload_sz  = payload_sz[ j&1 ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ j&1 ], payload_sz[ j&1 ]                                              );
        fd_memcpy( TXN(slot->txnp),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
        fd_pack_insert_txn_cancel( pack, slot );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) preinsert += fd_log_wallclock( );

      if( FD_LIKELY( iter>=WARMUP ) ) insert    -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz; j++ ) {
        memcpy( payload_scratch[j&1]+1UL, &j, sizeof(ulong) );
        fd_txn_e_t * slot       = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ j&1 ];
        slot->txnp->payload_sz  = payload_sz[ j&1 ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ j&1 ], payload_sz[ j&1 ]                                              );
        fd_memcpy( TXN(slot->txnp),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

        ulong _deleted;
        fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) insert   += fd_log_wallclock( );

      FD_TEST( fd_pack_avail_txn_cnt( pack )==heap_sz );

      if( FD_LIKELY( iter>=WARMUP ) ) end_block -= fd_log_wallclock( );
      for( ulong j=0UL; j<5UL; j++ ) {
        fd_pack_end_block( pack );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) end_block += fd_log_wallclock( );

      if( FD_LIKELY( iter>=WARMUP ) ) skip0     -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz/2UL; j++ ) {
        /* With a cap of tx2_cost-1 CUs, nothing fits, but we scan the whole heap
           each time to figure that out. */
        fd_pack_schedule_next_microblock( pack, tx2_cost - 1UL, 0.0f, 0UL, ALL, outcome.results );
        fd_pack_microblock_complete( pack, 0UL );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) skip0     += fd_log_wallclock( );
      FD_TEST( fd_pack_avail_txn_cnt( pack )==heap_sz );

      fd_pack_end_block( pack );

      if( FD_LIKELY( iter>=WARMUP ) ) schedule  -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz; j++ ) {
        /* With a cap of tx1_cost CUs, we schedule 1 transaction and then
           immediately break. */
        FD_TEST( 1UL==fd_pack_schedule_next_microblock( pack, tx1_cost, 0.0f, 0UL, ALL, outcome.results ));
        fd_pack_microblock_complete( pack, 0UL );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) schedule += fd_log_wallclock( );
      FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );

      fd_pack_end_block( pack );

      /* Fill the heap back up */
      for( ulong j=0UL; j<heap_sz; j++ ) {
        memcpy( payload_scratch[j&1]+1UL, &j, sizeof(ulong) );
        fd_txn_e_t * slot       = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ j&1 ];
        slot->txnp->payload_sz  = payload_sz[ j&1 ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ j&1 ], payload_sz[ j&1 ]                                              );
        fd_memcpy( TXN(slot->txnp),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

        ulong _deleted;
        fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
      }

      FD_TEST( fd_pack_avail_txn_cnt( pack )==heap_sz );
      if( FD_LIKELY( iter>=WARMUP ) ) skip1  -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz/2UL; j++ ) {
        /* With a cap of tx1_cost+tx2_cost+1 CUs, we schedule a copy of
           transaction 1, scan through all the duplicates of transaction
           1 (which conflict because of accounts), finally find an
           instance of transaction 2, schedule it, and then immediately
           break. */
        FD_TEST( 2UL==fd_pack_schedule_next_microblock( pack, tx1_cost+tx2_cost+1, 0.0f, 0UL, ALL, outcome.results ) );
        fd_pack_microblock_complete( pack, 0UL );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) skip1 += fd_log_wallclock( );
      FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );

      fd_pack_end_block( pack );

      /* Fill the heap back up */
      for( ulong j=0UL; j<heap_sz; j++ ) {
        memcpy( payload_scratch[j&1]+1UL, &j, sizeof(ulong) );
        fd_txn_e_t * slot       = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn        = (fd_txn_t*) txn_scratch[ j&1 ];
        slot->txnp->payload_sz  = payload_sz[ j&1 ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ j&1 ], payload_sz[ j&1 ]                                              );
        fd_memcpy( TXN(slot->txnp),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

        ulong _deleted;
        fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
      }

      FD_TEST( fd_pack_avail_txn_cnt( pack )==heap_sz );
      if( FD_LIKELY( iter>=WARMUP ) ) skip2  -= fd_log_wallclock( );
      for( ulong j=0UL; j<heap_sz/2UL; j++ ) {
        /* With a huge CU cap, we schedule a copy of transaction 1,
           scan through all the duplicates of transaction 1 (which
           conflict because of accounts), finally find an instance of
           transaction 2, schedule it, then continue skipping through
           all the copies of transaction 2. */
        FD_TEST( 2UL==fd_pack_schedule_next_microblock( pack, 5000000UL, 0.0f, 0UL, ALL, outcome.results ) );
        fd_pack_microblock_complete( pack, 0UL );
      }
      if( FD_LIKELY( iter>=WARMUP ) ) skip2 += fd_log_wallclock( );
      FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
    }
    double denominator = (double)(heap_sz*(ITER_CNT-WARMUP));
    FD_LOG_NOTICE(( "%5lu\t%9.3f\t%6.3f\t%9.0f\t%8.3f\t%9.3f\t%13.3f\t%13.3f", heap_sz,
          (double)(preinsert         )/denominator,
          (double)(insert-preinsert  )/denominator,
          (double)(end_block         )/(double)5.0,
          (double)(schedule          )/denominator,
          (double)(skip0             )/(denominator*(double)(heap_sz    )/2.0),
          (double)(skip1-schedule    )/(denominator*(double)(heap_sz+2UL)/8.0),
          (double)(skip2-schedule    )/(denominator*(double)(heap_sz+2UL)/4.0) ));


    if( FD_LIKELY( wksp ) ) fd_wksp_free_laddr( _mem );
  }
  if( FD_LIKELY( wksp ) ) fd_wksp_delete_anon( wksp );
}

void performance_end_block( void ) {
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, 0UL, "test_pack", 0UL );

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_NOTICE(( "TEST END BLOCK PERFORMANCE skipped" ));
    return;
  }
  FD_LOG_NOTICE(( "TEST END BLOCK PERFORMANCE" ));

  fd_pack_limits_t limits[ 1 ] = { {
    .max_cost_per_block          = 13UL*FD_PACK_TEST_MAX_COST_PER_BLOCK,
      .max_vote_cost_per_block   = 0UL,
      .max_write_cost_per_acct   = FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT,
      .max_data_bytes_per_block  = ULONG_MAX/2UL,
      .max_txn_per_microblock    = 31UL,
      .max_microblocks_per_block = 16384UL,
  } };
  ulong footprint = fd_pack_footprint( 4096UL, 0UL, 8UL, limits );
  void * _mem = fd_wksp_alloc_laddr( wksp, fd_pack_align(), footprint, 4UL );

  make_transaction( 0UL, 800U, 500U, 4.0, "", "", NULL, NULL );
  memcpy( txn_scratch    [ 0UL ], TXN( &txnp_scratch[ 0UL ] ), FD_TXN_MAX_SZ );
  memcpy( payload_scratch[ 0UL ], txnp_scratch[ 0UL ].payload, txnp_scratch[ 0UL ].payload_sz );
  payload_sz[ 0UL ] = txnp_scratch[ 0UL ].payload_sz;

  FD_LOG_NOTICE(( "Writers\tTime (ms/call)" ));
  fd_pack_t * pack = fd_pack_join( fd_pack_new( _mem, 4096UL, 0UL, 8UL, limits, rng ) );
  for( ulong writers_cnt=1UL; writers_cnt<=16*1024UL; writers_cnt *= 2UL ) {
    long end_block = 0L;

    for( ulong iter=0UL; iter<ITER_CNT; iter++ ) {
      for( ulong i=0UL; i<writers_cnt; i++ ) {
        /* Make signature and signer unique */
        for( int k=0UL; k<4; k++ ) {
          payload_scratch[ 0UL ][ 0x01+k ] = (uchar)((i+iter*writers_cnt)>>(8*k));
          payload_scratch[ 0UL ][ 0x45+k ] = (uchar)((i+iter*writers_cnt)>>(8*k));
        }
        fd_txn_e_t * slot      = fd_pack_insert_txn_init( pack );
        fd_txn_t *   txn       = (fd_txn_t*) txn_scratch[ 0UL ];
        slot->txnp->payload_sz = payload_sz[ 0UL ];
        fd_memcpy( slot->txnp->payload, payload_scratch[ 0UL ], payload_sz[ 0UL ]                                              );
        fd_memcpy( TXN(slot->txnp),     txn,                    fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );

        ulong _deleted;
        fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
      }
      while( fd_pack_avail_txn_cnt( pack )>0UL ) {
        FD_TEST( fd_pack_schedule_next_microblock( pack, 5000000UL, 0.0f, 0UL, ALL, outcome.results ) );
        fd_pack_microblock_complete( pack, 0UL );
      }

      if( FD_LIKELY( iter>=WARMUP ) ) end_block -= fd_log_wallclock( );
      fd_pack_end_block( pack );
      if( FD_LIKELY( iter>=WARMUP ) ) end_block += fd_log_wallclock( );
    }
    FD_LOG_NOTICE(( "%8lu\t%2.3f", writers_cnt, (double)end_block/(1000000.0 * (double)(ITER_CNT-WARMUP)) ));
  }

  fd_wksp_free_laddr( _mem );
  fd_wksp_delete_anon( wksp );
#undef WARMUP
#undef ITER_CNT
}


void heap_overflow_test( void ) {
  FD_LOG_NOTICE(( "TEST HEAP OVERFLOW" ));
  fd_pack_t * pack = init_all( 1024UL, 1UL, 2UL, &outcome );
  /* Insert a bunch of low-paying transactions */
  for( ulong j=0UL; j<1024UL; j++ ) {
    fd_txn_e_t * slot = fd_pack_insert_txn_init( pack );
    make_transaction1( slot->txnp, j, 800U, 500U, 3.0, "ABC", "DEF", NULL, NULL );  /* 11733 cus */
    ulong _deleted;
    fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
  }
  FD_TEST( fd_pack_avail_txn_cnt( pack )==1024UL );

  /* Now insert higher-paying transactions. They should mostly take the
     place of the low-paying transactions, but it's probabilistic since
     the transactions conflict a lot. */
  ulong r_hi;
  for( ulong j=0UL; j<1024UL; j++ ) {
    fd_txn_e_t * slot = fd_pack_insert_txn_init( pack );
    make_transaction1( slot->txnp, j, 500U, 500U, 10.0, "GHJ", "KLMNOP", &r_hi, NULL );  /* 11434 cus */
    ulong _deleted;
    fd_pack_insert_txn_fini( pack, slot, 0UL, &_deleted );
  }

  FD_TEST( fd_pack_avail_txn_cnt( pack )==1024UL );

  for( ulong j=0UL; j<1024UL; j++ ) {
    /* 30000 cannot fit more than 1 transaction. */
    schedule_validate_microblock( pack, 12000, 0.0f, j<900UL?1UL:0UL, j<900UL?r_hi:0UL, 0UL, &outcome );
  }

  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static void
test_gap( void ) {
  FD_LOG_NOTICE(( "TEST GAP" ));

  for( ulong gap=1UL; gap<=FD_PACK_MAX_BANK_TILES; gap++ ) {
    fd_pack_t * pack = init_all( 10240UL, gap, 2UL, &outcome );
    ulong i=0UL;
    ulong reward1, reward2;
    make_transaction( i,  500U, 500U, 11.0, "A", "B", &reward1, NULL ); insert( i++, pack );  /* 11034 cus */
    make_transaction( i,  500U, 500U, 10.0, "B", "A", &reward2, NULL ); insert( i++, pack );
    FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

    /* 30000 in only enough to fit 1 transaction */
    schedule_validate_microblock( pack, 12000UL, 0.0f, 1UL, reward1, 0UL, &outcome );

    for( ulong j=1UL; j<gap; j++ ) schedule_validate_microblock( pack, 12000UL, 0.0f, 0UL, 0UL, j, &outcome );

    FD_TEST( fd_pack_avail_txn_cnt( pack )==1UL );

    schedule_validate_microblock( pack, 12000UL, 0.0f, 1UL, reward2, 0UL, &outcome );
    FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
  }
}

static void
test_limits( void ) {
  FD_LOG_NOTICE(( "TEST LIMITS" ));

  fd_pack_rebate_sum_t _rebater[1];
  union{ fd_pack_rebate_t rebate[1]; uchar footprint[USHORT_MAX]; } report[1];
  fd_pack_rebate_sum_t * rebater = fd_pack_rebate_sum_join( fd_pack_rebate_sum_new( _rebater ) );
  fd_acct_addr_t const * rebate_alt[1] = { NULL };

  /* Test the max txn per microblock limit */
  for( ulong max=1UL; max<=15UL; max++ ) {
    fd_pack_t * pack = init_all( 1024UL, 1UL, max, &outcome );

    for( ulong i=0UL; i<max*2UL; i++ ) {
      /* The votes are all non-conflicting */
      make_vote_transaction( i );
      insert( i, pack );
    }
    FD_TEST( fd_pack_avail_txn_cnt( pack )==max*2UL );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 1.0f, max, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==max     );
  }


  /* Test the CU limit */
  if( 1 ) {
    fd_pack_t * pack = init_all( 1024UL, 1UL, 1024UL, &outcome );

    for( ulong i=0UL; i<1024UL; i++ ) {
      /* The votes are all non-conflicting */
      make_vote_transaction( i );
      insert( i, pack );
    }

    /* Test that as we gradually increase the CU limit, the correct number of votes get scheduled */
    for( ulong cu_limit=0UL; cu_limit<45UL*FD_PACK_SIMPLE_VOTE_COST; cu_limit += FD_PACK_SIMPLE_VOTE_COST ) {
      /* FIXME: CU limit for votes is done based on the typical cost,
         which is slightly different from the sample vote cost. */
      schedule_validate_microblock( pack, cu_limit, 1.0f, cu_limit/FD_PACK_SIMPLE_VOTE_COST, 0UL, 0UL, &outcome );
    }
    /* sum_{x=0}^44 x = 990, so there should be 34 transactions left */
    FD_TEST( fd_pack_avail_txn_cnt( pack )==34UL );
  }


  /* Test the block vote limit */
  if( 1 ) {
    fd_pack_t * pack = init_all( 1024UL, 1UL, 1024UL, &outcome );

    for( ulong j=0UL; j<FD_PACK_TEST_MAX_VOTE_COST_PER_BLOCK/(1024UL*FD_PACK_SIMPLE_VOTE_COST); j++ ) {
      for( ulong i=0UL; i<1024UL; i++ ) { make_vote_transaction( i ); insert( i, pack ); }
      schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 1.0f, 1024UL, 0UL, 0UL, &outcome );
    }

    for( ulong i=0UL; i<1024UL; i++ ) { make_vote_transaction( i ); insert( i, pack ); }
    ulong consumed_cost = (1024UL*FD_PACK_SIMPLE_VOTE_COST)*(FD_PACK_TEST_MAX_VOTE_COST_PER_BLOCK/(1024UL*FD_PACK_SIMPLE_VOTE_COST));
    ulong expected_votes = (FD_PACK_TEST_MAX_VOTE_COST_PER_BLOCK-consumed_cost)/FD_PACK_SIMPLE_VOTE_COST;

    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 1.0f,        expected_votes, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==1024UL-expected_votes );

    fd_pack_end_block( pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 1.0f, 1024UL-expected_votes, 0UL, 0UL, &outcome );
  }


  /* Test the block writer limit */
  if( 1 ) {
    fd_pack_t * pack = init_all( 1024UL, 1UL, 1024UL, &outcome );
    /* The limit is based on cost units, which are determined by the cost model (i.e. fd_pack_compute_cost) */
    ulong j = 0UL;
    ulong total_cus;
    make_transaction( j, 20000UL, 500U, 11.0, "A", "B", NULL, &total_cus );  /* transaction cost estimate = total_cus*/
    insert( j++, pack );
    FD_TEST( 21334==total_cus );

    for( ; j<FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT/total_cus; j++ ) {
      make_transaction( j, 20000UL, 500U, 11.0, "A", "B", NULL, &total_cus );  /* transaction cost estimate = total_cus*/
      insert( j, pack );
      schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );
    }
    /* Consumed total_cus*FD_PACK_TEST_MAX_COST_PER_BLOCK/(4*total_cus)=11,966,340
       cost units, so this next one can't fit (due to
       FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT) */

    make_transaction( j, 20000UL, 500U, 11.0, "A", "B", NULL, NULL );
    insert( j++, pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==1UL );

    outcome.results->bank_cu.rebated_cus = (uint)((total_cus + (total_cus*FD_PACK_TEST_MAX_COST_PER_BLOCK/(4*total_cus))) - FD_PACK_TEST_MAX_WRITE_COST_PER_ACCT);
    fd_pack_rebate_sum_add_txn( rebater, outcome.results, rebate_alt, 1UL );
    fd_pack_rebate_sum_report( rebater, report->rebate );
    fd_pack_rebate_cus( pack, report->rebate );
    /* Now consumed CUs is 12M - total_cus, so it just fits. */
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );

    make_transaction( j, 20000UL, 500U, 11.0, "A", "B", NULL, NULL );
    insert( j++, pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==1UL );

    fd_pack_end_block( pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );
  }


  /* Test the total cost block limit */
  if( 1 ) {
    fd_pack_t * pack = init_all( 1024UL, 1UL, 512UL, &outcome );
    /* The limit is based on cost units, which are determined by the cost model (i.e. fd_pack_compute_cost). */
    ulong total_cus;
    make_transaction( 0UL, 20000UL, 500U, 11.0, "A", "B", NULL, &total_cus ); insert( 0UL, pack );
    const ulong almost_full_iter = (FD_PACK_TEST_MAX_COST_PER_BLOCK/( 8*total_cus ));

    ulong i = 1UL;
    for( ulong j=0UL; j<almost_full_iter; j++ ) {
      /* We do it in batches of 8 so that the writer cost limit doesn't dominate */
      make_transaction( i, 20000UL, 500U, 11.0, "A", "B", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "C", "D", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "E", "F", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "G", "H", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "J", "K", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "L", "M", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "N", "O", NULL, NULL );     insert( i++, pack );
      make_transaction( i, 20000UL, 500U, 11.0, "P", "Q", NULL, NULL );     insert( i++, pack );
      schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 8UL, 0UL, 0UL, &outcome );
      i = i%512UL;
    }

    /* We are at almost_full_iter*8*total_cus = 47988240
       The remaining 11760 will not be enough for any more txns */
    make_transaction( i, 20000UL, 500U, 11.0, "A", "B", NULL, NULL );     insert( i++, pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==1UL );


    /* rebate just enough cus to have the total_cus needed for one more */
    outcome.results[ 0 ].bank_cu.rebated_cus = (uint)(total_cus - (FD_PACK_TEST_MAX_COST_PER_BLOCK - almost_full_iter*8UL*total_cus - 7UL*total_cus));
    fd_pack_rebate_sum_add_txn( rebater, outcome.results, rebate_alt, 1UL );
    fd_pack_rebate_sum_report( rebater, report->rebate );
    fd_pack_rebate_cus( pack, report->rebate );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 1UL, 0UL, 0UL, &outcome );

    fd_pack_end_block( pack );
    make_transaction( i, 20000UL, 500U, 11.0, "J", "K", NULL, NULL );     insert( i++, pack );
    make_transaction( i, 20000UL, 500U, 11.0, "L", "M", NULL, NULL );     insert( i++, pack );
    make_transaction( i, 20000UL, 500U, 11.0, "N", "P", NULL, NULL );     insert( i++, pack );
    make_transaction( i, 20000UL, 500U, 10.0, "Q", "R", NULL, NULL );     insert( i++, pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 4UL, 0UL, 0UL, &outcome );
  }

  /* Test the data size limit */
  if( 1 ) {
    /* 1024 microblocks, each with 5 max size transactions */
    fd_pack_t * pack = init_all( 1024UL, 1UL, 5UL, &outcome );

    /* Iterates 844 times, consuming all but 3328 bytes */
    ulong i=0UL;
    ulong almost_full_iter = (MAX_DATA_PER_BLOCK/(48 + 5UL*1232UL));
    for( ulong j=0UL; j<almost_full_iter; j++ ) {
      make_transaction( i, 1000UL, 500U, 11.0, "A", "B", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
      make_transaction( i, 1000UL, 500U, 11.0, "C", "D", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
      make_transaction( i, 1000UL, 500U, 11.0, "E", "F", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
      make_transaction( i, 1000UL, 500U, 11.0, "G", "H", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
      make_transaction( i, 1000UL, 500U, 11.0, "I", "J", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );

      schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 5UL, 0UL, 0UL, &outcome );
      i = i%512UL;
    }

    /* 3328 - 48 = 3280 */
    make_transaction( i, 1000UL, 500U, 11.0, "K", "L", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
    make_transaction( i, 1000UL, 500U, 11.0, "M", "N", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
    make_transaction( i, 1000UL, 500U, 10.0, "O", "P", NULL, NULL );  txnp_scratch[i].payload_sz= 816UL;  insert( i++, pack );
    make_transaction( i, 1000UL, 500U, 10.0, "Q", "R", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );
    make_transaction( i, 1000UL, 500U, 10.0, "S", "T", NULL, NULL );  txnp_scratch[i].payload_sz=1232UL;  insert( i++, pack );

    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 3UL, 0UL, 0UL, &outcome );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==2UL );

    fd_pack_end_block( pack );
    schedule_validate_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 2UL, 0UL, 0UL, &outcome );
  }
}

static inline void
test_vote_qos( void ) {
  FD_LOG_NOTICE(( "TEST VOTE QOS" ));
  fd_pack_t * pack = init_all( 16UL, 1UL, 128UL, &outcome );

  /* Fill with votes */
  for( ulong i=0UL; i<16UL; i++ ) {
    make_vote_transaction( i );
    FD_TEST( insert( i, pack )==FD_PACK_INSERT_ACCEPT_VOTE_ADD );
  }
  ulong i=16UL;
  /* treap is imbalanced so will accept any non-vote, even extremely
     non-lucrative ones. */
  make_transaction( i, 1000000UL, 500U, 0.001, "A", "B", NULL, NULL ); FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 1000000UL, 500U, 0.001, "A", "B", NULL, NULL ); FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 1000000UL, 500U, 0.001, "A", "B", NULL, NULL ); FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 1000000UL, 500U, 0.001, "A", "B", NULL, NULL ); FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  /* Now it's balanced, so the non-vote will be compared with the other
     non-votes.  It's not better than them, so reject. */
  make_transaction( i, 1000000UL, 500U, 0.001, "A", "B", NULL, NULL ); FD_TEST( insert( i++, pack )==FD_PACK_INSERT_REJECT_PRIORITY        );

  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  /* The first non-votes are worse than the votes, so now these
     lucrative transactions have replaced the old non-votes and we still
     have 12 pending votes */
  for( ulong j=16UL; j<20UL; j++ ) {
    fd_ed25519_sig_t const * sig = txnp_get_signatures( &txnp_scratch[j] );
    FD_TEST( !fd_pack_delete_transaction( pack, sig ) );
  }

  /* Now replace 8 votes with non-votes */
  for( ulong j=0UL; j<8UL; j++ ) {
    make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );    FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );
  }
  /* Exactly 25% votes, so this is not considered imbalanced and QoS
     rules allow it. */
  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE );

  /* It's now low on votes (<25%), so inserting a non-vote will compare
     only against other non-votes. */
  make_transaction( i, 100UL, 500U, 13.0, "A", "B", NULL, NULL );      FD_TEST( insert( i++, pack )==FD_PACK_INSERT_REJECT_PRIORITY        );

  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static inline void
test_reject_writes_to_sysvars( void ) {
  FD_LOG_NOTICE(( "TEST SYSVARS" ));
  fd_pack_t * pack = init_all( 1024UL, 1UL, 128UL, &outcome );
  /* list generated with:
        for x in ReservedAccountKeys::all_keys_iter() {
            println!("\"{:#?}\",", x);
        }
   */
#define N_ACCTS 31
  char const * sysvars[ N_ACCTS ] = {
    "AddressLookupTab1e1111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
    "StakeConfig11111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarRewards111111111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111"
  };
  for( ulong i=0UL; i<N_ACCTS; i++ ) {
    make_transaction( i, 1000001U, 500U, 11.0, "A", "B", NULL, NULL );
    /* Replace A with the sysvar */
    fd_base58_decode_32( sysvars[ i ], txnp_scratch[ i ].payload+97UL );
    txnp_scratch[ i ].payload[ 129UL ]++; /* so it no longer is the compute budget program */
    FD_TEST( insert( i, pack )==FD_PACK_INSERT_REJECT_WRITES_SYSVAR );
    FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  }
#undef N_ACCTS
}

static inline void
test_reject( void ) {
  FD_LOG_NOTICE(( "TEST REJECT" ));
  fd_pack_t * pack = init_all( 1024UL, 1UL, 128UL, &outcome );
  ulong i = 0UL;

  make_transaction( i, 1000001U, 500U, 11.0, "A", "B", NULL, NULL );
  fd_txn_t * txn = TXN( &txnp_scratch[ i ] );
  fd_memset( txnp_scratch[ i ].payload + txn->instr[ 0 ].data_off, 0xFF, 4 );
  FD_TEST( insert( i, pack )==FD_PACK_INSERT_REJECT_ESTIMATION_FAIL );

  i++;
  make_transaction( i, 1000001U, 500U, 11.0, "ABC", "DEF", NULL, NULL ); /* 6 listed + fee payer + 2 programs */
  txn = TXN( &txnp_scratch[ i ] );
  txn->addr_table_lookup_cnt        = 1;
  txn->addr_table_adtl_writable_cnt = 20;
  txn->addr_table_adtl_cnt          = 56;
  FD_TEST( insert( i, pack )==FD_PACK_INSERT_REJECT_ACCOUNT_CNT );

  i++;
  make_transaction( i, 1000001U, 500U, 11.0, "A", "A", NULL, NULL );
  FD_TEST( insert( i, pack )==FD_PACK_INSERT_REJECT_DUPLICATE_ACCT );


  for( ulong j=0UL; j<=i; j++ ) fd_memset( TXN( &txnp_scratch[ i ] ), (uchar)0, FD_TXN_MAX_SZ );
}

static inline void
test_duplicate_sig( void ) {
  FD_LOG_NOTICE(( "TEST DUPLICATE SIGNATURE" ));
  fd_pack_t * pack = init_all( 1024UL, 1UL, 128UL, &outcome );
  ulong i = 0UL;

  make_transaction( i, 1000001U, 500U, 11.0, "A", "B", NULL, NULL );
  FD_TEST( insert( i, pack )>=0 );
  FD_TEST( insert( i, pack )>=0 );
  FD_TEST( insert( i, pack )>=0 );

  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );

  fd_ed25519_sig_t const * sig0 = txnp_get_signatures( &txnp_scratch[0] );

  FD_TEST( fd_pack_delete_transaction( pack, sig0 ) );  FD_TEST( !fd_pack_delete_transaction( pack, sig0 ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );

  FD_TEST( insert( i, pack )>=0 );
  txnp_scratch[1] = txnp_scratch[0];

  i++;
  FD_TEST( insert( i, pack )>=0 ); /* inserted with expires_at==1 */
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 2UL );
  FD_TEST( 1UL==fd_pack_expire_before( pack, 1 ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 1UL );
  FD_TEST( fd_pack_delete_transaction( pack, sig0 ) );  FD_TEST( !fd_pack_delete_transaction( pack, sig0 ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static inline void
test_nonce( void ) {
  FD_LOG_NOTICE(( "TEST DUPLICATE NONCE" ));
  fd_pack_t * pack = init_all( 1024UL, 1UL, 128UL, &outcome );
  ulong i = 0UL;

  make_nonce_transaction( i, 11.0, 4, 0, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD     );
  make_nonce_transaction( i, 10.0, 4, 0, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_REJECT_NONCE_PRIORITY        );
  make_nonce_transaction( i, 14.0, 4, 0, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_REPLACE );
  /* Changing any of the tuple makes it a different nonce */
  make_nonce_transaction( i, 11.0, 5, 0, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD     );
  make_nonce_transaction( i, 11.0, 4, 1, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD     );
  make_nonce_transaction( i, 11.0, 4, 0, 'j' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD     );

  make_nonce_transaction( i, 11.0, 4, 5, 'h' );   FD_TEST( insert( i++, pack )==FD_PACK_INSERT_REJECT_INVALID_NONCE         );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
}

static void
test_bundle_nonce_conflict_detect( fd_pack_t * pack,
                                   ulong       txn_cnt,
                                   ulong       dup_idx_0,
                                   ulong       dup_idx_1 ) {
  FD_TEST(
      txn_cnt>1 &&
      dup_idx_0!=dup_idx_1 &&
      dup_idx_0<txn_cnt &&
      dup_idx_1<txn_cnt
  );
  fd_swap_if( dup_idx_0>dup_idx_1, dup_idx_0, dup_idx_1 );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );

  fd_txn_e_t * _bundle[ FD_PACK_MAX_TXN_PER_BUNDLE ];
  ulong _deleted;

  /* All transactions are nonce transactions */
  fd_txn_e_t * const * bundle = fd_pack_insert_bundle_init( pack, _bundle, txn_cnt );
  for( ulong i=0UL; i<txn_cnt; i++ ) make_nonce_transaction1( bundle[ i ]->txnp, i, 11.0, 4, 0, (char)( 'a'+i ) );
  make_nonce_transaction1( bundle[ dup_idx_0 ]->txnp, dup_idx_0, 11.0, 4, 0, 'D' );
  make_nonce_transaction1( bundle[ dup_idx_1 ]->txnp, dup_idx_1, 11.0, 4, 0, 'D' );
  int result = fd_pack_insert_bundle_fini( pack, bundle, txn_cnt, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_REJECT_NONCE_CONFLICT );

  /* Try again, but other transactions are non-nonce */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, txn_cnt );
  for( ulong i=0UL; i<txn_cnt; i++ ) make_vote_transaction1( bundle[ i ]->txnp, i );
  make_nonce_transaction1( bundle[ dup_idx_0 ]->txnp, dup_idx_0, 11.0, 4, 0, 'D' );
  make_nonce_transaction1( bundle[ dup_idx_1 ]->txnp, dup_idx_1, 11.0, 4, 0, 'D' );
  result = fd_pack_insert_bundle_fini( pack, bundle, txn_cnt, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_REJECT_NONCE_CONFLICT );

  /* Rule out false positive */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, txn_cnt );
  for( ulong i=0UL; i<txn_cnt; i++ ) make_vote_transaction1( bundle[ i ]->txnp, i );
  make_nonce_transaction1( bundle[ dup_idx_0 ]->txnp, dup_idx_0, 11.0, 4, 0, 'D' );
  make_nonce_transaction1( bundle[ dup_idx_1 ]->txnp, dup_idx_1, 11.0, 5, 0, 'D' ); /* different */
  fd_ed25519_sig_t sig; memcpy( &sig, txnp_get_signatures( bundle[ dup_idx_1 ]->txnp ), sizeof(fd_ed25519_sig_t) );
  result = fd_pack_insert_bundle_fini( pack, bundle, txn_cnt, 1000UL, 0, NULL, &_deleted );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==txn_cnt );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD );
  FD_TEST( fd_pack_delete_transaction( pack, fd_type_pun( &sig ) )>=1 );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
}

static void
test_bundle_nonce( void ) {
  ulong const pack_depth = 32UL;
  fd_pack_t * pack = init_all( pack_depth, 1UL, 32UL, &outcome );
  fd_pack_set_initializer_bundles_ready( pack );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* First bundle */
  fd_txn_e_t * _bundle[3];
  ulong _deleted;
  fd_txn_e_t * const * bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_nonce_transaction1( bundle[0]->txnp, 0UL, 11.0, 4, 0, 'a' );
  make_nonce_transaction1( bundle[1]->txnp, 1UL, 11.0, 5, 0, 'b' );
  make_nonce_transaction1( bundle[2]->txnp, 2UL, 11.0, 6, 0, 'c' );
  int result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 3UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Cannot insert bundle with same nonce, even with higher prio */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_vote_transaction1( bundle[0]->txnp, 0UL );
  make_nonce_transaction1( bundle[1]->txnp, 1UL, 999.0, 5, 0, 'b' );
  make_vote_transaction1( bundle[2]->txnp, 2UL );
  result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_REJECT_NONCE_PRIORITY );

  /* Cannot insert transaction with same nonce, even with higher prio */
  fd_txn_e_t * txn = fd_pack_insert_txn_init( pack );
  make_nonce_transaction1( txn->txnp, 1UL, 999.0, 5, 0, 'b' );
  result = fd_pack_insert_txn_fini( pack, txn, 1000UL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_REJECT_NONCE_PRIORITY );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==3UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Schedule transactions */
  ulong txn_cnt = fd_pack_schedule_next_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, FD_PACK_SCHEDULE_BUNDLE, outcome.results );
  FD_TEST( txn_cnt == 3UL );
  FD_TEST( fd_pack_avail_txn_cnt( pack ) == 0UL );
  for( ulong j = 0UL; j < 3UL; j++ ) {
    FD_TEST( outcome.results[j].flags & FD_TXN_P_FLAGS_BUNDLE );
    FD_TEST( outcome.results[j].flags & FD_TXN_P_FLAGS_DURABLE_NONCE );
  }
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  fd_pack_microblock_complete( pack, 0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Now, insert transaction (nonce free again) */
  txn = fd_pack_insert_txn_init( pack );
  make_nonce_transaction1( txn->txnp, 3UL, 10.0, 5, 0, 'b' );
  result = fd_pack_insert_txn_fini( pack, txn, 1000UL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==1UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Displace nonce txns using a bundle */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_nonce_transaction1( bundle[0]->txnp, 0UL, 2.0, 5, 0, 'b' );
  make_vote_transaction1( bundle[1]->txnp, 1UL );
  make_nonce_transaction1( bundle[2]->txnp, 2UL, 2.0, 5, 0, 'c' );
  fd_ed25519_sig_t sig; memcpy( &sig, txnp_get_signatures( bundle[1]->txnp ), sizeof(fd_ed25519_sig_t) );
  result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_REPLACE );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==3UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Deleting one bundle txn should reap siblings too */
  FD_TEST( fd_pack_delete_transaction( pack, fd_type_pun( &sig ) )>=1 );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Reject duplicate nonce in bundle */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_nonce_transaction1( bundle[0]->txnp, 0UL, 2.0, 5, 0, 'b' );
  make_vote_transaction1( bundle[1]->txnp, 1UL );
  make_nonce_transaction1( bundle[2]->txnp, 2UL, 2.0, 5, 0, 'b' );
  result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_REJECT_NONCE_CONFLICT );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Displace nonce txns using a bundle */
  for( ulong j=0UL; j<pack_depth; j++ ) {
    fd_txn_e_t * txn = fd_pack_insert_txn_init( pack );
    make_nonce_transaction1( txn->txnp, j, 2.0, 4, 0, (char)( 'A'+j ) );
    ulong _deleted;
    FD_TEST( fd_pack_insert_txn_fini( pack, txn, 1000UL, &_deleted )==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD );
  }
  bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_nonce_transaction1( bundle[0]->txnp, 0UL, 2.0, 4, 0, 'a' );
  make_nonce_transaction1( bundle[1]->txnp, 1UL, 2.0, 5, 0, 'b' );
  make_nonce_transaction1( bundle[2]->txnp, 2UL, 2.0, 4, 0, 'c' );
  result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_REPLACE );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==32UL );
  for( ulong j=0UL; j<pack_depth; j++ ) {
    fd_pack_schedule_next_microblock( pack, FD_PACK_TEST_MAX_COST_PER_BLOCK, 0.0f, 0UL, FD_PACK_SCHEDULE_BUNDLE|FD_PACK_SCHEDULE_TXN, outcome.results );
    fd_pack_microblock_complete( pack, 0UL );
  }
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Test clear_all */
  bundle = fd_pack_insert_bundle_init( pack, _bundle, 3UL );
  make_nonce_transaction1( bundle[0]->txnp, 0UL, 11.0, 4, 0, 'a' );
  make_nonce_transaction1( bundle[1]->txnp, 1UL, 11.0, 5, 0, 'b' );
  make_nonce_transaction1( bundle[2]->txnp, 2UL, 11.0, 6, 0, 'c' );
  result = fd_pack_insert_bundle_fini( pack, bundle, 3UL, 1000UL, 0, NULL, &_deleted );
  FD_TEST( result==FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==3UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );
  fd_pack_clear_all( pack );
  FD_TEST( fd_pack_avail_txn_cnt( pack )==0UL );
  FD_TEST( !fd_pack_verify( pack, pack_verify_scratch ) );

  /* Test custom nonce conflict-detection algorithm (generate every
     conflict possible), j,k indicate the conflicting indices. */
  for( ulong i=2UL; i<=FD_PACK_MAX_TXN_PER_BUNDLE; i++ ) {
    for( ulong j=0UL; j<i; j++ ) {
      for( ulong k=0UL; k<i; k++ ) {
        if( j==k ) continue;
        test_bundle_nonce_conflict_detect( pack, i, j, k );
      }
    }
  }
  fd_pack_delete( fd_pack_leave( pack ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  int extra_benchmark = fd_env_strip_cmdline_contains( &argc, &argv, "--extra-bench" );
  extra_verify = fd_env_strip_cmdline_contains( &argc, &argv, "--extra-verify" );

  test0();
  test1();
  test2();
  test_vote();
  heap_overflow_test();
  test_delete();
  test_expiration();
  test_gap();
  test_limits();
  if( 0 ) test_vote_qos();
  test_reject_writes_to_sysvars();
  test_reject();
  test_duplicate_sig();
  test_nonce();
  test_bundle_nonce();
  performance_test( extra_benchmark );
  performance_test2();
  performance_end_block();

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
