/* ************************ Pack Tile Test Configuration ******************** */
#include "fd_pack_tile.c"
#include "fd_pack.c"
#include "fd_pack.h"
#include "fd_pack_cost.h"
#include "fd_microblock.h"
#include "fd_pack_rebate_sum.h"

struct txn_ref {
  double prio;
  int    txn_i;

  /* treap field */
  ushort parent_cidx;
  ushort left_cidx;
  ushort right_cidx;
  ushort prio_cidx;
  ushort prev_cidx;
  ushort next_cidx;
};
typedef struct txn_ref txn_ref_t;

#define POOL_NAME  txn_ref_pool
#define POOL_T     txn_ref_t
#define POOL_IDX_T ushort
#define POOL_NEXT  parent_cidx
#include "../../util/tmpl/fd_pool.c"

/* TODO: check if possible to use float for priority  */
#define TREAP_NAME       txn_ref_treap
#define TREAP_T          txn_ref_t
#define TREAP_QUERY_T    double
#define TREAP_CMP(q,e)   (((double)(q)) < ((double)((e)->prio)) ? -1 : (((double)(q)) > ((double)((e)->prio))) ? 1 : 0)
#define TREAP_LT(e0,e1)  (((double)((e0)->prio)) < ((double)((e1)->prio)))
#define TREAP_IDX_T      ushort
#define TREAP_PARENT     parent_cidx
#define TREAP_LEFT       left_cidx
#define TREAP_RIGHT      right_cidx
#define TREAP_PRIO       prio_cidx
#define TREAP_IMPL_STYLE 0
#include "../../util/tmpl/fd_treap.c"

struct tile_test_locals {
  /* resolve_pack link */
  ulong txn_in_pack;            // number of txns currently stored in pack, including bundle txns
  int   txn_i;                  // current transaction being published
  ulong txn_ref_i;              // current transaction to check against
  ulong txn_cnt;                // expected number of txns in pack-bank link
  ulong in_sig;                 // min blockhash from resolve_pack link
  ulong bundle_id;              // current bundle id
  ulong bundle_txn_rcvd;        // number of txns recvd in the current bundle
  ulong txn_per_bundle;         // total number of txns in the current bundle
  long  last_successful_insert; // updated everytime in after_frag_check

  /* for stress test */
  ulong wrap_around;               // wrap around when txn_i hits MAX
  ulong is_stress_test;
  ulong stress_test_published;
  ulong stress_test_target;
  txn_ref_treap_t _treap[1];
  txn_ref_treap_t * txn_ref_treap;   // For keeping track of correct ordering of txns in stress test
  txn_ref_t       * txn_ref_pool;

  /* poh_pack link */
  fd_became_leader_t become_leader_ref;
  ulong              curr_leader_slot;
  int                crank_enabled;

  /* bank_pack link */
  fd_pack_rebate_t rebate_ref;
  int              rebate_checked;
};


#define TEST_CALLBACK_BEFORE_CREDIT before_credit
#define TEST_CALLBACK_AFTER_CREDIT  after_credit
#define TEST_CALLBACK_DURING_FRAG   during_frag
#define TEST_CALLBACK_AFTER_FRAG    after_frag
#define TEST_CALLBACK_HOUSEKEEPING  during_housekeeping

#define TEST_TILE_CTX_TYPE fd_pack_ctx_t

#define TEST_LINKS_OUT_CNT 2
#define TEST_LINKS_CNT     5

/* ******************************** Test APIs ******************************* */
#define TEST_IS_FIREDANCER (0)

/* Auxiliary tile unit test skeleton and api. */
#include "../../app/shared/fd_tile_unit_test.h"
#include "../../app/shared/fd_tile_unit_test_tmpl.c"

/* Base topology. */
#if TEST_IS_FIREDANCER==0
#include "../../app/fdctl/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/fdctl/config/default.toml")
#else
#include "../../app/firedancer/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/firedancer/config/default.toml")
#endif

/* Global config. */
config_t config[1];

static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 10, 10 ) ] __attribute__((aligned(FD_METRICS_ALIGN))) = {0};

/* ********************* Pack Tile Test Configuration TBC ******************* */
#define MAX_TEST_TXNS (26)
#define MAX_TEST_PENDING_TXNS (65524)
#define CRANK_WKSP_SIZE (2097152UL)   // 2MB
static fd_txn_e_t txn_scratch[ MAX_TEST_TXNS ] = {0};
static ulong      txnp_sz[ MAX_TEST_TXNS     ] = {0};
static ulong      txnt_sz[ MAX_TEST_TXNS     ] = {0};
static double     txn_prio[ MAX_TEST_TXNS ]    = {0.0};
static uchar      crank_scratch[ CRANK_WKSP_SIZE ]__attribute__((aligned((FD_SHMEM_NORMAL_PAGE_SZ)))) = {0};

#define TXN_REF_SCRATCH_SZ (MAX_TEST_PENDING_TXNS*sizeof(txn_ref_t))
/* Add 256 to account for header overhead: the size of
   txn_ref_pool_scratch needs to be compiled-time constant */
static uchar txn_ref_pool_scratch[ TXN_REF_SCRATCH_SZ + 256 ] __attribute__((aligned(128UL))) = {0};
static const char * accs [ MAX_TEST_TXNS ] = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S","T", "U", "V", "W", "X", "Y", "Z" };

static const char SIGNATURE_SUFFIX[ FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint) ] = ": this is the fake signature of transaction number ";
static const char WORK_PROGRAM_ID[ FD_TXN_ACCT_ADDR_SZ ]                                 = "Work Program Id Consumes 1<<j C";
static ulong      signer                                                                 = 0;

// PDA configs
static const fd_acct_addr_t * tip_distribution_program_addr = (const fd_acct_addr_t *)"The_tip_distribution_prgrm_addr";
static const fd_acct_addr_t * tip_payment_program_addr      = (const fd_acct_addr_t *)"The_tip_payment_program_addr___";
static const fd_acct_addr_t * validator_vote_acct_addr      = (const fd_acct_addr_t *)"The_validator_vote_acct_addr___";
static const fd_acct_addr_t * merkle_root_authority_addr    = (const fd_acct_addr_t *)"The_merkle_root_authority_addr_";
static const fd_acct_addr_t * validator_identity_pk         = (const fd_acct_addr_t *)"The_validator_identity_pk______";
static const char           * block_engine_commission_pk    = /*                    */"The_block_engine_commision_pk__";
static const uchar            block_engine_commission_pct   = /*                    */2;

#define MAX_PRIORITY (13.5)
#define TICKS_PER_SLOT (64)
#define TICK_DURATION_NS (6400)
#define SLOT_DURATION_NS (TICKS_PER_SLOT * TICK_DURATION_NS)
#define MAX_MICROBLOCKS_PER_SLOT (32768UL)      /* defined in fd_poh_tile.c */

static ulong epoch       = 0;
static ulong leader_slot = 1;

#define TEST_LINK_RESOLV_PACK 0
#define TEST_LINK_POH_PACK    1
#define TEST_LINK_BANK_PACK   2
#define TEST_LINK_PACK_BANK   3
#define TEST_LINK_PACK_POH    4

/**************************** Pack Tile Test Helper ***************************/

/* From test_pack.c
   Makes enough of a transaction to schedule that reads one account for
   each character in 'reads' and writes one account for each character in
   'writes'.  The characters before the nul-terminator in reads and writes
   should be in [0x30, 0x70), basically numbers and uppercase letters.
   Adds a unique signer.  A computeBudgetInstruction will be included
   with compute requested cus and another instruction will be added
   requesting loaded_data_sz bytes of accounts data.  Fee will be set to
   5^priority, so that even with a large stall, it should still schedule
   in decreasing priority order.  priority should be in (0, 13.5].
   Stores the created transaction in txn_scratch[ i ] and
   payload_scratch[ i ]. Return the priority fee*/
static ulong
make_transaction( fd_txn_p_t * txnp,
                   ulong        i,
                   uint         compute,
                   uint         loaded_data_sz,
                   double       priority,
                   char const * writes,
                   char const * reads ) {
  uchar * p = txnp->payload;
  uchar * p_base = p;
  fd_txn_t * t = TXN( txnp );

  *(p++) = (uchar)1;
  fd_memcpy( p,                                   &i,               sizeof(ulong)                                    );
  fd_memcpy( p+sizeof(ulong),                     SIGNATURE_SUFFIX, FD_TXN_SIGNATURE_SZ - sizeof(ulong)-sizeof(uint) );
  fd_memcpy( p+FD_TXN_SIGNATURE_SZ-sizeof(ulong), &compute,         sizeof(uint)                                     );
  p                         += FD_TXN_SIGNATURE_SZ;
  t->transaction_version    = FD_TXN_VLEGACY;
  t->signature_cnt          = 1;
  t->signature_off          = 1;
  t->message_off            = FD_TXN_SIGNATURE_SZ+1UL;
  t->readonly_signed_cnt    = 0;
  ulong programs_to_include = 2UL; /* 1 for compute budget, 1 for "work" program */
  t->readonly_unsigned_cnt  = (uchar)(strlen( reads ) + programs_to_include);
  t->acct_addr_cnt          = (ushort)(1UL + strlen( reads ) + programs_to_include + strlen( writes ));
  t->acct_addr_off          = FD_TXN_SIGNATURE_SZ+1UL;

  /* Add the signer */
  *p = 's'; fd_memcpy( p+1, &signer, sizeof(ulong) ); memset( p+9, 'S', FD_TXN_ACCT_ADDR_SZ-9 ); p += FD_TXN_ACCT_ADDR_SZ;
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

  t->recent_blockhash_off         = 0;
  t->addr_table_lookup_cnt        = 0;
  t->addr_table_adtl_writable_cnt = 0;
  t->addr_table_adtl_cnt          = 0;
  t->instr_cnt                    = 3U;
  uchar prog_start                = (uchar)(1UL+strlen( writes ));

  t->instr[ 0 ].program_id = prog_start;
  t->instr[ 0 ].acct_cnt   = 0;
  t->instr[ 0 ].data_sz    = 5;    // "2" and then "compute"
  t->instr[ 0 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 0 ].data_off   = (ushort)(p - p_base);

  /* Write instruction data */
  *p = 2; fd_memcpy( p+1, &compute, sizeof(uint) );
  p += 5UL;

  t->instr[ 1 ].program_id = prog_start;
  t->instr[ 1 ].acct_cnt   = 0;
  t->instr[ 1 ].data_sz    = 9;     // "3" and then "rewards_per_cu"
  t->instr[ 1 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 1 ].data_off   = (ushort)(p - p_base);

  /* 3 corresponds to SetComputeUnitPrice */
  ulong rewards_per_cu = (ulong) (pow( 5.0, priority )*10000.0 / (double)compute);
  *p = 3; fd_memcpy( p+1, &rewards_per_cu, sizeof(ulong) );
  p += 9UL;

  t->instr[ 2 ].program_id = prog_start;
  t->instr[ 2 ].acct_cnt   = 0;
  t->instr[ 2 ].data_sz    = 5;     // "4" and then "loaded_data_sz"
  t->instr[ 2 ].acct_off   = (ushort)(p - p_base);
  t->instr[ 2 ].data_off   = (ushort)(p - p_base);

  /* 4 corresponds to SetLoadedAccountsDataSizeLimit */
  *p = 4; fd_memcpy( p+1, &loaded_data_sz, sizeof(uint) );
  p  += 5UL;

  txnp->payload_sz = (ulong)(p-p_base);
  uint flags;
  ulong opt_fee;
  ulong cost = fd_pack_compute_cost( TXN( txnp ), txnp->payload, &flags, NULL, &opt_fee, NULL, NULL);
  FD_TEST( cost );

  return opt_fee;
}

static void
print_txn_treap( fd_pack_ctx_t * ctx ) {
  FD_LOG_NOTICE(( "print_txn_treap-------------------------" ));
  FD_LOG_NOTICE(( "treap max depth: %lu", ctx->pack->pack_depth ));
  treap_t           * txn_treap = &ctx->pack->pending[0];
  fd_pack_ord_txn_t * pool      = ctx->pack->pool;
  treap_rev_iter_t    prev      = treap_idx_null();
  for( treap_rev_iter_t _cur = treap_rev_iter_init( txn_treap, pool ); !treap_rev_iter_done( _cur ); _cur=prev ) {
    /* Capture next so that we can delete while we iterate. */
    prev = treap_rev_iter_next( _cur, pool );
    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
    FD_LOG_HEXDUMP_NOTICE(( "txn's w signer in treap", cur->txn->payload+0x41, 9 ));   // print the writable signer
    FD_LOG_HEXDUMP_NOTICE(( "txn's ro acc in treap", cur->txn->payload+0xa0, 8 ));   // print the read account
  }
  // Print bundle treap
  treap_t * bundle_treap = &ctx->pack->pending_bundles[ 0 ];
  /**/      prev         = treap_idx_null();
  for( treap_rev_iter_t _cur = treap_rev_iter_init( bundle_treap, pool ); !treap_rev_iter_done( _cur ); _cur=prev ) {
    /* Capture next so that we can delete while we iterate. */
    prev = treap_rev_iter_next( _cur, pool );
    fd_pack_ord_txn_t * cur = treap_rev_iter_ele( _cur, pool );
    FD_LOG_HEXDUMP_NOTICE(( "txn's w signer in bundle treap", cur->txn->payload+0x41, 9 ));   // print the writable signer
    FD_LOG_HEXDUMP_NOTICE(( "txn's ro acc in bundle treap", cur->txn->payload+0xa0, 8 ));   // print the read account
  }
  FD_LOG_NOTICE(( "print_txn_treap end-------------------------" ));
}

static void
print_txn_ref_treap( txn_ref_treap_t * treap,
                     txn_ref_t       * pool ) {
  FD_LOG_NOTICE(( "txn_ref_treap-------------------------" ));
  txn_ref_treap_rev_iter_t prev      = txn_ref_treap_idx_null();
  for( txn_ref_treap_rev_iter_t _cur = txn_ref_treap_rev_iter_init( treap, pool ); !txn_ref_treap_rev_iter_done( _cur ); _cur=prev ) {
    /* Capture next so that we can delete while we iterate. */
    prev = txn_ref_treap_rev_iter_next( _cur, pool );
    txn_ref_t * cur = txn_ref_treap_rev_iter_ele( _cur, pool );
    FD_LOG_NOTICE(( "cur prio: %lf, txn_i: %d", cur->prio, cur->txn_i ));
  }
  FD_LOG_NOTICE(( "txn_ref_treap end-------------------------" ));
}

/*************** Callbacks for selecting an input/output link ****************/

static void
txn_select_in_link( test_link_t   ** test_links,
                    test_ctx_t    *  test_ctx,
                    fd_pack_ctx_t *  ctx ) {
  if( test_ctx->locals->txn_i<MAX_TEST_TXNS ){
    test_ctx->in_link = test_links[ TEST_LINK_RESOLV_PACK ];
  } else if( ctx->leader_slot==ULONG_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_POH_PACK ];
  } else {
    test_ctx->in_link = NULL;
  }
}

static void
txn_select_out_link( test_link_t   ** test_links,
                     test_ctx_t    *  test_ctx,
                     fd_pack_ctx_t *  ctx FD_PARAM_UNUSED ) {
  if( test_ctx->locals->curr_leader_slot!=ULONG_MAX && test_ctx->locals->txn_in_pack ) {
    test_ctx->out_link = test_links[ TEST_LINK_PACK_BANK ];
  } else {
    test_ctx->out_link = NULL;
  }
}

static void
bundle_select_in_link( test_link_t   ** test_links,
                       test_ctx_t    *  test_ctx,
                       fd_pack_ctx_t *  ctx FD_PARAM_UNUSED ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->bundle_txn_rcvd < locals->txn_per_bundle ) {
    test_ctx->in_link = test_links[ TEST_LINK_RESOLV_PACK ];
  } else if( locals->curr_leader_slot==ULONG_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_POH_PACK ];
  } else if( locals->rebate_ref.ib_result==INT_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_BANK_PACK ];
  } else {
    test_ctx->in_link = NULL;
  }
}

static void
bundle_select_out_link( test_link_t   ** test_links,
                        test_ctx_t    *  test_ctx,
                        fd_pack_ctx_t *  ctx FD_PARAM_UNUSED ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->bundle_txn_rcvd < locals->txn_per_bundle ||
      locals->curr_leader_slot==ULONG_MAX ) {
    test_ctx->out_link = NULL;
  } else if( locals->rebate_ref.ib_result!=INT_MAX ) {
    test_ctx->out_link = test_links[ TEST_LINK_PACK_BANK ];
  }
}

static void
stress_txn_select_in_link( test_link_t   ** test_links,
                           test_ctx_t    *  test_ctx,
                           fd_pack_ctx_t *  ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->stress_test_published<locals->stress_test_target ) {
    test_ctx->in_link = test_links[ TEST_LINK_RESOLV_PACK ];
  } else if ( ctx->leader_slot==ULONG_MAX && locals->txn_in_pack ) {
    test_ctx->in_link = test_links[ TEST_LINK_POH_PACK ];
  } else {
    test_ctx->in_link = NULL;
  }
}

static void
stress_txn_select_out_link( test_link_t   ** test_links,
                            test_ctx_t    *  test_ctx,
                            fd_pack_ctx_t *  ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->stress_test_published>=locals->stress_test_target &&
      ctx->leader_slot!=ULONG_MAX && locals->txn_in_pack ) {
    test_ctx->out_link = test_links[ TEST_LINK_PACK_BANK ];
  } else {
    test_ctx->out_link = NULL;
  }
}

static void
overrun_txn_select_in_link( test_link_t   ** test_links,
                            test_ctx_t    *  test_ctx,
                            fd_pack_ctx_t *  ctx ) {
  if( test_links[ TEST_LINK_RESOLV_PACK ]->cons_seq==ULONG_MAX ||
      test_ctx->is_overrun ) {
    test_ctx->in_link = test_links[ TEST_LINK_RESOLV_PACK ];
  } else if ( ctx->leader_slot==ULONG_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_POH_PACK ];
  } else {
    test_ctx->in_link = NULL;
  }
}

static void
overrun_txn_select_out_link( test_link_t   ** test_links,
                             test_ctx_t    *  test_ctx,
                             fd_pack_ctx_t *  ctx ) {
  if( ctx->leader_slot==ULONG_MAX ||
      !test_ctx->locals->txn_in_pack ) {
    test_ctx->out_link = NULL;
  } else {
    test_ctx->out_link = test_links[ TEST_LINK_PACK_BANK ];
  }
}

static void
overrun_bundle_select_in_link( test_link_t   ** test_links,
                               test_ctx_t    *  test_ctx,
                               fd_pack_ctx_t *  ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->bundle_txn_rcvd < locals->txn_per_bundle ||
      test_ctx->is_overrun ) {
    test_ctx->in_link = test_links[ TEST_LINK_RESOLV_PACK ];
  } else if ( ctx->leader_slot==ULONG_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_POH_PACK ];
  } else if( locals->rebate_ref.ib_result==INT_MAX ) {
    test_ctx->in_link = test_links[ TEST_LINK_BANK_PACK ];
  } else {
    test_ctx->in_link = NULL;
  }
}

static void
overrun_bundle_select_out_link( test_link_t  ** test_links,
                               test_ctx_t    *  test_ctx,
                               fd_pack_ctx_t *  ctx FD_PARAM_UNUSED ) {
  if( test_ctx->locals->rebate_ref.ib_result!=INT_MAX &&
      test_ctx->locals->txn_in_pack ) {
    test_ctx->out_link = test_links[ TEST_LINK_PACK_BANK ];
  } else {
    test_ctx->out_link = NULL;
  }
}

/************************** before_credit verifier *************************/

static int
bc_check( test_ctx_t * test_ctx,
          fd_pack_ctx_t * ctx ) {
  if( !test_ctx->locals->bundle_id && ctx->cur_spot!=NULL ) {
    FD_LOG_WARNING(( "overrun frag not cleaned up" ));
    return -1;
  }
  return 0;
}

/************************** pack-bank out verifier *************************/
/* Verify the output of pack-bank link */
static int
bank_out_check( test_ctx_t     * test_ctx,
                fd_pack_ctx_t  * ctx ) {
  /* TODO: verify that we have actually timed out on the current leader slot */
  if( ctx->leader_slot==ULONG_MAX ) {
    // FD_LOG_NOTICE(( "bank_out_check-timed out" ));
    return 0;
  }

  tile_test_locals_t * locals = test_ctx->locals;

  fd_frag_meta_t * mline   = test_ctx->out_link->mcache + fd_mcache_line_idx( test_ctx->out_link->prod_seq, test_ctx->out_link->depth );
  ulong            out_mem = (ulong)fd_chunk_to_laddr( (void *)test_ctx->out_link->base, test_ctx->out_link->chunk ) + mline->ctl;

  if( locals->bundle_id && !locals->rebate_checked ) {
    // TODO: verify the content of IB txn
    if( !mline->sz ) {
      FD_LOG_WARNING(( "crank transaction not scheduled" ));
      return -1;
    }

    fd_fseq_update( ctx->bank_current[ 0 ], ctx->bank_expect[ 0 ] );
    test_ctx->out_link->prod_seq   = fd_seq_inc( test_ctx->out_link->prod_seq, 1 );
    test_ctx->out_link->chunk      = fd_dcache_compact_next( test_ctx->out_link->chunk, mline->sz, test_ctx->out_link->chunk0, test_ctx->out_link->wmark );
    locals->rebate_checked = 1;
    locals->txn_in_pack--;
    return 0;
  }

  ulong txn_out_cnt = (mline->sz-sizeof(fd_microblock_bank_trailer_t))/sizeof(fd_txn_p_t);
  if( locals->txn_cnt && !mline->sz ) {
    FD_LOG_WARNING(( "mline: %p, prod_seq: %lu sz: %u, chunk: %lu, chunk0: %lu", (void *)mline, test_ctx->out_link->prod_seq, mline->sz, test_ctx->out_link->chunk, test_ctx->out_link->chunk0 ));
    FD_LOG_WARNING(( "no transaction scheduled" ));
    return -1;
  }

  if( txn_out_cnt!=locals->txn_cnt ) {
    FD_LOG_WARNING(( "mline: %p, sz: %u, bank out mem: %p, chunk: %lu, chunk0: %lu", (void *)mline, mline->sz, (void *)out_mem, test_ctx->out_link->chunk, test_ctx->out_link->chunk0 ));
    FD_LOG_WARNING(( "test_ctx->txn_cnt: %lu, txn_out_cnt: %lu", locals->txn_cnt, txn_out_cnt ));
    FD_LOG_WARNING(( "transaction out cnt unmatched" ));
    return -1;
  }

  fd_txn_p_t * txnp_out = (fd_txn_p_t *)out_mem;
  ulong ref_i = locals->txn_ref_i;
  if( locals->is_stress_test ) {
    txn_ref_treap_rev_iter_t cur_iter = txn_ref_treap_rev_iter_init( locals->txn_ref_treap, locals->txn_ref_pool );
    txn_ref_t              * cur_ref  = txn_ref_treap_rev_iter_ele(      cur_iter,              locals->txn_ref_pool );
    ref_i = (ulong)cur_ref->txn_i;

    txn_ref_treap_idx_remove( locals->txn_ref_treap,  cur_iter, locals->txn_ref_pool );
    txn_ref_pool_idx_release(  locals->txn_ref_pool, cur_iter );
  } else {
    locals->txn_ref_i = locals->txn_ref_i+locals->txn_cnt;
  }

  FD_TEST( ref_i+locals->txn_cnt<=MAX_TEST_TXNS );

  for( ulong i=0; i<locals->txn_cnt; i++ ){
    fd_txn_e_t * txne_out_ref = &txn_scratch[ ref_i ];
    fd_txn_p_t * txnp_out_ref = txne_out_ref->txnp;
    ulong payload_sz_ref  = txnp_sz[ ref_i ];
    ulong txn_t_sz_ref    = txnt_sz[ ref_i ];

    if( ( txnp_out->payload_sz!=payload_sz_ref ) ||
        !fd_memeq( txnp_out_ref, txnp_out, txnp_out->payload_sz ) ) {
      FD_LOG_WARNING(( "mline: %p, sz: %u, bank out mem: %p, chunk: %lu, chunk0: %lu", (void *)mline, mline->sz, (void *)out_mem, test_ctx->out_link->chunk, test_ctx->out_link->chunk0 ));
      FD_LOG_HEXDUMP_WARNING(( "txnp_out_ref", txnp_out_ref, payload_sz_ref       ));
      FD_LOG_HEXDUMP_WARNING(( "txnp_out",     txnp_out,     txnp_out->payload_sz ));
      print_txn_treap( ctx );
      if( locals->txn_ref_treap && locals->txn_ref_pool ) print_txn_ref_treap( locals->txn_ref_treap, locals->txn_ref_pool );
      FD_LOG_WARNING(( "txn payload for %lu unmatched", i ));
      return -1;
    }
    fd_txn_t * txn_out     = TXN( txnp_out );
    fd_txn_t * txn_out_ref = TXN( txnp_out_ref );
    ulong txn_t_sz_out     = (ushort) fd_txn_footprint( txn_out->instr_cnt, txn_out->addr_table_adtl_cnt );
    if( ( txn_t_sz_out!=txn_t_sz_ref ) ||
        !fd_memeq( txn_out_ref, txn_out, txn_t_sz_ref ) ) {
      FD_LOG_WARNING(( "mline: %p, sz: %u, bank out mem: %p, chunk: %lu, chunk0: %lu", (void *)mline, mline->sz, (void *)out_mem, test_ctx->out_link->chunk, test_ctx->out_link->chunk0 ));
      FD_LOG_HEXDUMP_WARNING(( "txn",     txn_out_ref, txn_t_sz_ref ));
      FD_LOG_HEXDUMP_WARNING(( "txn_out", txn_out,     txn_t_sz_out ));
      FD_LOG_WARNING(( "txnt for %lu unmatched", i ));
      return -1;
    }
    // FD_LOG_HEXDUMP_NOTICE(( "txn out verified", txnp_out->payload+0xa0, 8 ));
    ref_i++;
    txnp_out++;
  }

  test_ctx->out_link->prod_seq = fd_seq_inc( test_ctx->out_link->prod_seq, 1 );
  test_ctx->out_link->chunk    = fd_dcache_compact_next( test_ctx->out_link->chunk, mline->sz, test_ctx->out_link->chunk0, test_ctx->out_link->wmark );

  locals->txn_in_pack-=locals->txn_cnt;
  // Mock the bank tile: it has handled the microblock
  fd_fseq_update( ctx->bank_current[ 0 ], ctx->bank_expect[ 0 ] );
  return 0;
}

/**************** resolv-pack link input generator/verifier *****************/

/* Publish a txn from the txn_scratch at txn_i to the resolve_pack in link's
   mcache and dcache. Return the published transaction's size */
static ulong
resolve_publish_txn( test_ctx_t * test_ctx,
                     test_link_t * resolv_pack_link ) {
  int txn_i = test_ctx->locals->txn_i;
  if( txn_i >= MAX_TEST_TXNS  ) return 0;
  // FD_LOG_NOTICE(( "resolve_publish_txn. txn_i: %d", txn_i ));
  fd_txn_e_t * txne    = &txn_scratch[ txn_i ];
  fd_txn_p_t * txnp    = txne->txnp;
  fd_txn_t   * txn     = TXN( txnp );
  txnp_sz[ txn_i ]     = txnp->payload_sz;
  txnt_sz[ txn_i ]     = (ushort) fd_txn_footprint( txn->instr_cnt, txn->addr_table_adtl_cnt );
  fd_txn_m_t * txnm    = (fd_txn_m_t *) fd_chunk_to_laddr( (void *)resolv_pack_link->base, resolv_pack_link->chunk );
  txnm->payload_sz     = (ushort) txnp_sz[ txn_i ];
  txnm->txn_t_sz       = (ushort) txnt_sz[ txn_i ];
  fd_memcpy( fd_txn_m_payload( txnm ), txnp,  txnm->payload_sz );
  fd_memcpy( fd_txn_m_txn_t(   txnm ), txn,   txnm->txn_t_sz   );
  ulong txnm_footprint = fd_txn_m_realized_footprint( txnm, 1, 0 );
  FD_TEST( txnm_footprint );
  fd_mcache_publish( resolv_pack_link->mcache, resolv_pack_link->depth, resolv_pack_link->prod_seq, 0, resolv_pack_link->chunk, txnm_footprint, 0, 0, 0 );

  txnm->block_engine.bundle_id = 0;

  test_ctx->locals->txn_cnt = 1;

  return txnm_footprint;
}

static ulong
resolve_publish_bundle( test_ctx_t * test_ctx,
                        test_link_t * resolv_pack_link ) {
  ulong txnm_footprint = resolve_publish_txn( test_ctx, resolv_pack_link );
  tile_test_locals_t * locals = test_ctx->locals;
  if( txnm_footprint ) {
    fd_txn_m_t * txnm    = (fd_txn_m_t *) fd_chunk_to_laddr( (void *)resolv_pack_link->base, resolv_pack_link->chunk );
    txnm->block_engine.bundle_id      = locals->bundle_id;
    txnm->block_engine.bundle_txn_cnt = locals->txn_per_bundle;

    fd_memcpy( txnm->block_engine.commission_pubkey, block_engine_commission_pk, 32 );
    txnm->block_engine.commission = block_engine_commission_pct;
  }
  test_ctx->locals->txn_cnt = test_ctx->locals->txn_per_bundle;
  return txnm_footprint;
}

/* To simulate overrun, we increment seq by depth after publishing a txn.
    upstream_produce will increment seq by 1 later.
    So resolv_pack_link->seq==resolv_pack_link->depth+1 after call to upstream_produce.
  */
static ulong
resolve_publish_txn_overrun( test_ctx_t  * test_ctx,
                             test_link_t * resolv_pack_link ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( test_ctx->is_overrun ) {
    locals->txn_i++;
    locals->txn_ref_i++;
  }
  ulong frag_sz = resolve_publish_txn( test_ctx, resolv_pack_link );
  if( resolv_pack_link->prod_seq<resolv_pack_link->depth ) {
    resolv_pack_link->prod_seq = fd_seq_inc( resolv_pack_link->prod_seq, resolv_pack_link->depth );
  }
  return frag_sz;
}

static ulong
resolve_publish_bundle_overrun( test_ctx_t  * test_ctx,
                                test_link_t * resolv_pack_link  ){
  tile_test_locals_t * locals = test_ctx->locals;
  if( test_ctx->is_overrun ) {
    locals->txn_ref_i   += locals->bundle_txn_rcvd+1; // skip the inserted txns and the txn that got overrun
    locals->txn_in_pack -= locals->bundle_txn_rcvd;   // overrun txns should be removed from pack

    // next bundle
    locals->txn_i++;
    locals->bundle_id++;
    locals->bundle_txn_rcvd = 0;
  }
  ulong frag_sz = resolve_publish_bundle( test_ctx, resolv_pack_link );
  if( locals->bundle_txn_rcvd==locals->txn_per_bundle-2 &&
      resolv_pack_link->prod_seq<resolv_pack_link->depth ) {
    resolv_pack_link->prod_seq = fd_seq_inc( resolv_pack_link->prod_seq, resolv_pack_link->depth );
  }
  return frag_sz;
}

/* Verify the context state is set correctly in during_frag */
static int
resolve_df_check( test_ctx_t    * test_ctx,
                  fd_pack_ctx_t * ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  int ref_i = locals->txn_i;
  fd_txn_e_t * txne = &txn_scratch[ ref_i ];
  fd_txn_p_t * txnp = txne->txnp;
  if( !ctx->cur_spot ) {
    FD_LOG_WARNING(( "insert txn init failed" ));
    return -1;
  }
  if( ctx->cur_spot->txnp->payload_sz!=txnp_sz[ ref_i ]  ||
      !fd_memeq( ctx->cur_spot->txnp->payload, txnp,  txnp_sz[ ref_i ] ) ||
      !fd_memeq( TXN(ctx->cur_spot->txnp), TXN(txnp), txnt_sz[ ref_i ] ) ) {
    FD_LOG_WARNING(( "pack_ctx payload_sz: %lu, txnp_sz[%d]: %lu", ctx->cur_spot->txnp->payload_sz, ref_i, txnp_sz[ ref_i ]));
    FD_LOG_HEXDUMP_WARNING(( "pack_ctx payload", ctx->cur_spot->txnp->payload, ctx->cur_spot->txnp->payload_sz ));
    FD_LOG_HEXDUMP_WARNING(( "payload", txnp, txnp_sz[ ref_i ] ));
    print_txn_treap( ctx );
    if( locals->txn_ref_treap && locals->txn_ref_pool  ) print_txn_ref_treap( locals->txn_ref_treap, locals->txn_ref_pool );
    FD_LOG_WARNING(( "pack_ctx txn payload unmatched" ));
    return -1;
  }
  if( locals->bundle_id ) {
    if( !ctx->is_bundle ) {
      FD_LOG_WARNING(( "pack_ctx did not recognize the bundle txn" ));
      return -1;
    }
    if( ctx->current_bundle->id!=locals->bundle_id ) {
      FD_LOG_WARNING(( "bundle id unmatched: %lu, %lu", ctx->current_bundle->id, locals->bundle_id ));
      return -1;
    }
    if( ctx->current_bundle->txn_cnt!=locals->txn_per_bundle ) {
      FD_LOG_WARNING(( "bundle txn cnt unmatched: %lu, %lu", ctx->current_bundle->txn_cnt, locals->txn_per_bundle ));
      return -1;
    }
    if( ctx->current_bundle->txn_received!=locals->bundle_txn_rcvd ) {
      FD_LOG_WARNING(( "bundle txn recvd cnt unmatched: %lu, %lu", ctx->current_bundle->txn_received, locals->bundle_txn_rcvd ));
      return -1;
    }
    if( ctx->current_bundle->min_blockhash_slot!=locals->in_sig ) {
      FD_LOG_WARNING(( "bundle txn signature unmatched: %lu, %lu", ctx->current_bundle->min_blockhash_slot, locals->in_sig ));
      return -1;
    }
    if( ctx->blk_engine_cfg->commission!=block_engine_commission_pct ) {
      FD_LOG_WARNING(( "bundle txn commission percentage unmatched: %lu, %d", ctx->blk_engine_cfg->commission, block_engine_commission_pct ));
      return -1;
    }
    if( !fd_memeq( ctx->blk_engine_cfg->commission_pubkey->b, block_engine_commission_pk, 32 ) ) {
      FD_LOG_HEXDUMP_WARNING(( "identity key in pack_ctx", ctx->blk_engine_cfg->commission_pubkey->b, 32 ));
      FD_LOG_HEXDUMP_WARNING(( "reference identity key",   block_engine_commission_pk,                32 ));
      FD_LOG_WARNING(("commission public key unmatched" ));
      return -1;
    }
  }
  return 0;
}

static int
resolve_af_update( test_ctx_t    * test_ctx,
                   fd_pack_ctx_t * ctx FD_PARAM_UNUSED ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( locals->is_stress_test ) {
    ulong pool_idx                 = txn_ref_pool_idx_acquire( locals->txn_ref_pool );
    locals->txn_ref_pool[ pool_idx ].prio  = txn_prio[ locals->txn_i ];
    locals->txn_ref_pool[ pool_idx ].txn_i = locals->txn_i;
    txn_ref_treap_idx_insert( locals->txn_ref_treap, pool_idx, locals->txn_ref_pool );
    locals->stress_test_published++;
  }

  locals->txn_i++;
  if( locals->wrap_around ) locals->txn_i = locals->txn_i % MAX_TEST_TXNS;
  if( locals->bundle_id ) locals->bundle_txn_rcvd++;
  locals->txn_in_pack++;
  locals->last_successful_insert = fd_tickcount();
  return 0;
}

/******************* poh-pack link input generator/verifier *******************/
static ulong
poh_publish( test_ctx_t  * test_ctx,
             test_link_t * poh_pack_link ){
  tile_test_locals_t * locals = test_ctx->locals;

  locals->become_leader_ref = (fd_became_leader_t) {
    .slot_start_ns           = fd_log_wallclock(),
    .slot_end_ns             = fd_log_wallclock() + SLOT_DURATION_NS,
    .max_microblocks_in_slot = MAX_MICROBLOCKS_PER_SLOT,
    .ticks_per_slot          = TICKS_PER_SLOT,
    .epoch                   = epoch,
    .limits                  = { FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND,
                                 FD_PACK_MAX_VOTE_COST_PER_BLOCK_LOWER_BOUND,
                                 FD_PACK_MAX_WRITE_COST_PER_ACCT_LOWER_BOUND }
  };
  if( locals->crank_enabled ) {
    locals->become_leader_ref.bundle->config->discriminator       = 0x82ccfa1ee0aa0c9bUL;
    locals->become_leader_ref.bundle->config->tip_receiver->b[1]  = 1;
    locals->become_leader_ref.bundle->config->block_builder->b[2] = 1;
  }
  fd_memcpy( fd_chunk_to_laddr( (void *)poh_pack_link->base, poh_pack_link->chunk ), &locals->become_leader_ref, sizeof(fd_became_leader_t) );
  locals->curr_leader_slot    = leader_slot;
  leader_slot = (leader_slot + 1) % TRANSACTION_LIFETIME_SLOTS;   /* no expired txnes */
  return sizeof(fd_became_leader_t);
}

static ulong
poh_make_sig( test_ctx_t  * test_ctx,
              test_link_t * poh_pack_link FD_PARAM_UNUSED ) {
  return fd_disco_poh_sig( test_ctx->locals->curr_leader_slot, POH_PKT_TYPE_BECAME_LEADER, 0 );
}

static int
poh_df_check( test_ctx_t * test_ctx,
              fd_pack_ctx_t * ctx ) {
  if( !fd_memeq( ctx->_became_leader, &test_ctx->locals->become_leader_ref, sizeof(fd_became_leader_t) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "_became_leader in ctx",     ctx->_became_leader,                  sizeof(fd_became_leader_t) ));
    FD_LOG_HEXDUMP_WARNING(( "became_leader in test_ctx", &test_ctx->locals->become_leader_ref, sizeof(fd_became_leader_t) ));
    FD_LOG_WARNING(( "_became_leader struct unmatch" ));
    return -1;
  }
  return 0;
}

/* Fake sign an IB txn ahead of time so that mcache_wait in
   fd_keyguard_client_sign would not block */
static void
fake_sign_IB_txn( fd_pack_ctx_t * ctx ) {
  fd_keyguard_client_t * client = ctx->crank->keyguard_client;
  ulong fd_mcache_wait_seq_expected = client->response_seq;
  fd_frag_meta_t * fd_mcache_wait_mline = client->response + fd_mcache_line_idx( fd_mcache_wait_seq_expected, client->response_depth );
  if( !fd_mcache_wait_mline->chunk )  {
    fd_mcache_wait_mline->chunk = (uint)ctx->crank->keyguard_client[0].response_chunk0;
  }
  else {
    fd_mcache_wait_mline->chunk = (uint)fd_dcache_compact_next( fd_mcache_wait_mline->chunk, 64UL, ctx->crank->keyguard_client[0].response_chunk0, ctx->crank->keyguard_client[0].response_wmark );
  }
  fd_mcache_wait_mline->seq = fd_mcache_wait_seq_expected;
}

static int
poh_af_check( test_ctx_t * test_ctx,
              fd_pack_ctx_t * ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( ctx->leader_slot!=locals->curr_leader_slot ){
    FD_LOG_WARNING(( "leader_slot unmatched. ctx->leader_slot: %lu, test_ctx->curr_leader_slot: %lu", ctx->leader_slot, locals->curr_leader_slot ));
    return -1;
  }
  if( locals->bundle_id &&
      locals->bundle_txn_rcvd == locals->txn_per_bundle &&
      locals->crank_enabled ) {
    fake_sign_IB_txn( ctx );
  }
  return 0;
}

/****************** bank-pack link input generator/verifier ******************/

/* Mock Bank (in link) tile by creating a rebate for IB, and the pack tile
   processes the frag to set the bundle state to ready. */
static ulong
bank_rebate_publish( test_ctx_t  * test_ctx,
                     test_link_t * bank_pack_link ) {
  test_ctx->locals->rebate_ref = (fd_pack_rebate_t){
    .ib_result = 1
  };
  fd_memcpy( fd_chunk_to_laddr( (void *)bank_pack_link->base, bank_pack_link->chunk ), &test_ctx->locals->rebate_ref, sizeof(fd_pack_rebate_t) );
  return sizeof(fd_pack_rebate_t);
}

static ulong
bank_rebate_make_sig( test_ctx_t  * test_ctx,
                      test_link_t * bank_pack_link FD_PARAM_UNUSED ) {
  return fd_disco_poh_sig_slot( fd_disco_poh_sig( test_ctx->locals->curr_leader_slot, POH_PKT_TYPE_BECAME_LEADER, 0UL ) );
}

static int
bank_rebate_df_check( test_ctx_t    * test_ctx,
                      fd_pack_ctx_t * ctx ) {
  if( ctx->pending_rebate_sz!=sizeof(fd_pack_rebate_t) ) {
    FD_LOG_WARNING(( "pending rebate size unmatched: %lu, %lu",ctx->pending_rebate_sz, sizeof(fd_pack_rebate_t) ));
    return -1;
  }
  if( !fd_memeq( ctx->rebate, &test_ctx->locals->rebate_ref, sizeof(fd_pack_rebate_t) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "rebate in ctx",      ctx->rebate,                   sizeof(fd_pack_rebate_t) ));
    FD_LOG_HEXDUMP_WARNING(( "rebate in test_ctx", &test_ctx->locals->rebate_ref, sizeof(fd_pack_rebate_t) ));
    FD_LOG_WARNING(( "rebate struct unmatch" ));
    return -1;
  }
  return 0;
}

static int
bank_rebate_af_check( test_ctx_t    * test_ctx,
                      fd_pack_ctx_t * ctx ) {
  tile_test_locals_t * locals = test_ctx->locals;
  if( ctx->leader_slot!=locals->curr_leader_slot ) {
    FD_LOG_WARNING(( "leader slot unmatched: %lu, %lu", ctx->leader_slot, locals->curr_leader_slot ));
    return -1;
  }
  if( ctx->pack->initializer_bundle_state!=FD_PACK_IB_STATE_READY ) {
    FD_LOG_WARNING(( "bundle state not ready" ));
    return -1;
  }
  locals->txn_in_pack++;  // IB txn inserted
  return 0;
}

/************************* Test Init Auxiliary Function ***********************/

static void
pack_find_in_idx( test_link_t   * test_link,
                  fd_pack_ctx_t * ctx ) {
  for( ulong i=0; i<sizeof(ctx->in)/sizeof(ctx->in[ 0 ]); i++ ) {
    if( ctx->in[ i ].mem == test_link->base ) {
        test_link->in_idx = i;
        break;
    }
  }
}


static void
populate_test_vectors( test_ctx_t * test_ctx FD_PARAM_UNUSED ) {
  const char empty_w_acc[1] = {0};

  /* Txn_i has priority strictly greater Txn_j if i<j,
     where priority is in (0,13.5] */
  for( ulong i=0; i<MAX_TEST_TXNS; i++ ) {
    double priority = MAX_PRIORITY - (double)i*0.2;
    fd_txn_e_t * txne = &txn_scratch[ i ];
    fd_txn_p_t * txnp = txne->txnp;
    make_transaction( txnp, i, 500U, 500U, priority, empty_w_acc, accs[ i ] );
    ++signer;
    txn_prio[ i ] = priority;
  }
}

/* Mock priviledged_init(...).
   Setup sign-in link, sign-out link, and keyswitch for cranking. */
static void
mock_privileged_init( fd_topo_t      * topo,
                      fd_topo_tile_t * tile ) {
  /* For now, pretend we only have one bank tile, so that
     ctx->bank_cnt = 1 and ctx->bank_idle_bitset = 1 */
  tile->pack.bank_tile_count = 1;

  FD_TEST( CRANK_WKSP_SIZE > fd_keyswitch_footprint() );
  ulong part_max = fd_wksp_part_max_est( CRANK_WKSP_SIZE, 64UL );
  ulong data_max = fd_wksp_data_max_est( CRANK_WKSP_SIZE, part_max );
  FD_TEST( CRANK_WKSP_SIZE > fd_wksp_footprint( part_max, 1UL ) );
  fd_wksp_t * crank_wksp = fd_wksp_join( fd_wksp_new( (void *)crank_scratch, "crank_wksp", 1234U, part_max, data_max ) );
  fd_shmem_join_anonymous( "crank_wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, crank_wksp, crank_scratch, FD_SHMEM_NORMAL_PAGE_SZ, sizeof(crank_scratch)>>FD_SHMEM_NORMAL_LG_PAGE_SZ );
  fd_topob_wksp( topo, "crank_wksp" );

  /* Sign in link */
  fd_topo_link_t * sign_in_link       = fd_topob_link( topo, "sign_pack", "crank_wksp", 128, 0, 1UL );
  void           * sign_in_mcache_mem = fd_wksp_alloc_laddr( crank_wksp, fd_mcache_align(), fd_mcache_footprint( 128, 0UL ), 1UL );
  sign_in_link->mcache                = fd_mcache_join( fd_mcache_new( sign_in_mcache_mem, 128, 0UL, 0UL ) );
  FD_TEST( sign_in_link->mcache );
  ulong  sign_in_dcache_sz  = fd_dcache_req_data_sz( 3840, 128UL, 1UL, 1 );
  void * sign_in_dcache_mem = fd_wksp_alloc_laddr( crank_wksp, fd_dcache_align(), fd_dcache_footprint( sign_in_dcache_sz, 0UL ), 1UL );
  sign_in_link->dcache      = fd_dcache_join( fd_dcache_new( sign_in_dcache_mem, sign_in_dcache_sz, 0UL ) );
  FD_TEST( sign_in_link->dcache );
  fd_topob_tile_in( topo, "pack", 0UL, "crank_wksp", "sign_pack", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  FD_TEST( fd_topo_find_tile_in_link ( topo, tile, "sign_pack", tile->kind_id )!=ULONG_MAX );

  /* Sign out link */
  fd_topo_link_t * sign_out_link       = fd_topob_link( topo, "pack_sign", "crank_wksp", 128, 0, 1UL );
  void           * sign_out_mcache_mem = fd_wksp_alloc_laddr( crank_wksp, fd_mcache_align(), fd_mcache_footprint( 128, 0UL ), 1UL );
  sign_out_link->mcache                = fd_mcache_join( fd_mcache_new( sign_out_mcache_mem, 128, 0UL, 0UL ) );
  FD_TEST( sign_out_link->mcache );
  ulong  sign_out_dcache_sz  = fd_dcache_req_data_sz( 3840UL, 128UL, 1UL, 1 );
  void * sign_out_dcache_mem = fd_wksp_alloc_laddr( crank_wksp, fd_dcache_align(), fd_dcache_footprint( sign_out_dcache_sz, 0UL ), 1UL );
  sign_out_link->dcache      = fd_dcache_join( fd_dcache_new( sign_out_dcache_mem, sign_out_dcache_sz, 0UL ) );
  sign_out_link->mtu         = 3840UL;
  FD_TEST( sign_out_link->dcache );
  fd_topob_tile_out( topo, "pack", 0UL, "pack_sign", 0UL );
  FD_TEST( fd_topo_find_tile_out_link( topo, tile, "pack_sign", tile->kind_id )!=ULONG_MAX );

  /* keyswitch*/
  void      * keyswitch_mem     = fd_wksp_alloc_laddr( crank_wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  FD_TEST( keyswitch_mem );
  fd_topo_obj_t * keyswitch_obj = fd_topob_obj( topo, "keyswitch", "crank_wksp" );
  tile->keyswitch_obj_id        = keyswitch_obj->id;
  topo->objs[ keyswitch_obj->id ].offset = (ulong)keyswitch_mem - (ulong)crank_wksp;
  topo->workspaces[ keyswitch_obj->wksp_id ].wksp = crank_wksp;
  FD_TEST( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id )==keyswitch_mem );
  FD_TEST( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );

  /* context */
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_pack_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );

  fd_memcpy( tile->pack.bundle.tip_distribution_program_addr, tip_distribution_program_addr, sizeof(fd_acct_addr_t) );
  fd_memcpy( tile->pack.bundle.tip_payment_program_addr,      tip_payment_program_addr,      sizeof(fd_acct_addr_t) );
  fd_memcpy( tile->pack.bundle.tip_distribution_authority,    merkle_root_authority_addr,    sizeof(fd_acct_addr_t) );
  tile->pack.bundle.commission_bps = 0UL;
  tile->pack.schedule_strategy     = 0UL;   // "PRF" mode

  fd_memcpy( ctx->crank->vote_pubkey->b,     validator_vote_acct_addr, sizeof(fd_acct_addr_t) );
  fd_memcpy( ctx->crank->identity_pubkey->b, validator_identity_pk,    sizeof(fd_acct_addr_t) );

  tile->pack.bundle.enabled = 1;
}

/* This function should be called before each test loop. It resets the pack's
   test environment in addition to reset_test_env, and calls unprivileged_init
   to reset the pack context */
static void
pack_reset( fd_topo_t      * topo,
            fd_topo_tile_t * tile,
            test_ctx_t     * test_ctx,
            fd_pack_ctx_t  * ctx,
            ulong txn_per_bundle,
            ulong stress_test_target ) {
  tile_test_locals_t * locals = test_ctx->locals;

  locals->curr_leader_slot     = ULONG_MAX;
  locals->rebate_ref.ib_result = INT_MAX;
  if( txn_per_bundle ) {
    locals->bundle_id      = 1;
    locals->txn_per_bundle = txn_per_bundle;
    locals->crank_enabled  = 1;
  }
  if( stress_test_target ) {
    locals->is_stress_test      = 1;
    locals->stress_test_target  = stress_test_target;
    locals->wrap_around   = 1;
    locals->txn_ref_treap = txn_ref_treap_join( txn_ref_treap_new( locals->_treap, MAX_TEST_PENDING_TXNS ) );
    if( sizeof(txn_ref_pool_scratch) < txn_ref_pool_footprint( MAX_TEST_PENDING_TXNS ) ) {
      FD_LOG_ERR(( "txn_ref_pool_scratch size: %lu, needed: %lu", sizeof(txn_ref_pool_scratch), txn_ref_pool_footprint( MAX_TEST_PENDING_TXNS ) ));
    }
    locals->txn_ref_pool  = txn_ref_pool_join(   txn_ref_pool_new(  txn_ref_pool_scratch,       MAX_TEST_PENDING_TXNS ) );
    FD_TEST( locals->txn_ref_treap );
    FD_TEST( locals->txn_ref_pool  );
  }
  // Reset the bank_current so that we start with fresh bank's consumer seq and unprivilege_init won't crash
  *ctx->bank_current[ 0 ] = ULONG_MAX;
  unprivileged_init( topo, tile );

  /* TODO: allow waiting between scheduling microblocks.
    Do not change wait_duration_ticks[ 0 ] since we wait for ULONG_MAX if no transactions are available. That's why we start at 1. */
  for( ulong i=1; i<sizeof(ctx->wait_duration_ticks)/sizeof(ctx->wait_duration_ticks[0]); i++ ) ctx->wait_duration_ticks[ i ]=10;
}

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  /* Leave the rng for future use */
  uint rng_seed = fd_env_strip_cmdline_uint( &argc, &argv, "--rng-seed", NULL, 0U );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  /* Initialize tile unit test */
  char const * default_topo_config_path  = TEST_DEFAULT_TOPO_CONFIG_PATH;
  char const * override_topo_config_path = NULL;
  char const * user_topo_config_path     = NULL;
  int          netns                     = 0;
  int          is_firedancer             = TEST_IS_FIREDANCER;
  int          is_local_cluster          = 0;
  fd_topo_tile_t * pack_tile = fd_tile_unit_test_init( default_topo_config_path, override_topo_config_path, user_topo_config_path,
                                                       netns, is_firedancer, is_local_cluster,
                                                       fd_topo_initialize, &fd_tile_pack, config );
  FD_TEST( pack_tile );
  fd_metrics_register( fd_metrics_new( metrics_scratch, 10, 10 ) );

  fd_pack_ctx_t * ctx = fd_topo_obj_laddr( &config->topo, pack_tile->tile_obj_id );
  FD_TEST( ctx );

  test_ctx_t test_ctx = {0};

  /* [tile-unit-test] unprivileged_init. */
  mock_privileged_init( &config->topo, pack_tile );
  unprivileged_init(    &config->topo, pack_tile );

  /* resolv-pack link */
  test_link_t resolv_pack_link = {0};
  init_test_link( &config->topo, &resolv_pack_link, "resolv_pack", ctx,
                  pack_find_in_idx,
                  resolve_publish_txn, NULL,
                  NULL, NULL, NULL, resolve_df_check, resolve_af_update );
  /* poh-pack link */
  test_link_t poh_pack_link = {0};
  init_test_link( &config->topo, &poh_pack_link, "poh_pack", ctx,
                  pack_find_in_idx,
                  poh_publish, poh_make_sig,
                  NULL, NULL, NULL, poh_df_check, poh_af_check );
  /* bank-pack link */
  test_link_t bank_pack_link = {0};
  init_test_link( &config->topo, &bank_pack_link, "bank_pack", ctx,
                  pack_find_in_idx,
                  bank_rebate_publish, bank_rebate_make_sig,
                  NULL, NULL, NULL, bank_rebate_df_check, bank_rebate_af_check );
  /* pack-bank link */
  test_link_t pack_bank_link = {0};
  init_test_link( &config->topo, &pack_bank_link, "pack_bank", ctx,
                  pack_find_in_idx,
                  NULL, NULL,
                  bc_check, bank_out_check, NULL, NULL, NULL );
  /* pack-poh link */
  test_link_t pack_poh_link = {0};
  init_test_link( &config->topo, &pack_poh_link, "pack_poh", ctx,
                  pack_find_in_idx,
                  NULL, NULL,
                  bc_check, NULL, NULL, NULL, NULL );

  test_link_t * test_links[ 5 ] = { 0 };
  test_links[ TEST_LINK_RESOLV_PACK ] = &resolv_pack_link;
  test_links[ TEST_LINK_POH_PACK    ] = &poh_pack_link;
  test_links[ TEST_LINK_BANK_PACK   ] = &bank_pack_link;
  test_links[ TEST_LINK_PACK_BANK   ] = &pack_bank_link;
  test_links[ TEST_LINK_PACK_POH    ] = &pack_poh_link;

  ulong stem_min_cr_avail         = ULONG_MAX;
  ulong stem_mcache_depth[2]      = { pack_bank_link.depth,  pack_poh_link.depth  };
  ulong stem_cr_avil[2]           = { ULONG_MAX,             ULONG_MAX            };
  ulong stem_seq[2]               = { 0,                     0                    };
  fd_frag_meta_t * stem_mcache[2] = { pack_bank_link.mcache, pack_poh_link.mcache };
  fd_stem_context_t stem = {
    .min_cr_avail = &stem_min_cr_avail,
    .cr_avail     = stem_cr_avil,
    .depths       = stem_mcache_depth,
    .mcaches      = stem_mcache,
    .seqs         = stem_seq
  };

  /* Populate txn_scratch */
  populate_test_vectors( &test_ctx );

  FD_LOG_NOTICE(( "[tile-unit-test] Stress test txn I/O" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_txn, NULL );
  reset_test_env( &test_ctx, &stem, test_links, stress_txn_select_in_link, stress_txn_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, 0, 1000 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 2200, 10 );

  FD_LOG_NOTICE(( "[tile-unit-test] Test bundle overrun" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_bundle_overrun, NULL );
  reset_test_env( &test_ctx, &stem, test_links, overrun_bundle_select_in_link, overrun_bundle_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, FD_PACK_MAX_TXN_PER_BUNDLE, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 20, 2 );

  FD_LOG_NOTICE(( "[tile-unit-test] Test txn overrun" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_txn_overrun, NULL );
  reset_test_env( &test_ctx, &stem, test_links, overrun_txn_select_in_link, overrun_txn_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, 0, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 7, 2 );

  /* Normal transaction loop */
  FD_LOG_NOTICE(( "[tile-unit-test] Normal transaction I/O" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_txn, NULL );
  reset_test_env( &test_ctx, &stem, test_links, txn_select_in_link, txn_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, 0, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, MAX_TEST_TXNS*3, 5 );

  /* Normal bundle loop */
  FD_LOG_NOTICE(( "[tile-unit-test] Bundle I/O" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_bundle, NULL );
  reset_test_env( &test_ctx, &stem, test_links, bundle_select_in_link, bundle_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, FD_PACK_MAX_TXN_PER_BUNDLE, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 8, 2 );

  /* Normal transaction loop again */
  FD_LOG_NOTICE(( "[tile-unit-test] Normal transaction I/O again" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_txn, NULL );
  reset_test_env( &test_ctx, &stem, test_links, txn_select_in_link, txn_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, 0, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, MAX_TEST_TXNS*3, 2 );

  FD_LOG_NOTICE(( "[tile-unit-test] Test txn overrun again" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_txn_overrun, NULL );
  reset_test_env( &test_ctx, &stem, test_links, overrun_txn_select_in_link, overrun_txn_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, 0, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 15, 2 );

  FD_LOG_NOTICE(( "[tile-unit-test] Test bundle overrun again" ));
  update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_bundle_overrun, NULL );
  reset_test_env( &test_ctx, &stem, test_links, overrun_bundle_select_in_link, overrun_bundle_select_out_link );
  pack_reset( &config->topo, pack_tile, &test_ctx, ctx, FD_PACK_MAX_TXN_PER_BUNDLE-1, 0 );
  tile_test_run( ctx, &stem, test_links, &test_ctx, 20, 2 );

  /* TODO enable once the crash behavior is corrected inside the pack tile */
  if( 0 ) {
    FD_LOG_NOTICE(( "[tile-unit-test] Test FD_PACK_MAX_TXN_PER_BUNDLE+1 txn per bundle" ));
    update_test_link_callback( &resolv_pack_link, CALLBACK_FN_PUB, resolve_publish_bundle, NULL );
    reset_test_env( &test_ctx, &stem, test_links, bundle_select_in_link, bundle_select_out_link );
    pack_reset( &config->topo, pack_tile, &test_ctx, ctx, FD_PACK_MAX_TXN_PER_BUNDLE+1, 0 );
    tile_test_run( ctx, &stem, test_links, &test_ctx, 8, 2 );
  }

  /* TODO: test should be expanded to use random tests */
  /* Tear down tile-unit-test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();

  return 0;
}
