#include "fd_bundle_crank.h"
#include "../../flamenco/runtime/fd_pubkey_utils.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

FD_STATIC_ASSERT( sizeof(fd_bundle_crank_tip_payment_config_t)==89UL, config_struct );

#define MEMO_PROGRAM_ID 0x05U,0x4aU,0x53U,0x5aU,0x99U,0x29U,0x21U,0x06U,0x4dU,0x24U,0xe8U,0x71U,0x60U,0xdaU,0x38U,0x7cU, \
                        0x7cU,0x35U,0xb5U,0xddU,0xbcU,0x92U,0xbbU,0x81U,0xe4U,0x1fU,0xa8U,0x40U,0x41U,0x05U,0x44U,0x8dU

static const fd_bundle_crank_3_t fd_bundle_crank_3_base[1] = {{

    .sig_cnt         =  1,
    ._sig_cnt        =  1,
    .ro_signed_cnt   =  0,
    .ro_unsigned_cnt =  5,
    .acct_addr_cnt   = 21,

    .system_program         = { SYS_PROG_ID            },
    .compute_budget_program = { COMPUTE_BUDGET_PROG_ID },
    .memo_program           = { MEMO_PROGRAM_ID        },

    .instr_cnt = 5,
    .compute_budget_instruction = {
        .prog_id = 16,
        .acct_cnt = 0,
        .data_sz = 5,
        .set_cu_limit = 2,
        .cus = 130000U
    },

    .init_tip_distribution_acct = {
        .prog_id = 20,
        .acct_cnt = 5,
        .acct_idx = { 9, 13, 15, 0, 19 },
        .data_sz = 43,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_INIT_TIP_DISTR },
    },

    .change_tip_receiver = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 11, 13, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0 },
        .data_sz = 8,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV }
    },

    .change_block_builder = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 13, 12, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0},
        .data_sz = 16,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD },
    },

    .memo = {
      .prog_id = 18,
      .acct_cnt = 0,
      .data_sz  = 3
    },

    /* Account addresses that depend on the network: */
    .tip_payment_accounts            = {{ 0 }},
    .tip_distribution_program_config =  { 0 },
    .tip_payment_program_config      =  { 0 },
    .tip_distribution_program        =  { 0 },
    .tip_payment_program             =  { 0 },

    /* Fields that depend on the validator configuration: */
    .authorized_voter       = { 0 },
    .validator_vote_account = { 0 },
    .memo.memo              = { 0 },
    .init_tip_distribution_acct.merkle_root_upload_authority = { 0 },
    .init_tip_distribution_acct.commission_bps               = 0,
    .init_tip_distribution_acct.bump                         = 0,

    /* Fields that vary each time: */
    .old_tip_receiver  = { 0 },
    .old_block_builder = { 0 },
    .new_tip_receiver  = { 0 },
    .new_block_builder = { 0 },
    .change_block_builder.block_builder_commission_pct = 0UL
}};

static const fd_bundle_crank_2_t fd_bundle_crank_2_base[1] = {{

    .sig_cnt         =  1,
    ._sig_cnt        =  1,
    .ro_signed_cnt   =  0,
    .ro_unsigned_cnt =  3,
    .acct_addr_cnt   = 19,

    .compute_budget_program = { COMPUTE_BUDGET_PROG_ID },
    .memo_program           = { MEMO_PROGRAM_ID        },

    .instr_cnt = 4,
    .compute_budget_instruction = {
        .prog_id = 16,
        .acct_cnt = 0,
        .data_sz = 5,
        .set_cu_limit = 2,
        .cus = 83000U
    },

    .change_tip_receiver = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 11, 13, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0 },
        .data_sz = 8,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV }
    },

    .change_block_builder = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 13, 12, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0},
        .data_sz = 16,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD },
    },

    .memo = {
      .prog_id = 18,
      .acct_cnt = 0,
      .data_sz = 3
    },

    /* Account addresses that depend on the network: */
    .tip_payment_accounts            = {{ 0 }},
    .tip_distribution_program_config =  { 0 },
    .tip_payment_program_config      =  { 0 },
    .tip_payment_program             =  { 0 },

    /* Fields that depend on the validator configuration: */
    .authorized_voter       = { 0 },
    .memo.memo              = { 0 },
    .validator_vote_account = { 0 },

    /* Fields that vary each time: */
    .old_tip_receiver  = { 0 },
    .old_block_builder = { 0 },
    .new_tip_receiver  = { 0 },
    .new_block_builder = { 0 },
    .change_block_builder.block_builder_commission_pct = 0UL
}};

static const fd_acct_addr_t null_addr = { 0 };

#define MAP_NAME pidx_map
#define MAP_T    fd_bundle_crank_gen_pidx_t
#define MAP_KEY_T   fd_acct_addr_t
#define MAP_MEMOIZE   0
#define MAP_QUERY_OPT 2 /* low hit rate */
#define MAP_LG_SLOT_CNT 5 /* 18 entries, space for 32 */
#define MAP_KEY_NULL          null_addr
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_addr)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))

#include "../../util/tmpl/fd_map.c"


#define EXPAND_ARR8(arr, i)  arr[(i)], arr[(i)+1], arr[(i)+2], arr[(i)+3], arr[(i)+4], arr[(i)+5], arr[(i)+6], arr[(i)+7],
#define EXPAND_ARR32(arr, i) EXPAND_ARR8(arr, (i)) EXPAND_ARR8(arr, (i)+8) EXPAND_ARR8(arr, (i)+16) EXPAND_ARR8(arr, (i)+24)



fd_bundle_crank_gen_t *
fd_bundle_crank_gen_init( void                 * mem,
                          fd_acct_addr_t const * tip_distribution_program_addr,
                          fd_acct_addr_t const * tip_payment_program_addr,
                          fd_acct_addr_t const * validator_vote_acct_addr,
                          fd_acct_addr_t const * merkle_root_authority_addr,
                          char const *           scheduler_mode,
                          ulong                  commission_bps ) {
  fd_bundle_crank_gen_t * g = (fd_bundle_crank_gen_t *)mem;
  memcpy( g->crank3, fd_bundle_crank_3_base, sizeof(fd_bundle_crank_3_base) );
  memcpy( g->crank2, fd_bundle_crank_2_base, sizeof(fd_bundle_crank_2_base) );

  g->crank3->init_tip_distribution_acct.commission_bps = (ushort)commission_bps;
  memcpy( g->crank3->tip_distribution_program,                                tip_distribution_program_addr, 32UL );
  memcpy( g->crank3->tip_payment_program,                                     tip_payment_program_addr,      32UL );
  memcpy( g->crank3->validator_vote_account,                                  validator_vote_acct_addr,      32UL );
  memcpy( g->crank3->init_tip_distribution_acct.merkle_root_upload_authority, merkle_root_authority_addr,    32UL );

  /* What we want here is just an strncpy, but the compiler makes it
     really hard to use strncpy to make a deliberately potentially
     unterminated string.  Rather than fight the compiler, we basically
     hand-do it. */
  int is_nul;
  is_nul = 0      || (!scheduler_mode[0]);    g->crank3->memo.memo[0] = is_nul ? '\0' : scheduler_mode[0];
  is_nul = is_nul || (!scheduler_mode[1]);    g->crank3->memo.memo[1] = is_nul ? '\0' : scheduler_mode[1];
  is_nul = is_nul || (!scheduler_mode[2]);    g->crank3->memo.memo[2] = is_nul ? '\0' : scheduler_mode[2];

  uint  cerr[1];
  do {
    char seed[13];
    fd_memcpy( seed, "TIP_ACCOUNT_0", 13 ); /* Not NUL terminated */
    uchar const * seed_ptr[1] = { (uchar const *)seed };
    ulong seed_len = 13;
    for( ulong i=0UL; i<8UL; i++ ) {
      seed[12] = (char)((ulong)'0' + i);
      uchar out_bump[1];
      FD_TEST( FD_PUBKEY_SUCCESS==fd_pubkey_find_program_address( (fd_pubkey_t const *)tip_payment_program_addr,
                                                                  1UL, seed_ptr, &seed_len,
                                                                  (fd_pubkey_t *)g->crank3->tip_payment_accounts[i], out_bump, cerr ) );
    }
  } while( 0 );

  do {
    char seed[14];
    fd_memcpy( seed, "CONFIG_ACCOUNT", 14 ); /* Not NUL terminated */
    ulong seed_len = 14;
    uchar out_bump[1];
    uchar const * seed_ptr[1] = { (uchar const *)seed };
    FD_TEST( FD_PUBKEY_SUCCESS==fd_pubkey_find_program_address( (fd_pubkey_t const *)tip_payment_program_addr,
                                                                1UL, seed_ptr, &seed_len,
                                                                (fd_pubkey_t *)g->crank3->tip_payment_program_config, out_bump, cerr ) );
    /* Same seed used for tip distribution config account too */
    FD_TEST( FD_PUBKEY_SUCCESS==fd_pubkey_find_program_address( (fd_pubkey_t const *)tip_distribution_program_addr,
                                                                1UL, seed_ptr, &seed_len,
                                                                (fd_pubkey_t *)g->crank3->tip_distribution_program_config, out_bump, cerr ) );
  } while( 0 );

  /* Populate crank2 from crank3 */
  memcpy( g->crank2->tip_payment_accounts,            g->crank3->tip_payment_accounts,            8UL*32UL );
  memcpy( g->crank2->tip_distribution_program_config, g->crank3->tip_distribution_program_config,     32UL );
  memcpy( g->crank2->tip_payment_program_config,      g->crank3->tip_payment_program_config,          32UL );
  memcpy( g->crank2->tip_payment_program,             g->crank3->tip_payment_program,                 32UL );
  memcpy( g->crank2->validator_vote_account,          g->crank3->validator_vote_account,              32UL );
  memcpy( g->crank2->memo.memo,                       g->crank3->memo.memo,                            3UL );

  FD_TEST( sizeof(g->txn3)==fd_txn_parse( (uchar const *)g->crank3, sizeof(g->crank3), g->txn3, NULL ) );
  FD_TEST( sizeof(g->txn2)==fd_txn_parse( (uchar const *)g->crank2, sizeof(g->crank2), g->txn2, NULL ) );

  pidx_map_new( g->map );
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[0],         0 ) }} )->idx= 1UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[1],         0 ) }} )->idx= 2UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[2],         0 ) }} )->idx= 3UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[3],         0 ) }} )->idx= 4UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[4],         0 ) }} )->idx= 5UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[5],         0 ) }} )->idx= 6UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[6],         0 ) }} )->idx= 7UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_accounts[7],         0 ) }} )->idx= 8UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_distribution_program_config, 0 ) }} )->idx= 9UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_program_config,      0 ) }} )->idx=10UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->validator_vote_account,          0 ) }} )->idx=15UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->compute_budget_program,          0 ) }} )->idx=16UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_payment_program,             0 ) }} )->idx=17UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->memo_program,                    0 ) }} )->idx=18UL;
  pidx_map_insert( g->map, (fd_acct_addr_t){{ EXPAND_ARR32( g->crank3->tip_distribution_program,        0 ) }} )->idx=20UL;

  g->configured_epoch = ULONG_MAX;
  return g;
}


static inline void
fd_bundle_crank_update_epoch( fd_bundle_crank_gen_t * g,
                              ulong                   epoch ) {
  uchar const * const seeds[3] = {
    (uchar const *)"TIP_DISTRIBUTION_ACCOUNT",
    (uchar const *)g->crank3->validator_vote_account,
    (uchar const *)&epoch,
  };
  ulong seed_szs[3] = { 24, 32, 8 };
  uint custom_err[1];
  FD_TEST( FD_PUBKEY_SUCCESS==fd_pubkey_find_program_address( (fd_pubkey_t const *)g->crank3->tip_distribution_program,
                                                              3UL, seeds, seed_szs,
                                                              (fd_pubkey_t *)g->crank3->new_tip_receiver,
                                                              &(g->crank3->init_tip_distribution_acct.bump), custom_err ) );
  memcpy( g->crank2->new_tip_receiver, g->crank3->new_tip_receiver, 32UL );
  g->configured_epoch = epoch;
}

void
fd_bundle_crank_get_addresses( fd_bundle_crank_gen_t * gen,
                               ulong                   epoch,
                               fd_acct_addr_t        * out_tip_payment_config,
                               fd_acct_addr_t        * out_tip_receiver ) {
  if( FD_UNLIKELY( epoch!=gen->configured_epoch ) ) fd_bundle_crank_update_epoch( gen, epoch );
  memcpy( out_tip_payment_config, gen->crank3->tip_payment_program_config, 32UL );
  memcpy( out_tip_receiver,       gen->crank3->new_tip_receiver,           32UL );
}

ulong
fd_bundle_crank_generate( fd_bundle_crank_gen_t                       * gen,
                          fd_bundle_crank_tip_payment_config_t const  * old_tip_payment_config,
                          fd_acct_addr_t                       const  * new_block_builder,
                          fd_acct_addr_t                       const  * identity,
                          fd_acct_addr_t                       const  * tip_receiver_owner,
                          ulong                                         epoch,
                          ulong                                         block_builder_commission,
                          uchar                                       * out_payload,
                          fd_txn_t                                    * out_txn ) {

  if( FD_UNLIKELY( epoch!=gen->configured_epoch ) ) fd_bundle_crank_update_epoch( gen, epoch );

  if( FD_UNLIKELY( old_tip_payment_config->discriminator != 0x82ccfa1ee0aa0c9bUL ) ) {
    FD_LOG_WARNING(( "Found unexpected tip payment config account discriminator %lx.  Refusing to crank bundles.",
                      old_tip_payment_config->discriminator ));
    return ULONG_MAX;
  }

  int swap3 = !fd_memeq( tip_receiver_owner, gen->crank3->tip_distribution_program, sizeof(fd_acct_addr_t) );

  if( FD_LIKELY( fd_memeq( old_tip_payment_config->tip_receiver,  gen->crank3->new_tip_receiver, 32UL ) &&
                 fd_memeq( old_tip_payment_config->block_builder, new_block_builder,             32UL ) &&
                 !swap3                                                                                 &&
                 old_tip_payment_config->commission_pct==block_builder_commission ) ) {
    /* Everything configured properly! */
    return 0UL;
  }


  if( FD_UNLIKELY( swap3 ) ) {
    memcpy( gen->crank3->authorized_voter,  identity,                              32UL );
    memcpy( gen->crank3->new_block_builder, new_block_builder,                     32UL );
    memcpy( gen->crank3->old_tip_receiver,  old_tip_payment_config->tip_receiver,  32UL );
    memcpy( gen->crank3->old_block_builder, old_tip_payment_config->block_builder, 32UL );
    gen->crank3->change_block_builder.block_builder_commission_pct = block_builder_commission;
  } else {
    memcpy( gen->crank2->authorized_voter,  identity,                              32UL );
    memcpy( gen->crank2->new_block_builder, new_block_builder,                     32UL );
    memcpy( gen->crank2->old_tip_receiver,  old_tip_payment_config->tip_receiver,  32UL );
    memcpy( gen->crank2->old_block_builder, old_tip_payment_config->block_builder, 32UL );
    gen->crank2->change_block_builder.block_builder_commission_pct = block_builder_commission;
  }

  /* If it weren't for the fact that the old tip payment config is
     essentially attacker-controlled, we'd be basically done now.
     However, someone trying to grief us can e.g. set the old block
     builder to the tip payment program, and if we're not careful, we'll
     create a transaction with a duplicate account.  We trust identity,
     new tip_receiver, and new_block_builder well enough though.  Note
     that it's not possible for either attacker-controlled address to be
     the system program, because the account must be writable, and write
     locks to the system program get demoted.

     Technically, the validator vote account could be a read only
     account, but if an attacker set the old block builder or tip
     receiver to that address, we'd need to promote it to a writable
     account which is a bit difficult with this way of doing it.
     There's not much harm in passing it as writable, and that makes
     things much easier. */
  fd_bundle_crank_gen_pidx_t * identity_pidx = pidx_map_insert( gen->map, *(fd_acct_addr_t *)identity );
  if( FD_UNLIKELY( !identity_pidx ) ) {
    FD_LOG_WARNING(( "Identity was already in map.  Refusing to crank bundles." ));
    return ULONG_MAX;
  }
  identity_pidx->idx = 0UL;

  fd_bundle_crank_gen_pidx_t * new_tr_pidx = pidx_map_insert( gen->map, *(fd_acct_addr_t *)gen->crank3->new_tip_receiver );
  if( FD_UNLIKELY( !new_tr_pidx ) ) {
    pidx_map_remove( gen->map, identity_pidx );
    FD_LOG_WARNING(( "New tip receiver was already in map.  Refusing to crank bundles." ));
    return ULONG_MAX;
  }
  new_tr_pidx->idx = 13UL;

  fd_bundle_crank_gen_pidx_t * new_bb_pidx = pidx_map_insert( gen->map, *(fd_acct_addr_t *)new_block_builder );
  if( FD_UNLIKELY( !new_bb_pidx ) ) {
    pidx_map_remove( gen->map, new_tr_pidx   );
    pidx_map_remove( gen->map, identity_pidx );
    FD_LOG_WARNING(( "New block builder was already in map.  Refusing to crank bundles." ));
    return ULONG_MAX;
  }
  new_bb_pidx->idx = 14UL;

  int inserted1 = 0;
  int inserted2 = 0;
  fd_bundle_crank_gen_pidx_t dummy1[1] = {{ .idx = 11UL }};
  fd_bundle_crank_gen_pidx_t dummy2[1] = {{ .idx = 12UL }};
  ulong swap2_unused_idx = ULONG_MAX;

  fd_bundle_crank_gen_pidx_t * old_tr_pidx = pidx_map_query( gen->map, *old_tip_payment_config->tip_receiver, NULL );
  if( FD_LIKELY( NULL==old_tr_pidx ) ) {
    old_tr_pidx = pidx_map_insert( gen->map, *old_tip_payment_config->tip_receiver );
    old_tr_pidx->idx = 11UL;
    inserted1 = 1;
  } else if( FD_UNLIKELY( !swap3 && old_tr_pidx->idx>18UL ) ) {
    /* Not an account we use in swap2, so it's okay to use index 11 for
       the old tip receiver. */
    swap2_unused_idx = old_tr_pidx->idx;
    old_tr_pidx      = dummy1;
  } else {
    /* perturb the account at index 11, where the old tip receiver
       pubkey normally goes, so that it's not a duplicate, then use the
       other index.  None of the non-attacker controlled keys look
       anything like 0xEE, 0xEE, ..., 0xEE, so we just need to make sure
       it doesn't match the old block builder (which will end up with a
       first byte of either 0xFE or the current value of
       old_block_builder[0]). */
    memset( gen->crank3->old_tip_receiver, (char)0xEE, 32UL );
    memset( gen->crank2->old_tip_receiver, (char)0xEE, 32UL );
    gen->crank3->old_tip_receiver[0] = gen->crank3->old_block_builder[0]+1;
    gen->crank2->old_tip_receiver[0] = gen->crank2->old_block_builder[0]+1;
  }

  fd_bundle_crank_gen_pidx_t * old_bb_pidx = pidx_map_query( gen->map, *old_tip_payment_config->block_builder, NULL );
  if( FD_UNLIKELY( NULL==old_bb_pidx ) ) {
    old_bb_pidx = pidx_map_insert( gen->map, *old_tip_payment_config->block_builder );
    old_bb_pidx->idx = 12UL;
    inserted2 = 1;
  } else if( FD_UNLIKELY( !swap3 && old_bb_pidx->idx>18UL && old_bb_pidx->idx!=swap2_unused_idx ) ) {
    /* If it happens to be the same account that we don't use in swap2,
       then we need to handle it differently. */
    old_bb_pidx = dummy2;
  } else {
    memset( gen->crank3->old_block_builder, (char)0xFE, 32UL );
    memset( gen->crank2->old_block_builder, (char)0xFE, 32UL );
    gen->crank3->old_block_builder[2] = gen->crank3->old_tip_receiver[2]+1;
    gen->crank2->old_block_builder[2] = gen->crank2->old_tip_receiver[2]+1;
    if( FD_UNLIKELY( old_bb_pidx->idx==swap2_unused_idx ) ) old_bb_pidx = dummy1;
  }

  gen->crank3->change_tip_receiver.acct_idx [1] = (uchar)(old_tr_pidx->idx);
  gen->crank2->change_tip_receiver.acct_idx [1] = (uchar)(old_tr_pidx->idx);
  gen->crank3->change_tip_receiver.acct_idx [3] = (uchar)(old_bb_pidx->idx);
  gen->crank3->change_block_builder.acct_idx[2] = (uchar)(old_bb_pidx->idx);
  gen->crank2->change_tip_receiver.acct_idx [3] = (uchar)(old_bb_pidx->idx);
  gen->crank2->change_block_builder.acct_idx[2] = (uchar)(old_bb_pidx->idx);

  if( FD_UNLIKELY( inserted2 ) ) pidx_map_remove( gen->map, old_bb_pidx );
  if( FD_LIKELY  ( inserted1 ) ) pidx_map_remove( gen->map, old_tr_pidx );
  pidx_map_remove( gen->map, new_bb_pidx   );
  pidx_map_remove( gen->map, new_tr_pidx   );
  pidx_map_remove( gen->map, identity_pidx );

  if( FD_UNLIKELY( swap3 ) ) {
    fd_memcpy( out_payload, gen->crank3, sizeof(gen->crank3) );
    fd_memcpy( out_txn,     gen->txn3,   sizeof(gen->txn3)   );
    return sizeof(gen->crank3);
  } else {
    fd_memcpy( out_payload, gen->crank2, sizeof(gen->crank2) );
    fd_memcpy( out_txn,     gen->txn2,   sizeof(gen->txn2)   );
    return sizeof(gen->crank2);
  }
}

void
fd_bundle_crank_apply( fd_bundle_crank_gen_t                       * gen,
                       fd_bundle_crank_tip_payment_config_t        * tip_payment_config,
                       fd_acct_addr_t                       const  * new_block_builder,
                       fd_acct_addr_t                              * tip_receiver_owner,
                       ulong                                         epoch,
                       ulong                                         block_builder_commission ) {

  if( FD_UNLIKELY( epoch!=gen->configured_epoch ) ) fd_bundle_crank_update_epoch( gen, epoch );

  memcpy( tip_receiver_owner,                gen->crank3->tip_distribution_program, sizeof(fd_acct_addr_t) );
  memcpy( tip_payment_config->tip_receiver,  gen->crank3->new_tip_receiver,         sizeof(fd_acct_addr_t) );
  memcpy( tip_payment_config->block_builder, new_block_builder,                     sizeof(fd_acct_addr_t) );

  tip_payment_config->commission_pct = block_builder_commission;
}
