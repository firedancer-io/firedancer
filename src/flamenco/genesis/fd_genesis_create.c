#define FD_SCRATCH_USE_HANDHOLDING 1
#include "fd_genesis_create.h"

#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/sysvar/fd_sysvar_clock.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../types/fd_types.h"

#define SORT_NAME sort_acct
#define SORT_KEY_T fd_pubkey_account_pair_t
#define SORT_BEFORE(a,b) (0>memcmp( (a).key.ul, (b).key.ul, sizeof(fd_pubkey_t) ))
#include "../../util/tmpl/fd_sort.c"

static ulong
genesis_create( void *                       buf,
                ulong                        bufsz,
                fd_genesis_options_t const * options ) {

# define REQUIRE(c)                         \
  do {                                      \
    if( FD_UNLIKELY( !(c) ) ) {             \
      FD_LOG_WARNING(( "FAIL: %s", #c ));   \
      return 0UL;                           \
    }                                       \
  } while(0);

  fd_genesis_solana_t genesis[1];
  fd_genesis_solana_new( genesis );

  genesis->cluster_type = 3;  /* development */

  genesis->creation_time  = options->creation_time;
  genesis->ticks_per_slot = options->ticks_per_slot;
  REQUIRE( genesis->ticks_per_slot );

  genesis->unused = 1024UL; /* match Anza genesis byte-for-byte */

  genesis->poh_config.has_hashes_per_tick = !!options->hashes_per_tick;
  genesis->poh_config.hashes_per_tick     =   options->hashes_per_tick;

  ulong target_tick_micros = options->target_tick_duration_micros;
  REQUIRE( target_tick_micros );
  genesis->poh_config.target_tick_duration = (fd_rust_duration_t) {
    .seconds     =         target_tick_micros / 1000000UL,
    .nanoseconds = (uint)( target_tick_micros % 1000000UL * 1000UL ),
  };

  /* Create fee rate governor */

  genesis->fee_rate_governor = (fd_fee_rate_governor_t) {
    .target_lamports_per_signature  =  10000UL,
    .target_signatures_per_slot     =  20000UL,
    .min_lamports_per_signature     =   5000UL,
    .max_lamports_per_signature     = 100000UL,
    .burn_percent                   =     50,
  };

  /* Create rent configuration */

  genesis->rent = (fd_rent_t) {
    .lamports_per_uint8_year = 3480,
    .exemption_threshold     = 2.0,
    .burn_percent            = 50,
  };

  /* Create inflation configuration */

  genesis->inflation = (fd_inflation_t) {
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
    .__unused        = 0.0,
  };

  /* Create epoch schedule */
  /* TODO The epoch schedule should be configurable! */

  genesis->epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 8192UL,
    .leader_schedule_slot_offset = 8192UL,
    .warmup                      =    0,
    .first_normal_epoch          =    0UL,
    .first_normal_slot           =    0UL,
  };

  /* Create faucet account */

  fd_pubkey_account_pair_t const faucet_account = {
    .key = options->faucet_pubkey,
    .account = {
      .lamports   = options->faucet_balance,
      .owner      = fd_solana_system_program_id,
      .rent_epoch = 0UL
    }
  };
  ulong const faucet_account_index = genesis->accounts_len++;

  /* Create identity account (vote authority, withdraw authority) */

  fd_pubkey_account_pair_t const identity_account = {
    .key = options->identity_pubkey,
    .account = {
      .lamports   = 500000000000UL /* 500 SOL */,
      .owner      = fd_solana_system_program_id,
      .rent_epoch = 0UL
    }
  };
  ulong const identity_account_index = genesis->accounts_len++;

  /* Create vote account */

  ulong const vote_account_index = genesis->accounts_len++;

  uchar vote_state_data[ FD_VOTE_STATE_V3_SZ ] = {0};

  FD_SCRATCH_SCOPE_BEGIN {
    fd_vote_state_versioned_t vsv[1];
    fd_vote_state_versioned_new_disc( vsv, fd_vote_state_versioned_enum_current );

    fd_vote_state_t * vs = &vsv->inner.current;
    vs->node_pubkey             = options->identity_pubkey;
    vs->authorized_withdrawer   = options->identity_pubkey;
    vs->commission              = 100;
    vs->authorized_voters.pool  = fd_vote_authorized_voters_pool_alloc ( fd_scratch_virtual() );
    vs->authorized_voters.treap = fd_vote_authorized_voters_treap_alloc( fd_scratch_virtual() );

    fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
    *ele = (fd_vote_authorized_voter_t) {
      .epoch  = 0UL,
      .pubkey = options->identity_pubkey,
      .prio   = options->identity_pubkey.ul[0],  /* treap prio */
    };
    fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, ele, vs->authorized_voters.pool );

    fd_bincode_encode_ctx_t encode =
      { .data    = vote_state_data,
        .dataend = vote_state_data + sizeof(vote_state_data) };
    REQUIRE( fd_vote_state_versioned_encode( vsv, &encode ) == FD_BINCODE_SUCCESS );
  }
  FD_SCRATCH_SCOPE_END;

  /* Create stake account */

  ulong const stake_account_index = genesis->accounts_len++;

  uchar stake_data[ FD_STAKE_STATE_V2_SZ ];

  ulong stake_state_min_bal = fd_rent_exempt_minimum_balance2( &genesis->rent, FD_STAKE_STATE_V2_SZ );
  ulong vote_min_bal        = fd_rent_exempt_minimum_balance2( &genesis->rent, FD_VOTE_STATE_V3_SZ  );

  do {
    fd_stake_state_v2_t state[1];
    fd_stake_state_v2_new_disc( state, fd_stake_state_v2_enum_stake );

    fd_stake_state_v2_stake_t * stake = &state->inner.stake;
    stake->meta = (fd_stake_meta_t) {
      .rent_exempt_reserve = stake_state_min_bal,
      .authorized = {
        .staker     = options->identity_pubkey,
        .withdrawer = options->identity_pubkey,
      }
    };
    stake->stake = (fd_stake_t) {
      .delegation = (fd_delegation_t) {
        .voter_pubkey       = options->vote_pubkey,
        .stake              = fd_ulong_max( stake_state_min_bal, 500000000UL /* 0.5 SOL */ ),
        .activation_epoch   = ULONG_MAX, /*  bootstrap stake denoted with ULONG_MAX */
        .deactivation_epoch = ULONG_MAX
      },
      .credits_observed = 0UL
    };

    fd_bincode_encode_ctx_t encode =
      { .data    = stake_data,
        .dataend = stake_data + sizeof(stake_data) };
    REQUIRE( fd_stake_state_v2_encode( state, &encode ) == FD_BINCODE_SUCCESS );
  } while(0);

  /* Read enabled features */

  ulong         feature_cnt = 0UL;
  fd_pubkey_t * features =
      fd_scratch_alloc( alignof(fd_pubkey_t), FD_FEATURE_ID_CNT * sizeof(fd_pubkey_t) );

  if( options->features ) {
    for( fd_feature_id_t const * id = fd_feature_iter_init();
                                     !fd_feature_iter_done( id );
                                 id = fd_feature_iter_next( id ) ) {
      if( fd_features_get( options->features, id ) == 0UL )
        features[ feature_cnt++ ] = id->id;
    }
  }

  /* Allocate the account table */

  ulong default_funded_cnt = options->fund_initial_accounts;

  ulong default_funded_idx = genesis->accounts_len;      genesis->accounts_len += default_funded_cnt;
  ulong feature_gate_idx   = genesis->accounts_len;      genesis->accounts_len += feature_cnt;

  genesis->accounts = fd_scratch_alloc( alignof(fd_pubkey_account_pair_t),
                                        genesis->accounts_len * sizeof(fd_pubkey_account_pair_t) );
  fd_memset( genesis->accounts, 0,      genesis->accounts_len * sizeof(fd_pubkey_account_pair_t) );

  genesis->accounts[ faucet_account_index ] = faucet_account;
  genesis->accounts[ identity_account_index ] = identity_account;
  genesis->accounts[ stake_account_index ] = (fd_pubkey_account_pair_t) {
    .key     = options->stake_pubkey,
    .account = (fd_solana_account_t) {
      .lamports   = stake_state_min_bal,
      .data_len   = FD_STAKE_STATE_V2_SZ,
      .data       = stake_data,
      .owner      = fd_solana_stake_program_id,
      .rent_epoch = 0UL
    }
  };
  genesis->accounts[ vote_account_index ] = (fd_pubkey_account_pair_t) {
    .key     = options->vote_pubkey,
    .account = (fd_solana_account_t) {
      .lamports   = vote_min_bal,
      .data_len   = FD_VOTE_STATE_V3_SZ,
      .data       = vote_state_data,
      .owner      = fd_solana_vote_program_id,
      .rent_epoch = 0UL
    }
  };

  /* Set up primordial accounts */

  ulong default_funded_balance = options->fund_initial_amount_lamports;
  for( ulong j=0UL; j<default_funded_cnt; j++ ) {
    fd_pubkey_account_pair_t * pair = &genesis->accounts[ default_funded_idx+j ];

    uchar privkey[ 32 ] = {0};
    FD_STORE( ulong, privkey, j );
    fd_sha512_t sha[1];
    fd_ed25519_public_from_private( pair->key.key, privkey, sha );

    pair->account = (fd_solana_account_t) {
      .lamports   = default_funded_balance,
      .data_len   = 0UL,
      .owner      = fd_solana_system_program_id,
      .rent_epoch = 0UL
    };
  }

#define FEATURE_ENABLED_SZ 9UL
  static const uchar feature_enabled_data[ FEATURE_ENABLED_SZ ] = { 1, 0, 0, 0, 0, 0, 0, 0, 0 };
  ulong default_feature_enabled_balance = fd_rent_exempt_minimum_balance2( &genesis->rent, FEATURE_ENABLED_SZ );

  /* Set up feature gate accounts */
  for( ulong j=0UL; j<feature_cnt; j++ ) {
    fd_pubkey_account_pair_t * pair = &genesis->accounts[ feature_gate_idx+j ];

    pair->key     = features[ j ];
    pair->account = (fd_solana_account_t) {
      .lamports   = default_feature_enabled_balance,
      .data_len   = FEATURE_ENABLED_SZ,
      .data       = (uchar *)feature_enabled_data,
      .owner      = fd_solana_feature_program_id,
      .rent_epoch = 0UL,
    };
  }
#undef FEATURE_ENABLED_SZ

  /* Sort and check for duplicates */

  sort_acct_inplace( genesis->accounts, genesis->accounts_len );

  for( ulong j=1UL; j < genesis->accounts_len; j++ ) {
    if( 0==memcmp( genesis->accounts[j-1].key.ul, genesis->accounts[j].key.ul, sizeof(fd_pubkey_t) ) ) {
      char dup_cstr[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( genesis->accounts[j].key.uc, NULL, dup_cstr );
      FD_LOG_WARNING(( "Account %s is duplicate", dup_cstr ));
      return 0UL;
    }
  }

  /* Serialize bincode blob */

  fd_bincode_encode_ctx_t encode =
    { .data    = buf,
      .dataend = (uchar *)buf + bufsz };
  int encode_err = fd_genesis_solana_encode( genesis, &encode );
  if( FD_UNLIKELY( encode_err ) ) {
    FD_LOG_WARNING(( "Failed to encode genesis blob (bufsz=%lu)", bufsz ));
    return 0UL;
  }
  return (ulong)encode.data - (ulong)buf;

# undef REQUIRE
}

ulong
fd_genesis_create( void *                       buf,
                   ulong                        bufsz,
                   fd_genesis_options_t const * options ) {
  fd_scratch_push();
  ulong ret = genesis_create( buf, bufsz, options );
  fd_scratch_pop();
  return ret;
}
