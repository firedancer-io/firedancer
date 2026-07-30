#include "fd_genesis_create.h"

#include "../runtime/fd_system_ids.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/program/vote/fd_vote_codec.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"

#include <stddef.h>

/* Alpenglow genesis accounts.

   A cluster that runs alpenglow from slot 0 never goes through the
   TowerBFT migration, so genesis has to contain the two accounts that
   the migration would otherwise have written.  Both live at off curve
   addresses derived under the alpenglow feature gate pubkey and are
   owned by the system program.  Mirrors agave's
   runtime/src/genesis_utils.rs::configure_alpenglow_at_genesis. */

/* Seeds of the two program derived addresses.  agave derives these in
   votor-messages/src/migration.rs (GENESIS_CERTIFICATE_ACCOUNT) and
   runtime/src/block_component_processor/vote_reward/
   epoch_inflation_account_state.rs (VOTE_REWARD_ACCOUNT_ADDR). */

#define FD_ALPENGLOW_GENESIS_CERT_SEED    "carlgration"
#define FD_ALPENGLOW_EPOCH_INFLATION_SEED "vote_reward_account"

/* Size of an uncompressed ("affine") BLS12-381 signature: a G2 point is
   a pair of Fp2 coordinates of 96 bytes each.  Matches
   solana_bls_signatures::BLS_SIGNATURE_AFFINE_SIZE. */

#define FD_ALPENGLOW_BLS_SIGNATURE_AFFINE_SZ (192UL)

/* Serialized size of the genesis certificate, a WireBlockCertMessage
   (agave votor-messages/src/wire.rs):

     Block { slot: u64, block_id: [uchar;32] }
     WireCertSignature { signature: [uchar;192], bitmap: Vec<uchar> }

   The stub written here certifies slot 0 with a zero block id and no
   signers, which is what tells agave that every slot after 0 is an
   alpenglow block (MigrationPhase::is_alpenglow_block).  Its signature
   and bitmap are never verified: every consumer of
   Bank::get_alpenglow_genesis_certificate reads only .block.

   A vector is length prefixed with a little endian u64.  The bitmap is
   solana_signer_store::encode_base2 of an empty bit vector, which is a
   one byte version tag (Base2 is 0), then the bit count as a little
   endian u16 (zero), then the packed bits (none): three zero bytes. */

#define FD_ALPENGLOW_CERT_BITMAP_SZ (3UL)

#define FD_ALPENGLOW_GENESIS_CERT_SZ \
  (8UL + 32UL + FD_ALPENGLOW_BLS_SIGNATURE_AFFINE_SZ + 8UL + FD_ALPENGLOW_CERT_BITMAP_SZ)

/* Serialized size of EpochInflationAccountState:

     current: EpochInflationState { max_possible_validator_reward: u64,
                                    slots_per_epoch:               u64,
                                    epoch:                         u64 }
     prev:    Option<EpochInflationState>

   An Option is a one byte tag followed by the payload when present. */

#define FD_ALPENGLOW_EPOCH_INFLATION_SZ (8UL + 8UL + 8UL + 1UL)

/* An alpenglow validator burns a validator admission ticket out of its
   vote account every epoch and is dropped from the rank map once it can
   no longer pay, so the genesis vote account needs runway on top of the
   rent exempt minimum.  agave funds 100 epochs of it in
   genesis_utils::minimum_vote_account_balance_for_vat, and the per
   epoch burn is from runtime/src/slot_params.rs LEGACY_SLOT_PARAMS. */

#define FD_ALPENGLOW_VAT_TO_BURN_PER_EPOCH (1600000000UL) /* 1.6 SOL */
#define FD_ALPENGLOW_VAT_EPOCHS            (100UL)

/* TODO: Unify type with the one in fd_genesis_parse.c */

struct fd_rust_duration {
  ulong seconds;
  uint nanoseconds;
};
typedef struct fd_rust_duration fd_rust_duration_t;

struct fd_poh_config {
  fd_rust_duration_t target_tick_duration;
  ulong target_tick_count;
  uchar has_target_tick_count;
  ulong hashes_per_tick;
  uchar has_hashes_per_tick;
};
typedef struct fd_poh_config fd_poh_config_t;

struct fd_genesis_account {
  ulong       lamports;
  ulong       data_len;
  uchar *     data;
  fd_pubkey_t owner;
  uchar       executable;
  ulong       rent_epoch;
};
typedef struct fd_genesis_account fd_genesis_account_t;

struct fd_genesis_account_pair {
  fd_pubkey_t          key;
  fd_genesis_account_t account;
};
typedef struct fd_genesis_account_pair fd_genesis_account_pair_t;

#define SORT_NAME sort_acct
#define SORT_KEY_T fd_genesis_account_pair_t
#define SORT_BEFORE(a,b) (0>memcmp( (a).key.ul, (b).key.ul, sizeof(fd_pubkey_t) ))
#include "../../util/tmpl/fd_sort.c"

static inline uchar *
emit_u8( uchar * p, uchar * end, uchar v ) {
  if( FD_UNLIKELY( p+1>end ) ) return NULL;
  *p = v;
  return p+1;
}

static inline uchar *
emit_u32( uchar * p, uchar * end, uint v ) {
  if( FD_UNLIKELY( p+4>end ) ) return NULL;
  FD_STORE( uint, p, v );
  return p+4;
}

static inline uchar *
emit_u64( uchar * p, uchar * end, ulong v ) {
  if( FD_UNLIKELY( p+8>end ) ) return NULL;
  FD_STORE( ulong, p, v );
  return p+8;
}

static inline uchar *
emit_f64( uchar * p, uchar * end, double v ) {
  if( FD_UNLIKELY( p+8>end ) ) return NULL;
  FD_STORE( double, p, v );
  return p+8;
}

static inline uchar *
emit_bytes( uchar * p, uchar * end, void const * src, ulong n ) {
  if( FD_UNLIKELY( p+n>end ) ) return NULL;
  fd_memcpy( p, src, n );
  return p+n;
}

/* Private struct mirroring the Solana GenesisConfig bincode layout.
   Only used locally for building up state before serialization. */

struct genesis_solana {
  ulong                      creation_time;
  ulong                      accounts_len;
  fd_genesis_account_pair_t * accounts;
  ulong                      native_instruction_processors_len;
  ulong                      rewards_pools_len;
  ulong                      ticks_per_slot;
  ulong                      unused;
  fd_poh_config_t            poh_config;
  ulong                      __backwards_compat_with_v0_23;
  fd_fee_rate_governor_t     fee_rate_governor;
  fd_rent_t                  rent;
  fd_inflation_t             inflation;
  fd_epoch_schedule_t        epoch_schedule;
  uint                       cluster_type;
};
typedef struct genesis_solana genesis_solana_t;

/* genesis_encode serializes a genesis_solana_t into a bincode blob
   byte-for-byte compatible with Anza's genesis.bin format.  Returns the
   number of bytes written, or 0 on failure (buffer too small). */

static ulong
genesis_encode( genesis_solana_t const * g,
                uchar *                  buf,
                ulong                    bufsz ) {
  uchar * p   = buf;
  uchar * end = buf + bufsz;

# define EMIT(expr) do { p = (expr); if( FD_UNLIKELY( !p ) ) return 0UL; } while(0)

  EMIT( emit_u64( p, end, g->creation_time ) );

  /* accounts vector */
  EMIT( emit_u64( p, end, g->accounts_len ) );
  for( ulong i=0; i<g->accounts_len; i++ ) {
    fd_genesis_account_pair_t const * a = &g->accounts[i];
    EMIT( emit_bytes( p, end, a->key.key, 32 ) );
    EMIT( emit_u64(   p, end, a->account.lamports ) );
    EMIT( emit_u64(   p, end, a->account.data_len ) );
    if( a->account.data_len )
      EMIT( emit_bytes( p, end, a->account.data, a->account.data_len ) );
    EMIT( emit_bytes( p, end, a->account.owner.key, 32 ) );
    EMIT( emit_u8(    p, end, !!a->account.executable ) );
    EMIT( emit_u64(   p, end, a->account.rent_epoch ) );
  }

  /* native_instruction_processors vector
     TODO: currently always empty */
  EMIT( emit_u64( p, end, g->native_instruction_processors_len ) );

  /* rewards_pools vector
     TODO: currently always empty */
  EMIT( emit_u64( p, end, g->rewards_pools_len ) );

  EMIT( emit_u64( p, end, g->ticks_per_slot ) );
  EMIT( emit_u64( p, end, g->unused ) );

  /* poh_config
     TODO: has target tick count always == 0 */
  EMIT( emit_u64( p, end, g->poh_config.target_tick_duration.seconds ) );
  EMIT( emit_u32( p, end, g->poh_config.target_tick_duration.nanoseconds ) );
  EMIT( emit_u8(  p, end, !!g->poh_config.has_target_tick_count ) );
  if( g->poh_config.has_target_tick_count )
    EMIT( emit_u64( p, end, g->poh_config.target_tick_count ) );
  EMIT( emit_u8(  p, end, !!g->poh_config.has_hashes_per_tick ) );
  if( g->poh_config.has_hashes_per_tick )
    EMIT( emit_u64( p, end, g->poh_config.hashes_per_tick ) );

  /* TODO: always set to 0 */
  EMIT( emit_u64( p, end, g->__backwards_compat_with_v0_23 ) );

  /* fee_rate_governor */
  EMIT( emit_u64( p, end, g->fee_rate_governor.target_lamports_per_signature ) );
  EMIT( emit_u64( p, end, g->fee_rate_governor.target_signatures_per_slot ) );
  EMIT( emit_u64( p, end, g->fee_rate_governor.min_lamports_per_signature ) );
  EMIT( emit_u64( p, end, g->fee_rate_governor.max_lamports_per_signature ) );
  EMIT( emit_u8(  p, end, g->fee_rate_governor.burn_percent ) );

  /* rent */
  EMIT( emit_u64( p, end, g->rent.lamports_per_uint8_year ) );
  EMIT( emit_f64( p, end, g->rent.exemption_threshold ) );
  EMIT( emit_u8(  p, end, g->rent.burn_percent ) );

  /* inflation */
  EMIT( emit_f64( p, end, g->inflation.initial ) );
  EMIT( emit_f64( p, end, g->inflation.terminal ) );
  EMIT( emit_f64( p, end, g->inflation.taper ) );
  EMIT( emit_f64( p, end, g->inflation.foundation ) );
  EMIT( emit_f64( p, end, g->inflation.foundation_term ) );
  EMIT( emit_f64( p, end, g->inflation.unused ) );

  /* epoch_schedule */
  EMIT( emit_u64( p, end, g->epoch_schedule.slots_per_epoch ) );
  EMIT( emit_u64( p, end, g->epoch_schedule.leader_schedule_slot_offset ) );
  EMIT( emit_u8(  p, end, !!g->epoch_schedule.warmup ) );
  EMIT( emit_u64( p, end, g->epoch_schedule.first_normal_epoch ) );
  EMIT( emit_u64( p, end, g->epoch_schedule.first_normal_slot ) );

  EMIT( emit_u32( p, end, g->cluster_type ) );

# undef EMIT
  return (ulong)(p - buf);
}

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

  genesis_solana_t genesis[1] = {0};

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
  };

  /* Create epoch schedule */
  /* TODO The epoch schedule should be configurable! */

  /* If warmup is enabled:
     MINIMUM_SLOTS_PER_EPOCH = 32
     first_normal_epoch = log2( slots_per_epoch ) - log2( MINIMUM_SLOTS_PER_EPOCH  )
     first_normal_slot  = MINIMUM_SLOTS_PER_EPOCH * ( 2^( first_normal_epoch ) - 1 )
  */

  genesis->epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 8192UL,
    .leader_schedule_slot_offset = 8192UL,
    .warmup                      = fd_uchar_if( options->warmup_epochs,    1,   0   ),
    .first_normal_epoch          = fd_ulong_if( options->warmup_epochs,    8UL, 0UL ),
    .first_normal_slot           = fd_ulong_if( options->warmup_epochs, 8160UL, 0UL ),
  };

  /* Create faucet account */

  fd_genesis_account_pair_t const faucet_account = {
    .key = options->faucet_pubkey,
    .account = {
      .lamports   = options->faucet_balance,
      .owner      = fd_solana_system_program_id
    }
  };
  ulong const faucet_account_index = genesis->accounts_len++;

  /* Create identity account (vote authority, withdraw authority) */

  fd_genesis_account_pair_t const identity_account = {
    .key = options->identity_pubkey,
    .account = {
      .lamports   = 500000000000UL /* 500 SOL */,
      .owner      = fd_solana_system_program_id
    }
  };
  ulong const identity_account_index = genesis->accounts_len++;

  /* Create vote account */

  ulong const vote_account_index = genesis->accounts_len++;

  /* VoteStateV3 and VoteStateV4 happen to serialize into the same
     amount of space, so the account size does not depend on which one
     is written. */

  FD_STATIC_ASSERT( FD_VOTE_STATE_V3_SZ==FD_VOTE_STATE_V4_SZ, vote_state_sz );

  uchar vote_state_data[ FD_VOTE_STATE_V3_SZ ] = {0};

  FD_SCRATCH_SCOPE_BEGIN {
    fd_vote_state_versioned_t     versioned[1];
    fd_vote_authorized_voters_t * authorized_voters;

    if( options->alpenglow ) {

      /* Alpenglow votes are BLS signed, and epoch_stakes gives no
         weight at all to a vote account without a BLS pubkey, so the
         genesis vote account has to be a V4 carrying one.  The key is
         derived from the authorized voter, which is the identity
         below, so the validator will sign with the key registered
         here. */

      fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v4 );

      fd_vote_state_v4_t * vote_state             = &versioned->v4;
      vote_state->node_pubkey                     = options->identity_pubkey;
      vote_state->authorized_withdrawer           = options->identity_pubkey;
      vote_state->inflation_rewards_collector     = options->vote_pubkey;
      vote_state->block_revenue_collector         = options->identity_pubkey;

      /* V3 states commission as a percentage, V4 as basis points. */
      vote_state->inflation_rewards_commission_bps = 100*100;
      vote_state->block_revenue_commission_bps     = 100*100;

      vote_state->has_bls_pubkey_compressed        = 1;
      fd_memcpy( vote_state->bls_pubkey_compressed, options->identity_bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ );

      authorized_voters = &vote_state->authorized_voters;

    } else {

      fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v3 );

      fd_vote_state_v3_t * vote_state   = &versioned->v3;
      vote_state->node_pubkey           = options->identity_pubkey;
      vote_state->authorized_withdrawer = options->identity_pubkey;
      vote_state->commission            = 100;

      authorized_voters = &vote_state->authorized_voters;

    }

    fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( authorized_voters->pool );
    *voter = (fd_vote_authorized_voter_t) {
      .epoch  = 0UL,
      .pubkey = options->identity_pubkey,
      .prio   = options->identity_pubkey.uc[0],
    };
    fd_vote_authorized_voters_treap_ele_insert( authorized_voters->treap, voter, authorized_voters->pool );

    REQUIRE( !fd_vote_state_versioned_serialize( versioned, vote_state_data, sizeof(vote_state_data) ) );
  }
  FD_SCRATCH_SCOPE_END;

  /* Create stake account */

  ulong const stake_account_index = genesis->accounts_len++;

  uchar stake_data[ FD_STAKE_STATE_SZ ] = {0};

  ulong stake_state_min_bal = fd_rent_exempt_minimum_balance( &genesis->rent, FD_STAKE_STATE_SZ   );
  ulong vote_min_bal        = fd_rent_exempt_minimum_balance( &genesis->rent, FD_VOTE_STATE_V3_SZ );

  if( options->alpenglow ) vote_min_bal += FD_ALPENGLOW_VAT_TO_BURN_PER_EPOCH*FD_ALPENGLOW_VAT_EPOCHS;

  do {
    FD_STORE( fd_stake_state_t, stake_data, ((fd_stake_state_t) {
      .stake_type = FD_STAKE_STATE_STAKE,
      .stake = {
        .meta = {
          .rent_exempt_reserve = stake_state_min_bal,
          .staker              = options->identity_pubkey,
          .withdrawer          = options->identity_pubkey,
        },
        .stake = (fd_stake_t) {
          .delegation = (fd_delegation_t) {
            .voter_pubkey         = options->vote_pubkey,
            .stake                = fd_ulong_max( stake_state_min_bal, options->vote_account_stake ),
            .activation_epoch     = ULONG_MAX, /* bootstrap stake denoted with ULONG_MAX */
            .deactivation_epoch   = ULONG_MAX,
            .warmup_cooldown_rate = 0.25
          },
          .credits_observed = 0UL
        }
      }
    }) );
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

  ulong alpenglow_cnt      = options->alpenglow ? 2UL : 0UL;

  ulong default_funded_idx = genesis->accounts_len;      genesis->accounts_len += default_funded_cnt;
  ulong feature_gate_idx   = genesis->accounts_len;      genesis->accounts_len += feature_cnt;
  ulong alpenglow_idx      = genesis->accounts_len;      genesis->accounts_len += alpenglow_cnt;

  genesis->accounts = fd_scratch_alloc( alignof(fd_genesis_account_pair_t),
                                        genesis->accounts_len * sizeof(fd_genesis_account_pair_t) );
  fd_memset( genesis->accounts, 0,      genesis->accounts_len * sizeof(fd_genesis_account_pair_t) );

  genesis->accounts[ faucet_account_index ] = faucet_account;
  genesis->accounts[ identity_account_index ] = identity_account;
  genesis->accounts[ stake_account_index ] = (fd_genesis_account_pair_t) {
    .key     = options->stake_pubkey,
    .account = (fd_genesis_account_t) {
      .lamports   = fd_ulong_max( stake_state_min_bal, options->vote_account_stake ),
      .data_len   = FD_STAKE_STATE_SZ,
      .data       = stake_data,
      .owner      = fd_solana_stake_program_id
    }
  };
  genesis->accounts[ vote_account_index ] = (fd_genesis_account_pair_t) {
    .key     = options->vote_pubkey,
    .account = (fd_genesis_account_t) {
      .lamports   = vote_min_bal,
      .data_len   = FD_VOTE_STATE_V3_SZ,
      .data       = vote_state_data,
      .owner      = fd_solana_vote_program_id
    }
  };

  /* Set up primordial accounts */

  ulong default_funded_balance = options->fund_initial_amount_lamports;
  for( ulong j=0UL; j<default_funded_cnt; j++ ) {
    fd_genesis_account_pair_t * pair = &genesis->accounts[ default_funded_idx+j ];

    uchar privkey[ 32 ] = {0};
    FD_STORE( ulong, privkey, j );
    fd_sha512_t sha[1];
    fd_ed25519_public_from_private( pair->key.key, privkey, sha );

    pair->account = (fd_genesis_account_t) {
      .lamports   = default_funded_balance,
      .data_len   = 0UL,
      .owner      = fd_solana_system_program_id
    };
  }

#define FEATURE_ENABLED_SZ 9UL
  static const uchar feature_enabled_data[ FEATURE_ENABLED_SZ ] = { 1, 0, 0, 0, 0, 0, 0, 0, 0 };
  ulong default_feature_enabled_balance = fd_rent_exempt_minimum_balance( &genesis->rent, FEATURE_ENABLED_SZ );

  /* Set up feature gate accounts */
  for( ulong j=0UL; j<feature_cnt; j++ ) {
    fd_genesis_account_pair_t * pair = &genesis->accounts[ feature_gate_idx+j ];

    pair->key     = features[ j ];
    pair->account = (fd_genesis_account_t) {
      .lamports   = default_feature_enabled_balance,
      .data_len   = FEATURE_ENABLED_SZ,
      .data       = (uchar *)feature_enabled_data,
      .owner      = fd_solana_feature_program_id
    };
  }
#undef FEATURE_ENABLED_SZ

  /* Set up the alpenglow genesis accounts.  Both are owned by the
     system program and sit at off curve addresses derived under the
     alpenglow feature gate pubkey.  See the layout comments at the top
     of this file. */

  uchar alpenglow_cert_data     [ FD_ALPENGLOW_GENESIS_CERT_SZ    ] = {0};
  uchar alpenglow_inflation_data[ FD_ALPENGLOW_EPOCH_INFLATION_SZ ] = {0};

  if( options->alpenglow ) {
    fd_pubkey_t const * alpenglow_program_id = &ids[ offsetof(fd_features_t, alpenglow)>>3 ].id;

    uchar bump;
    uint  custom_err;

    /* Genesis certificate.  It certifies slot 0 with a zero block id,
       a zero signature and an empty signer bitmap, which is what makes
       agave treat every later slot as an alpenglow block.  Every byte
       is zero except the length prefix of the bitmap vector. */

    FD_STORE( ulong, alpenglow_cert_data+8UL+32UL+FD_ALPENGLOW_BLS_SIGNATURE_AFFINE_SZ,
              FD_ALPENGLOW_CERT_BITMAP_SZ );

    uchar const * const cert_seeds   [1] = { (uchar const *)FD_ALPENGLOW_GENESIS_CERT_SEED };
    ulong         const cert_seed_szs[1] = { sizeof(FD_ALPENGLOW_GENESIS_CERT_SEED)-1UL };

    fd_genesis_account_pair_t * cert_pair = &genesis->accounts[ alpenglow_idx ];
    REQUIRE( !fd_pubkey_find_program_address( alpenglow_program_id, 1UL, cert_seeds, cert_seed_szs,
                                              &cert_pair->key, &bump, &custom_err ) );
    cert_pair->account = (fd_genesis_account_t) {
      .lamports = fd_rent_exempt_minimum_balance( &genesis->rent, FD_ALPENGLOW_GENESIS_CERT_SZ ),
      .data_len = FD_ALPENGLOW_GENESIS_CERT_SZ,
      .data     = alpenglow_cert_data,
      .owner    = fd_solana_system_program_id
    };

    /* Epoch inflation state.  Nothing has been earned yet in epoch 0
       and there is no previous epoch, so only slots_per_epoch is
       non-zero. */

    FD_STORE( ulong, alpenglow_inflation_data+8UL, genesis->epoch_schedule.slots_per_epoch );

    uchar const * const infl_seeds   [1] = { (uchar const *)FD_ALPENGLOW_EPOCH_INFLATION_SEED };
    ulong         const infl_seed_szs[1] = { sizeof(FD_ALPENGLOW_EPOCH_INFLATION_SEED)-1UL };

    fd_genesis_account_pair_t * infl_pair = &genesis->accounts[ alpenglow_idx+1UL ];
    REQUIRE( !fd_pubkey_find_program_address( alpenglow_program_id, 1UL, infl_seeds, infl_seed_szs,
                                              &infl_pair->key, &bump, &custom_err ) );
    infl_pair->account = (fd_genesis_account_t) {
      .lamports = fd_ulong_max( 1UL, fd_rent_exempt_minimum_balance( &genesis->rent, FD_ALPENGLOW_EPOCH_INFLATION_SZ ) ),
      .data_len = FD_ALPENGLOW_EPOCH_INFLATION_SZ,
      .data     = alpenglow_inflation_data,
      .owner    = fd_solana_system_program_id
    };
  }

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

  ulong encoded_sz = genesis_encode( genesis, (uchar *)buf, bufsz );
  if( FD_UNLIKELY( !encoded_sz ) ) {
    FD_LOG_WARNING(( "Failed to encode genesis blob (bufsz=%lu)", bufsz ));
    return 0UL;
  }
  return encoded_sz;

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
