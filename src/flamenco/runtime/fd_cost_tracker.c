#include "fd_cost_tracker.h"
#include "fd_system_ids.h"
#include "fd_bank.h"
#include "fd_runtime.h"
#include "../features/fd_features.h"
#include "../vm/fd_vm_base.h"

struct account_cost {
  fd_pubkey_t account;
  ulong       cost;

  struct {
    ulong next;
  } map;
};

typedef struct account_cost account_cost_t;

#define MAP_NAME               account_cost_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              account_cost_t
#define MAP_KEY                account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               map.next
#include "../../util/tmpl/fd_map_chain.c"

struct cost_tracker_outer {
  fd_cost_tracker_t cost_tracker[1];
  ulong             pool_offset;
  ulong             accounts_used;
  ulong             magic;
};

typedef struct cost_tracker_outer cost_tracker_outer_t;

FD_FN_CONST ulong
fd_cost_tracker_align( void ) {
  return FD_COST_TRACKER_ALIGN;
}

FD_FN_CONST ulong
fd_cost_tracker_footprint( void ) {
  ulong map_chain_cnt = account_cost_map_chain_cnt_est( FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_cost_tracker_align(),  sizeof(cost_tracker_outer_t) );
  l = FD_LAYOUT_APPEND( l,  account_cost_map_align(), account_cost_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l,  alignof(account_cost_t),  FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT*sizeof(account_cost_t) );
  return FD_LAYOUT_FINI( l, fd_cost_tracker_align() );
}

void *
fd_cost_tracker_new( void * shmem,
                     int    larger_max_cost_per_block,
                     ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_cost_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong map_chain_cnt = account_cost_map_chain_cnt_est( FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  cost_tracker_outer_t * cost_tracker = FD_SCRATCH_ALLOC_APPEND( l, fd_cost_tracker_align(),  sizeof(cost_tracker_outer_t) );
  void * _map                         = FD_SCRATCH_ALLOC_APPEND( l, account_cost_map_align(), account_cost_map_footprint( map_chain_cnt ) );
  void * _accounts                    = FD_SCRATCH_ALLOC_APPEND( l, alignof(account_cost_t),  FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT*sizeof(account_cost_t) );

  account_cost_map_t * map = account_cost_map_join( account_cost_map_new( _map, map_chain_cnt, seed ) );
  FD_TEST( map );

  cost_tracker->pool_offset = (ulong)_accounts-(ulong)cost_tracker;

  cost_tracker->cost_tracker->larger_max_cost_per_block = larger_max_cost_per_block;

  (void)_accounts;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cost_tracker->magic ) = FD_COST_TRACKER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_cost_tracker_t *
fd_cost_tracker_join( void * shct ) {
  if( FD_UNLIKELY( !shct ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shct, fd_cost_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  cost_tracker_outer_t * cost_tracker = (cost_tracker_outer_t *)shct;

  if( FD_UNLIKELY( cost_tracker->magic!=FD_COST_TRACKER_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid cost tracker magic" ));
    return NULL;
  }

  return cost_tracker->cost_tracker;
}

void
fd_cost_tracker_init( fd_cost_tracker_t *   cost_tracker,
                      fd_features_t const * features,
                      ulong                 slot ) {
  if( FD_FEATURE_ACTIVE( slot, features, raise_block_limits_to_100m ) ) {
    cost_tracker->block_cost_limit   = FD_MAX_BLOCK_UNITS_SIMD_0286;
    cost_tracker->vote_cost_limit    = FD_MAX_VOTE_UNITS;
    cost_tracker->account_cost_limit = FD_MAX_WRITABLE_ACCOUNT_UNITS;
  } else if( FD_FEATURE_ACTIVE( slot, features, raise_block_limits_to_60m ) ) {
    cost_tracker->block_cost_limit   = FD_MAX_BLOCK_UNITS_SIMD_0256;
    cost_tracker->vote_cost_limit    = FD_MAX_VOTE_UNITS;
    cost_tracker->account_cost_limit = FD_MAX_WRITABLE_ACCOUNT_UNITS;
  } else {
    cost_tracker->block_cost_limit   = FD_MAX_BLOCK_UNITS_SIMD_0207;
    cost_tracker->vote_cost_limit    = FD_MAX_VOTE_UNITS;
    cost_tracker->account_cost_limit = FD_MAX_WRITABLE_ACCOUNT_UNITS;
  }

  if( FD_UNLIKELY( cost_tracker->larger_max_cost_per_block ) ) cost_tracker->block_cost_limit = LARGER_MAX_COST_PER_BLOCK;

  /* https://github.com/anza-xyz/agave/blob/v3.0.1/runtime/src/bank.rs#L4059-L4066 */
  if( FD_FEATURE_ACTIVE( slot, features, raise_account_cu_limit ) ) {
    cost_tracker->account_cost_limit = fd_ulong_sat_mul( cost_tracker->block_cost_limit, 40UL ) / 100UL;
  }

  cost_tracker->block_cost                   = 0UL;
  cost_tracker->vote_cost                    = 0UL;
  cost_tracker->allocated_accounts_data_size = 0UL;

  cost_tracker_outer_t * outer = fd_type_pun( cost_tracker );
  outer->accounts_used = 0UL;
  account_cost_map_reset( fd_type_pun( outer+1UL ) );
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L313-L321 */
FD_FN_PURE static inline ulong
get_instructions_data_cost( fd_txn_in_t const * txn_in ) {
  ulong total_instr_data_sz = 0UL;
  for( ushort i=0; i<TXN( txn_in->txn )->instr_cnt; i++ ) {
    total_instr_data_sz += TXN( txn_in->txn )->instr[ i ].data_sz;
  }
  return total_instr_data_sz / FD_PACK_INV_COST_PER_INSTR_DATA_BYTE;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L152-L187 */
FD_FN_PURE static inline ulong
get_signature_cost( fd_txn_in_t const * txn_in, fd_bank_t * bank ) {
  fd_txn_t const *       txn      = TXN( txn_in->txn );
  void const *           payload  = txn_in->txn->payload;
  fd_acct_addr_t const * accounts = fd_txn_get_acct_addrs( txn, payload );

  /* Compute signature counts (both normal + precompile)
     TODO: Factor this logic out into a shared function that can be used
     both here and in fd_pack_cost.h */
  ulong signature_cost                       = fd_ulong_sat_mul( txn->signature_cnt, FD_PACK_COST_PER_SIGNATURE );
  ulong num_secp256k1_instruction_signatures = 0UL;
  ulong num_ed25519_instruction_signatures   = 0UL;
  ulong num_secp256r1_instruction_signatures = 0UL;

  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn->instr[ i ];
    if( instr->data_sz==0UL ) continue;

    fd_acct_addr_t const * prog_id    = accounts + instr->program_id;
    uchar const *          instr_data = fd_txn_get_instr_data( instr, payload );

    if( fd_memeq( prog_id, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t) ) ) {
      num_ed25519_instruction_signatures += (ulong)instr_data[ 0 ];
    } else if( fd_memeq( prog_id, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t) ) ) {
      num_secp256k1_instruction_signatures += (ulong)instr_data[ 0 ];
    } else if( fd_memeq( prog_id, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t) ) ) {
      num_secp256r1_instruction_signatures += (ulong)instr_data[ 0 ];
    }
  }

  /* No direct permalink, just factored out for readability */
  ulong secp256k1_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_SECP256K1_SIGNATURE, num_secp256k1_instruction_signatures );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L155-L160 */
  ulong ed25519_verify_cost;
  if( FD_FEATURE_ACTIVE_BANK( bank, ed25519_precompile_verify_strict ) ) {
    ed25519_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_ED25519_SIGNATURE, num_ed25519_instruction_signatures );
  } else {
    ed25519_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_NON_STRICT_ED25519_SIGNATURE, num_ed25519_instruction_signatures );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L162-L167 */
  ulong secp256r1_verify_cost = 0UL;
  if( FD_FEATURE_ACTIVE_BANK( bank, enable_secp256r1_precompile ) ) {
    secp256r1_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_SECP256R1_SIGNATURE, num_secp256r1_instruction_signatures );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L169-L186 */
  return fd_ulong_sat_add( signature_cost,
                           fd_ulong_sat_add( secp256k1_verify_cost,
                                             fd_ulong_sat_add( ed25519_verify_cost,
                                                               secp256r1_verify_cost ) ) );
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L190-L192 */
FD_FN_PURE static inline ulong
get_write_lock_cost( ulong num_write_locks ) {
  return fd_ulong_sat_mul( num_write_locks, FD_WRITE_LOCK_UNITS );
}

/* Loop through all instructions here and deserialize the instruction data to try to determine any
   system program allocations done.

   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L367-L386 */
static inline ulong
calculate_allocated_accounts_data_size( fd_txn_in_t const * txn_in ) {
  fd_txn_t const * txn     = TXN( txn_in->txn );
  void const *     payload = txn_in->txn->payload;

  ulong allocated_accounts_data_size = 0UL;
  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr      = &txn->instr[ i ];
    fd_acct_addr_t const * accounts   = fd_txn_get_acct_addrs( txn, payload );
    fd_acct_addr_t const * prog_id    = accounts + instr->program_id;
    uchar const *          instr_data = fd_txn_get_instr_data( instr, payload );

    if( instr->data_sz==0UL || !fd_memeq( prog_id, &fd_solana_system_program_id, sizeof(fd_pubkey_t) ) ) continue;

    fd_bincode_decode_ctx_t ctx = {
      .data    = instr_data,
      .dataend = instr_data + instr->data_sz,
    };

    ulong total_sz = 0UL;
    int err = fd_system_program_instruction_decode_footprint( &ctx, &total_sz );
    if( FD_UNLIKELY( err ) ) continue;

    uchar buf[total_sz];
    fd_system_program_instruction_t * instruction = fd_system_program_instruction_decode( buf, &ctx );
    if( FD_UNLIKELY( !instruction ) ) continue;

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L330-L346 */
    ulong space = 0UL;

    switch( instruction->discriminant ) {
      case fd_system_program_instruction_enum_create_account: {
        space = instruction->inner.create_account.space;
        break;
      }
      case fd_system_program_instruction_enum_create_account_with_seed: {
        space = instruction->inner.create_account_with_seed.space;
        break;
      }
      case fd_system_program_instruction_enum_allocate: {
        space = instruction->inner.allocate;
        break;
      }
      case fd_system_program_instruction_enum_allocate_with_seed: {
        space = instruction->inner.allocate_with_seed.space;
        break;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L373-L380 */
    if( FD_UNLIKELY( space>FD_RUNTIME_ACC_SZ_MAX ) ) return 0UL;

    allocated_accounts_data_size = fd_ulong_sat_add( allocated_accounts_data_size, space );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L396-L397 */
  return fd_ulong_min( 2UL*FD_RUNTIME_ACC_SZ_MAX, allocated_accounts_data_size );
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L123-L149 */
static inline fd_transaction_cost_t
calculate_non_vote_transaction_cost( fd_bank_t *          bank,
                                     fd_txn_in_t const *  txn_in,
                                     fd_txn_out_t const * txn_out,
                                     ulong                loaded_accounts_data_size_cost,
                                     ulong                data_bytes_cost ) {

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L132 */
  ulong signature_cost = get_signature_cost( txn_in, bank );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L133 */
  ulong write_lock_cost = get_write_lock_cost( fd_txn_account_cnt( TXN( txn_in->txn ), FD_TXN_ACCT_CAT_WRITABLE ) );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L135-L136 */
  ulong allocated_accounts_data_size = calculate_allocated_accounts_data_size( txn_in );

  return (fd_transaction_cost_t) {
    .type = FD_TXN_COST_TYPE_TRANSACTION,
    .transaction = {
      .signature_cost                 = signature_cost,
      .write_lock_cost                = write_lock_cost,
      .data_bytes_cost                = data_bytes_cost,
      .programs_execution_cost        = fd_ulong_sat_sub( txn_out->details.compute_budget.compute_unit_limit,
                                                          txn_out->details.compute_budget.compute_meter ),
      .loaded_accounts_data_size_cost = loaded_accounts_data_size_cost,
      .allocated_accounts_data_size   = allocated_accounts_data_size,
    }
  };
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L26-L42 */
FD_FN_PURE static inline ulong
transaction_cost_sum( fd_transaction_cost_t const * txn_cost ) {
  switch( txn_cost->type ) {
    case FD_TXN_COST_TYPE_SIMPLE_VOTE: {
      /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L38 */
      return FD_PACK_SIMPLE_VOTE_COST;
    }
    case FD_TXN_COST_TYPE_TRANSACTION: {
      /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L164-L171 */
      fd_usage_cost_details_t const * usage_cost = &txn_cost->transaction;
      ulong                           cost       = 0UL;

      cost = fd_ulong_sat_add( cost, usage_cost->signature_cost );
      cost = fd_ulong_sat_add( cost, usage_cost->write_lock_cost );
      cost = fd_ulong_sat_add( cost, usage_cost->data_bytes_cost );
      cost = fd_ulong_sat_add( cost, usage_cost->programs_execution_cost );
      cost = fd_ulong_sat_add( cost, usage_cost->loaded_accounts_data_size_cost );

      return cost;
    }
    default: {
      __builtin_unreachable();
    }
  }
}

FD_FN_PURE static inline ulong
get_allocated_accounts_data_size( fd_transaction_cost_t const * txn_cost ) {
  switch( txn_cost->type ) {
  case FD_TXN_COST_TYPE_SIMPLE_VOTE:
    return 0UL;
  case FD_TXN_COST_TYPE_TRANSACTION:
    return txn_cost->transaction.allocated_accounts_data_size;
  default:
    __builtin_unreachable();
  }
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L277-L322 */
static inline int
would_fit( fd_cost_tracker_t const *     cost_tracker,
           fd_txn_out_t *                txn_out,
           fd_transaction_cost_t const * tx_cost ) {

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L281 */
  ulong cost = transaction_cost_sum( tx_cost );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L283-L288 */
  if( tx_cost->type==FD_TXN_COST_TYPE_SIMPLE_VOTE ) {
    if( FD_UNLIKELY( fd_ulong_sat_add( cost_tracker->vote_cost, cost )>cost_tracker->vote_cost_limit ) ) {
      return FD_COST_TRACKER_ERROR_WOULD_EXCEED_VOTE_MAX_LIMIT;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L290-L293 */
  if( FD_UNLIKELY( fd_ulong_sat_add( cost_tracker->block_cost, cost )>cost_tracker->block_cost_limit ) ) {
    return FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L295-L298 */
  if( FD_UNLIKELY( cost>cost_tracker->account_cost_limit ) ) {
    return FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L300-L301 */
  ulong allocated_accounts_data_size = fd_ulong_sat_add( cost_tracker->allocated_accounts_data_size,
                                                         get_allocated_accounts_data_size( tx_cost ) );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L303-L304 */
  if( FD_UNLIKELY( allocated_accounts_data_size>FD_MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA ) ) {
    return FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L308-L319 */

  account_cost_map_t const * map = fd_type_pun_const(((cost_tracker_outer_t const *)cost_tracker)+1UL);
  account_cost_t const * pool = fd_type_pun_const( (void*)((ulong)cost_tracker + ((cost_tracker_outer_t const *)cost_tracker)->pool_offset) );

  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( txn_out->accounts.is_writable[i]==0 ) continue;

    fd_pubkey_t const * writable_acc = &txn_out->accounts.keys[i];

    account_cost_t const * chained_cost = account_cost_map_ele_query_const( map, writable_acc, NULL, pool );
    if( FD_UNLIKELY( chained_cost && fd_ulong_sat_add( chained_cost->cost, cost )>cost_tracker->account_cost_limit ) ) {
      return FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT;
    }
  }

  return FD_COST_TRACKER_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L352-L372 */
static inline void
add_transaction_execution_cost( fd_cost_tracker_t *           _cost_tracker,
                                fd_txn_out_t *                txn_out,
                                fd_transaction_cost_t const * tx_cost,
                                ulong                         adjustment ) {
  cost_tracker_outer_t * cost_tracker = fd_type_pun( _cost_tracker );
  account_cost_map_t * map = fd_type_pun( cost_tracker+1UL );
  account_cost_t * pool = fd_type_pun( (void*)((ulong)cost_tracker+cost_tracker->pool_offset) );

  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( FD_LIKELY( txn_out->accounts.is_writable[i]==0 ) ) continue;

    fd_pubkey_t const * writable_acc = &txn_out->accounts.keys[i];

    account_cost_t * account_cost = account_cost_map_ele_query( map, writable_acc, NULL, pool );
    if( FD_UNLIKELY( !account_cost ) ) {
      FD_TEST( cost_tracker->accounts_used<FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT );

      account_cost = pool+cost_tracker->accounts_used;
      cost_tracker->accounts_used++;

      account_cost->account = *writable_acc;
      account_cost->cost    = adjustment;

      account_cost_map_ele_insert( map, account_cost, pool );
    } else {
      account_cost->cost = fd_ulong_sat_add( account_cost->cost, adjustment );
    }
  }

  cost_tracker->cost_tracker->block_cost = fd_ulong_sat_add( cost_tracker->cost_tracker->block_cost, adjustment );
  if( FD_UNLIKELY( tx_cost->type==FD_TXN_COST_TYPE_SIMPLE_VOTE ) ) {
    cost_tracker->cost_tracker->vote_cost = fd_ulong_sat_add( cost_tracker->cost_tracker->vote_cost, adjustment );
  }
}



/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L323-L328 */
FD_FN_PURE ulong
fd_cost_tracker_calculate_loaded_accounts_data_size_cost( fd_txn_out_t const * txn_out ) {
  ulong cost = fd_ulong_sat_sub( fd_ulong_sat_add( txn_out->details.loaded_accounts_data_size,
                                                   FD_ACCOUNT_DATA_COST_PAGE_SIZE ),
                                 1UL );
  cost /= FD_ACCOUNT_DATA_COST_PAGE_SIZE;
  return fd_ulong_sat_mul( cost, FD_VM_HEAP_COST );
}

void
fd_cost_tracker_calculate_cost( fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/cost-model/src/cost_model.rs#L83-L85 */
  fd_transaction_cost_t * txn_cost = &txn_out->details.txn_cost;
  if( txn_out->details.is_simple_vote ) {
    txn_cost->type = FD_TXN_COST_TYPE_SIMPLE_VOTE;
  } else {
    /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L78-L81 */
    ulong loaded_accounts_data_size_cost = fd_cost_tracker_calculate_loaded_accounts_data_size_cost( txn_out );

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L82-L83 */
    ulong instructions_data_cost = get_instructions_data_cost( txn_in );

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L85-L93 */
    *txn_cost = calculate_non_vote_transaction_cost( bank, txn_in, txn_out, loaded_accounts_data_size_cost, instructions_data_cost );
  }
}

int
fd_cost_tracker_try_add_cost( fd_cost_tracker_t * cost_tracker,
                              fd_txn_out_t *      txn_out ) {

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L167 */
  int err = would_fit( cost_tracker, txn_out, &txn_out->details.txn_cost );
  if( FD_UNLIKELY( err!=FD_COST_TRACKER_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L325-L335 */

  /* We don't need `updated_costliest_account_cost` since it seems to be
     for a different use case other than validating block cost limits.
     https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L168 */

  /* Note: We purposely omit signature counts updates since they're not relevant to cost calculations right now. */
  cost_tracker->allocated_accounts_data_size += get_allocated_accounts_data_size( &txn_out->details.txn_cost );
  add_transaction_execution_cost( cost_tracker, txn_out, &txn_out->details.txn_cost, transaction_cost_sum( &txn_out->details.txn_cost ) );
  return FD_COST_TRACKER_SUCCESS;
}
