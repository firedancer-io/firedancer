/* Test fee_calculator correctness in nonce accounts and blockhash
   registration.  Regression for 6a6861d / f86def8. */

#include "fd_svm_mini.h"
#include "../fd_system_ids.h"
#include "../fd_blockhashes.h"
#include "../program/fd_system_program.h"
#include "../../../disco/fd_txn_p.h"
#include "../../types/fd_types.h"
#include "../fd_runtime_const.h"

#define FEE_A (7000UL)
#define FEE_B (3000UL)

#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  if( FD_UNLIKELY( (*_cur_data)+_sz>_begin+FD_TXN_MTU ) ) return;                    \
  fd_memcpy( *_cur_data, _to_add, _sz );                                             \
  *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                               \
     uchar _buf[3];                                                                  \
     fd_bincode_encode_ctx_t _encode_ctx = { .data = _buf, .dataend = _buf+3 };      \
     fd_bincode_compact_u16_encode( &_to_add, &_encode_ctx );                        \
     ulong _sz = (ulong) ((uchar *)_encode_ctx.data - _buf );                        \
     FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                     \
  } while(0);                                                                        \
})

struct txn_instr {
  uchar   program_id_idx;
  uchar * account_idxs;
  ushort  account_idxs_cnt;
  uchar * data;
  ushort  data_sz;
};
typedef struct txn_instr txn_instr_t;

static void
txn_serialize( fd_txn_p_t *     out,
               ulong            num_signers,
               ulong            num_readonly_unsigned,
               ulong            account_keys_cnt,
               fd_pubkey_t *    account_keys,
               fd_hash_t *      recent_blockhash,
               txn_instr_t *    instrs,
               ushort           instr_cnt ) {
  uchar * txn_raw_begin   = out->payload;
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = (uchar)num_signers;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i=0; i<signature_cnt; i++ ) {
    fd_signature_t sig = {0};
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &sig, FD_TXN_SIGNATURE_SZ );
  }

  uchar header_b0 = (uchar)0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  uchar num_req_sigs    = (uchar)num_signers;
  uchar num_ro_signed   = 0;
  uchar num_ro_unsigned = (uchar)num_readonly_unsigned;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_req_sigs,    1 );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_signed,   1 );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_unsigned, 1 );

  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i=0; i<num_acct_keys; i++ ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_keys[i], sizeof(fd_pubkey_t) );
  }

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_cnt );
  for( ushort i=0; i<instr_cnt; i++ ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &instrs[i].program_id_idx, sizeof(uchar) );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data_sz );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data, instrs[i].data_sz );
  }

  ushort addr_table_cnt = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  out->payload_sz = (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

static void
durable_nonce_from_blockhash( fd_hash_t *       out,
                              fd_hash_t const * blockhash ) {
  uchar buf[45];
  memcpy( buf,    "DURABLE_NONCE", 13UL );
  memcpy( buf+13, blockhash,       sizeof(fd_hash_t) );
  fd_sha256_hash( buf, sizeof(buf), out );
}

static void
create_nonce_account_initialized( fd_svm_mini_t *        mini,
                                  fd_accdb_fork_id_t     fork_id,
                                  fd_pubkey_t const *    nonce_pubkey,
                                  fd_pubkey_t const *    authority,
                                  fd_hash_t const *      durable_nonce,
                                  ulong                  fee_lamports_per_sig ) {
  fd_nonce_state_versions_t state = {
    .version                = FD_NONCE_VERSION_CURRENT,
    .kind                   = FD_NONCE_STATE_INITIALIZED,
    .authority              = *authority,
    .durable_nonce          = *durable_nonce,
    .lamports_per_signature = fee_lamports_per_sig
  };

  uchar nonce_data[ FD_SYSTEM_PROGRAM_NONCE_DLEN ] = {0};
  ulong written = 0UL;
  FD_TEST( fd_nonce_state_versions_encode( &state, nonce_data, FD_SYSTEM_PROGRAM_NONCE_DLEN, &written )==0 );

  fd_accdb_t * accdb = mini->runtime->accdb;
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, fork_id, nonce_pubkey->key, 1, 0 );
  fd_memcpy( entry.data, nonce_data, FD_SYSTEM_PROGRAM_NONCE_DLEN );
  entry.data_len = FD_SYSTEM_PROGRAM_NONCE_DLEN;
  entry.lamports = 10000000UL;
  fd_memcpy( entry.owner, fd_solana_system_program_id.key, 32UL );
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );
}

static void
create_nonce_account_uninitialized( fd_svm_mini_t *        mini,
                                    fd_accdb_fork_id_t     fork_id,
                                    fd_pubkey_t const *    nonce_pubkey ) {
  fd_nonce_state_versions_t state = {
    .version = FD_NONCE_VERSION_CURRENT,
    .kind    = FD_NONCE_STATE_UNINITIALIZED
  };

  uchar nonce_data[ FD_SYSTEM_PROGRAM_NONCE_DLEN ] = {0};
  ulong written = 0UL;
  FD_TEST( fd_nonce_state_versions_encode( &state, nonce_data, FD_SYSTEM_PROGRAM_NONCE_DLEN, &written )==0 );

  fd_accdb_t * accdb = mini->runtime->accdb;
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, fork_id, nonce_pubkey->key, 1, 0 );
  fd_memcpy( entry.data, nonce_data, FD_SYSTEM_PROGRAM_NONCE_DLEN );
  entry.data_len = FD_SYSTEM_PROGRAM_NONCE_DLEN;
  entry.lamports = 10000000UL;
  fd_memcpy( entry.owner, fd_solana_system_program_id.key, 32UL );
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );
}

static ulong
read_nonce_fee( fd_svm_mini_t *        mini,
                fd_accdb_fork_id_t     fork_id,
                fd_pubkey_t const *    nonce_pubkey ) {
  fd_accdb_t * accdb = mini->runtime->accdb;
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, nonce_pubkey->key );

  fd_nonce_state_versions_t state = {0};
  FD_TEST( fd_nonce_state_versions_decode(
      &state, entry.data, entry.data_len )==0 );
  fd_accdb_unread_one( accdb, &entry );

  FD_TEST( state.version == FD_NONCE_VERSION_CURRENT );
  FD_TEST( state.kind    == FD_NONCE_STATE_INITIALIZED );
  return state.lamports_per_signature;
}

static ulong
read_lamports( fd_svm_mini_t *        mini,
               fd_accdb_fork_id_t     fork_id,
               fd_pubkey_t const *    pubkey ) {
  return fd_accdb_lamports( mini->runtime->accdb, fork_id, pubkey->key );
}

/* Helper: set up root -> slot 2 (frozen with FEE_A) -> slot 3 (FEE_B).
   Returns slot 3's bank_idx. */

struct test_env {
  fd_bank_t *        bank;
  fd_accdb_fork_id_t fork_id;
  fd_hash_t          genesis_hash;
};

static struct test_env
setup_two_fee_slots( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong slot2_idx   = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t * slot2 = fd_svm_mini_bank( mini, slot2_idx );
  slot2->f.rbh_lamports_per_sig = FEE_A;
  fd_svm_mini_freeze( mini, slot2_idx );
  fd_svm_mini_advance_root( mini, slot2_idx );

  ulong child_idx         = fd_svm_mini_attach_child( mini, slot2_idx, 3UL );
  fd_bank_t *        bank = fd_svm_mini_bank( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );
  bank->f.rbh_lamports_per_sig = FEE_B;

  fd_hash_t genesis_hash = {0};
  fd_memset( genesis_hash.uc, 0xAB, FD_HASH_FOOTPRINT );

  return (struct test_env){ .bank = bank, .fork_id = fork_id, .genesis_hash = genesis_hash };
}

static void
execute_txn( fd_svm_mini_t * mini,
             fd_bank_t *     bank,
             fd_txn_p_t *    txn_p,
             fd_txn_out_t *  txn_out ) {
  fd_txn_in_t txn_in = {0};
  txn_in.txn              = txn_p;
  txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, &txn_in, txn_out );
}

/* AdvanceNonceAccount: nonce fee_calculator comes from the blockhash
   queue entry, not bank->rbh_lamports_per_sig. */

static void
test_advance_nonce_fee( fd_svm_mini_t * mini ) {
  struct test_env env = setup_two_fee_slots( mini );

  fd_blockhash_info_t const * last_bh =
      fd_blockhashes_peek_last( &env.bank->f.block_hash_queue );
  FD_TEST( last_bh );
  FD_TEST( last_bh->lamports_per_signature == FEE_A );

  fd_hash_t durable_nonce;
  durable_nonce_from_blockhash( &durable_nonce, &env.genesis_hash );

  fd_pubkey_t fee_payer_key = { .ul[0] = 0xFEE1UL };
  fd_pubkey_t nonce_key     = { .ul[0] = 0xAAAAUL };

  fd_svm_mini_add_lamports( mini, env.fork_id, &fee_payer_key, 10000000000UL );
  create_nonce_account_initialized( mini, env.fork_id, &nonce_key, &fee_payer_key,
                                    &durable_nonce, FEE_A );

  ulong payer_before = read_lamports( mini, env.fork_id, &fee_payer_key );

  fd_pubkey_t tx_keys[4] = {
    fee_payer_key, nonce_key,
    fd_sysvar_recent_block_hashes_id, fd_solana_system_program_id,
  };
  uchar ix_accts[3] = { 1, 2, 0 };
  uchar ix_data[4]  = { 4, 0, 0, 0 };
  txn_instr_t instrs[1] = {{
    .program_id_idx = 3, .account_idxs = ix_accts,
    .account_idxs_cnt = 3, .data = ix_data, .data_sz = 4,
  }};

  fd_txn_p_t txn_p = {0};
  txn_serialize( &txn_p, 1UL, 2UL, 4UL, tx_keys, &durable_nonce, instrs, 1 );
  FD_TEST( fd_txn_parse( txn_p.payload, txn_p.payload_sz, TXN( &txn_p ), NULL ) );

  fd_txn_out_t txn_out[1] = {0};
  execute_txn( mini, env.bank, &txn_p, txn_out );

  FD_TEST( txn_out->err.is_committable );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  fd_runtime_commit_txn( mini->runtime, env.bank, txn_out );

  FD_TEST( read_nonce_fee( mini, env.fork_id, &nonce_key ) == FEE_A );
  FD_TEST( payer_before - read_lamports( mini, env.fork_id, &fee_payer_key ) == FD_RUNTIME_FEE_STRUCTURE_LAMPORTS_PER_SIGNATURE );

  FD_LOG_NOTICE(( "test_advance_nonce_fee: PASSED" ));
}

/* InitializeNonceAccount: fee_calculator comes from the blockhash
   queue entry, not bank->rbh_lamports_per_sig. */

static void
test_initialize_nonce_fee( fd_svm_mini_t * mini ) {
  struct test_env env = setup_two_fee_slots( mini );

  fd_pubkey_t fee_payer_key = { .ul[0] = 0xFEE2UL };
  fd_pubkey_t nonce_key     = { .ul[0] = 0xBBBBUL };

  fd_svm_mini_add_lamports( mini, env.fork_id, &fee_payer_key, 10000000000UL );
  create_nonce_account_uninitialized( mini, env.fork_id, &nonce_key );

  fd_blockhash_info_t const * last_bh =
      fd_blockhashes_peek_last( &env.bank->f.block_hash_queue );
  FD_TEST( last_bh );

  fd_pubkey_t tx_keys[5] = {
    fee_payer_key, nonce_key,
    fd_sysvar_recent_block_hashes_id, fd_sysvar_rent_id,
    fd_solana_system_program_id,
  };
  uchar ix_accts[3] = { 1, 2, 3 };
  uchar ix_data[36];
  FD_STORE( uint, ix_data, 6U ); /* InitializeNonceAccount discriminant */
  memcpy( ix_data + 4, fee_payer_key.key, 32 );

  txn_instr_t instrs[1] = {{
    .program_id_idx = 4, .account_idxs = ix_accts,
    .account_idxs_cnt = 3, .data = ix_data, .data_sz = 36,
  }};

  fd_txn_p_t txn_p = {0};
  fd_hash_t blockhash = last_bh->hash;
  txn_serialize( &txn_p, 1UL, 3UL, 5UL, tx_keys, &blockhash, instrs, 1 );
  FD_TEST( fd_txn_parse( txn_p.payload, txn_p.payload_sz, TXN( &txn_p ), NULL ) );

  fd_txn_out_t txn_out[1] = {0};
  execute_txn( mini, env.bank, &txn_p, txn_out );

  FD_TEST( txn_out->err.is_committable );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  fd_runtime_commit_txn( mini->runtime, env.bank, txn_out );

  FD_TEST( read_nonce_fee( mini, env.fork_id, &nonce_key ) == FEE_A );

  FD_LOG_NOTICE(( "test_initialize_nonce_fee: PASSED" ));
}

/* Freeze stamps the blockhash queue entry with the bank's current
   rbh_lamports_per_sig. */

static void
test_blockhash_registration_fee( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong slot2_idx   = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t * slot2 = fd_svm_mini_bank( mini, slot2_idx );
  slot2->f.rbh_lamports_per_sig = 12345UL;
  fd_svm_mini_freeze( mini, slot2_idx );

  fd_blockhash_info_t const * last =
      fd_blockhashes_peek_last( &slot2->f.block_hash_queue );
  FD_TEST( last );
  FD_TEST( last->lamports_per_signature == 12345UL );

  FD_LOG_NOTICE(( "test_blockhash_registration_fee: PASSED" ));
}

/* Fee rate governor updates rbh_lamports_per_sig between blocks based
   on parent_signature_cnt vs target_signatures_per_slot. */

static void
test_fee_rate_governor_derived( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root = fd_svm_mini_bank( mini, root_idx );

  root->f.fee_rate_governor = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = 10000UL,
    .target_signatures_per_slot    = 100UL,
    .min_lamports_per_signature    = 0UL,
    .max_lamports_per_signature    = 100000UL,
    .burn_percent                  = 50,
  };
  root->f.rbh_lamports_per_sig = 5000UL;

  root->f.signature_count = 200UL;

  ulong slot2_idx   = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t * slot2 = fd_svm_mini_bank( mini, slot2_idx );

  FD_TEST( slot2->f.rbh_lamports_per_sig > 5000UL );

  fd_svm_mini_freeze( mini, slot2_idx );

  ulong slot2_fee = slot2->f.rbh_lamports_per_sig;
  slot2->f.signature_count = 0UL;

  fd_svm_mini_advance_root( mini, slot2_idx );
  ulong slot3_idx   = fd_svm_mini_attach_child( mini, slot2_idx, 3UL );
  fd_bank_t * slot3 = fd_svm_mini_bank( mini, slot3_idx );

  FD_TEST( slot3->f.rbh_lamports_per_sig < slot2_fee );

  FD_LOG_NOTICE(( "test_fee_rate_governor_derived: PASSED" ));
}

/* Nonce transaction whose durable_nonce matches the current slot's
   derivation is rejected as already advanced. */

static void
test_advance_nonce_already_advanced( fd_svm_mini_t * mini ) {
  struct test_env env = setup_two_fee_slots( mini );

  fd_blockhash_info_t const * last_bh =
      fd_blockhashes_peek_last( &env.bank->f.block_hash_queue );
  FD_TEST( last_bh );

  fd_hash_t durable_nonce;
  durable_nonce_from_blockhash( &durable_nonce, &last_bh->hash );

  fd_pubkey_t fee_payer_key = { .ul[0] = 0xFEE3UL };
  fd_pubkey_t nonce_key     = { .ul[0] = 0xCCCCUL };

  fd_svm_mini_add_lamports( mini, env.fork_id, &fee_payer_key, 10000000000UL );
  create_nonce_account_initialized( mini, env.fork_id, &nonce_key, &fee_payer_key,
                                    &durable_nonce, FEE_A );

  fd_pubkey_t tx_keys[4] = {
    fee_payer_key, nonce_key,
    fd_sysvar_recent_block_hashes_id, fd_solana_system_program_id,
  };
  uchar ix_accts[3] = { 1, 2, 0 };
  uchar ix_data[4]  = { 4, 0, 0, 0 };
  txn_instr_t instrs[1] = {{
    .program_id_idx = 3, .account_idxs = ix_accts,
    .account_idxs_cnt = 3, .data = ix_data, .data_sz = 4,
  }};

  fd_txn_p_t txn_p = {0};
  txn_serialize( &txn_p, 1UL, 2UL, 4UL, tx_keys, &durable_nonce, instrs, 1 );
  FD_TEST( fd_txn_parse( txn_p.payload, txn_p.payload_sz, TXN( &txn_p ), NULL ) );

  fd_txn_out_t txn_out[1] = {0};
  execute_txn( mini, env.bank, &txn_p, txn_out );

  FD_TEST( !txn_out->err.is_committable );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED );

  FD_LOG_NOTICE(( "test_advance_nonce_already_advanced: PASSED" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_advance_nonce_fee( mini );
  test_initialize_nonce_fee( mini );
  test_blockhash_registration_fee( mini );
  test_fee_rate_governor_derived( mini );
  test_advance_nonce_already_advanced( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
