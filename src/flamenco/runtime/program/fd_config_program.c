#include "fd_config_program.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../../log_collector/fd_log_collector.h"

/* Useful links:

   https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs */

#define DEFAULT_COMPUTE_UNITS 450UL

/* The bound on the number of keys that could get passed into the config
   program is bounded by the TXN_MTU of 1232 bytes.  Assuming that the
   vector of config keys comprises the entire transaction, then we can
   have 1232(bytes)/(33 bytes/key) = 37 keys.  So our bound is equal to
   sizeof(fd_config_keys_t) + 37*sizeof(fd_config_keys_pair_t) = 1237 bytes. */

#define CONFIG_INSTRUCTION_KEYS_FOOTPRINT (1237UL)

/* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L16 */

static int
_process_config_instr( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_CONFIG ((uchar)0)

  int err;

  /* Deserialize the Config Program instruction data, which consists only of the ConfigKeys
     https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L21 */
  if( FD_UNLIKELY( ctx->instr->data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
  if( FD_UNLIKELY( ctx->instr->data_sz>FD_TXN_MTU ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  int decode_result;
  uchar key_list_mem[ CONFIG_INSTRUCTION_KEYS_FOOTPRINT ] __attribute__((aligned(FD_CONFIG_KEYS_ALIGN)));
  fd_config_keys_t * key_list = fd_bincode_decode_static(
      config_keys, key_list_mem,
      ctx->instr->data,
      ctx->instr->data_sz,
      &decode_result );
  if( FD_UNLIKELY( decode_result != FD_BINCODE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L22-L26 */

  int                 is_config_account_signer = 0;
  fd_pubkey_t const * config_account_key       = NULL;

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/config/src/config_processor.rs#L26 */
  fd_guarded_borrowed_account_t config_acc_rec = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_CONFIG, &config_acc_rec );

  config_account_key = config_acc_rec.pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L27 */

  is_config_account_signer = fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_CONFIG, NULL );

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L29-L31 */

  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &config_acc_rec ), fd_solana_config_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L33-L40 */

  uchar current_data_mem[ CONFIG_INSTRUCTION_KEYS_FOOTPRINT ] __attribute__((aligned(FD_CONFIG_KEYS_ALIGN)));
  fd_config_keys_t * current_data = fd_bincode_decode_static(
      config_keys, current_data_mem,
      fd_borrowed_account_get_data( &config_acc_rec ),
      fd_borrowed_account_get_data_len( &config_acc_rec ),
      &decode_result );
  if( FD_UNLIKELY( decode_result!=FD_BINCODE_SUCCESS ) ) {
    //TODO: full log, including err
    fd_log_collector_msg_literal( ctx, "Unable to deserialize config account" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/config/src/config_processor.rs#L43 */

  fd_borrowed_account_drop( &config_acc_rec );

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L44-L49 */

  fd_pubkey_t current_signer_keys[ 37UL ];
  ulong       current_signer_key_cnt = 0UL;

  for( ulong i=0UL; i < current_data->keys_len; i++ ) {
    if( current_data->keys[i].signer ) {
      current_signer_keys[ current_signer_key_cnt++ ] = current_data->keys[i].key;
    }
  }

  /* If we have no keys in the account, require the config account to have signed the transaction
     https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L50-L56 */

  if( FD_UNLIKELY( current_signer_key_cnt==0UL && !is_config_account_signer ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L58 */

  ulong counter = 0UL;
  /* Invariant: counter <= key_list.keys_len */

  for( ulong i=0UL; i<key_list->keys_len; i++ ) {
    if( !key_list->keys[i].signer ) continue;
    fd_pubkey_t const * signer = &key_list->keys[i].key;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L60 */

    counter++;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L61 */

    if( 0!=memcmp( signer, config_account_key, sizeof(fd_pubkey_t) ) ) {

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L62-L71 */

      /* Intentionally don't use the scoping macro here because Anza maps the
         error to missing required signature if the try borrow fails */
      fd_borrowed_account_t signer_account;
      int borrow_err = fd_exec_instr_ctx_try_borrow_instr_account( ctx, (uchar)counter, &signer_account );
      if( FD_UNLIKELY( borrow_err ) ) {
        /* Max msg_sz: 33 - 2 + 45 = 76 < 127 => we can use printf */
        FD_BASE58_ENCODE_32_BYTES( signer->uc, signer_b58 );
        fd_log_collector_printf_dangerous_max_127( ctx,
          "account %s is not in account list", signer_b58 );
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L72-L79 */

      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, (uchar)counter, NULL ) ) ) {
        /* Max msg_sz: 33 - 2 + 45 = 76 < 127 => we can use printf */
        FD_BASE58_ENCODE_32_BYTES( signer->uc, signer_b58 );
        fd_log_collector_printf_dangerous_max_127( ctx,
          "account %s signer_key().is_none()", signer_b58 );
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L80-L87 */

      if( FD_UNLIKELY( 0!=memcmp( signer_account.pubkey, signer, sizeof(fd_pubkey_t) ) ) ) {
        /* Max msg_sz: 53 - 3 + 20 = 70 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( ctx,
          "account[%lu].signer_key() does not match Config data)", counter+1 );
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L89-L98 */

      if( current_data->keys_len>0UL ) {
        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L90 */
        int is_signer = 0;
        for( ulong j=0UL; j<current_signer_key_cnt; j++ ) {
          if( 0==memcmp( &current_signer_keys[j], signer, sizeof(fd_pubkey_t) ) ) {
            is_signer = 1;
            break;
          }
        }
        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L97 */
        if( FD_UNLIKELY( !is_signer ) ) {
          /* Max msg_sz: 39 - 2 + 45 = 82 < 127 => we can use printf */
          FD_BASE58_ENCODE_32_BYTES( signer->uc, signer_b58 );
          fd_log_collector_printf_dangerous_max_127( ctx,
            "account %s is not in stored signer list", signer_b58 );
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
      }

      /* implicit drop of signer account */

    } else if( !is_config_account_signer ) {

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L101 */
      fd_log_collector_msg_literal( ctx, "account[0].signer_key().is_none()" );
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    }
  }

  /* Disallow duplicate keys
     https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L105-L115

  TODO: Agave uses a O(n log n) algorithm here */
  for( ulong i = 0; i < key_list->keys_len; i++ ) {
    for( ulong j = 0; j < key_list->keys_len; j++ ) {
      if( i == j ) continue;

      if( FD_UNLIKELY( memcmp( &key_list->keys[i].key, &key_list->keys[j].key, sizeof(fd_pubkey_t) ) == 0 &&
                        key_list->keys[i].signer == key_list->keys[j].signer ) ) {
        fd_log_collector_msg_literal( ctx, "new config contains duplicate keys" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    }
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L118-L126 */

  if( FD_UNLIKELY( current_signer_key_cnt>counter ) ) {
    /* Max msg_sz: 35 - 6 + 2*20 = 69 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "too few signers: %lu; expected: %lu", counter, current_signer_key_cnt );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Upgrade to writable handle
     https://github.com/anza-xyz/agave/blob/v2.1.4/programs/config/src/config_processor.rs#L125-L126 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_CONFIG, &config_acc_rec );

  /* Upgrade to writable handle
    https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L130-L133 */

  if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &config_acc_rec )<ctx->instr->data_sz ) ) {
    fd_log_collector_msg_literal( ctx, "instruction data too large" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/config/src/config_processor.rs#L131 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &config_acc_rec, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* copy_from_slice */
  fd_memcpy( data, ctx->instr->data, ctx->instr->data_sz );

  /* Implicitly dropped */

  return FD_EXECUTOR_INSTR_SUCCESS;
# undef ACC_IDX_CONFIG

}

int
fd_config_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* Prevent execution of migrated native programs */
  if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( ctx->bank, migrate_config_program_to_core_bpf ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.27/programs/config/src/config_processor.rs#L14
     See DEFAULT_COMPUTE_UNITS */
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  int ret = _process_config_instr( ctx );
  return ret;
}
