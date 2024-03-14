#include "fd_config_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"

#define DEFAULT_COMPUTE_UNITS 450UL
/* Useful links:

   https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs */

/* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L16 */

static int
_process_config_instr( fd_exec_instr_ctx_t ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    /* Deserialize the Config Program instruction data, which consists only of the ConfigKeys
      https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L21 */

    fd_bincode_decode_ctx_t decode =
      { .valloc  = fd_scratch_virtual(),
        .data    = ctx.instr->data,
        .dataend = ctx.instr->data + ctx.instr->data_sz };

    fd_config_keys_t key_list;
    int decode_result = fd_config_keys_decode( &key_list, &decode );
    if( decode_result != FD_BINCODE_SUCCESS )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L22-L26 */

    if( FD_UNLIKELY( ctx.instr->acct_cnt < 1UL ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  # define ACC_IDX_CONFIG (0UL)
    fd_borrowed_account_t * config_acc_rec = NULL;
    fd_instr_borrowed_account_view_idx( &ctx, ACC_IDX_CONFIG, &config_acc_rec );

    fd_pubkey_t const * config_account_key = config_acc_rec->pubkey;

    if( FD_UNLIKELY( !fd_borrowed_account_acquire_read( config_acc_rec ) ) )
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L27 */

    uint is_config_account_signer = fd_instr_acc_is_signer_idx( ctx.instr, ACC_IDX_CONFIG );

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L29-L31 */

    if( 0!=memcmp( &config_acc_rec->const_meta->info.owner, fd_solana_config_program_id.key, sizeof(fd_pubkey_t) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L33-L40 */

    fd_bincode_decode_ctx_t config_acc_state_decode_context = {
      .valloc  = ctx.valloc,
      .data    = config_acc_rec->const_data,
      .dataend = config_acc_rec->const_data + config_acc_rec->const_meta->dlen,
    };
    fd_config_keys_t current_data;
    decode_result = fd_config_keys_decode( &current_data, &config_acc_state_decode_context );
    if( decode_result != FD_BINCODE_SUCCESS )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L42 */

    fd_borrowed_account_release_read( config_acc_rec );

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L44-L49 */

    fd_pubkey_t * current_signer_keys = fd_scratch_alloc( alignof(fd_pubkey_t), sizeof(fd_pubkey_t) * current_data.keys_len );
    ulong         current_signer_key_cnt = 0UL;

    for( ulong i=0UL; i < current_data.keys_len; i++ )
      if( current_data.keys[i].signer )
        current_signer_keys[ current_signer_key_cnt++ ] = current_data.keys[i].key;

    /* If we have no keys in the account, require the config account to have signed the transaction
      https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L50-L56 */

    if( ( current_signer_key_cnt==0 ) &
        ( !is_config_account_signer ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L58 */

    ulong counter = 0UL;
    /* Invariant: counter <= key_list.keys_len */

    for( ulong i=0UL; i < key_list.keys_len; i++ ) {
      if( !key_list.keys[i].signer ) continue;
      fd_pubkey_t const * signer = &key_list.keys[i].key;

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L60 */

      counter++;

      /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L61 */

      if( 0!=memcmp( signer, config_account_key, sizeof(fd_pubkey_t) ) ) {

        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L62-L71 */

        fd_borrowed_account_t * signer_account = NULL;
        int borrow_err = fd_instr_borrowed_account_view_idx( &ctx, (uchar)counter, &signer_account );
        if( FD_UNLIKELY( borrow_err!=FD_ACC_MGR_SUCCESS ) )
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        if( FD_UNLIKELY( !fd_borrowed_account_acquire_read( signer_account ) ) )
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;  /* seems to be deliberately not ACC_BORROW_FAILED? */

        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L72-L79 */

        if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, (uchar)counter ) ) )
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L80-L87 */

        if( FD_UNLIKELY( 0!=memcmp( signer_account->pubkey, signer, sizeof(fd_pubkey_t) ) ) )
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L89-L98 */

        if( current_data.keys_len>0UL ) {
          /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L90 */
          int is_signer = 0;
          for( ulong j=0UL; j < current_signer_key_cnt; j++ ) {
            if( 0==memcmp( &current_signer_keys[j], signer, sizeof(fd_pubkey_t) ) ) {
              is_signer = 1;
              break;
            }
          }
          /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L97 */
          if( !is_signer )
            return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }

      } else if( !is_config_account_signer ) {

        /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L101 */
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

      }
    }

    /* Disallow duplicate keys
      https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L105-L115

      TODO: Solana Labs uses a O(n log n) algorithm here */
    if( FD_FEATURE_ACTIVE( ctx.slot_ctx, dedupe_config_program_signers ) ) {
      for( ulong i = 0; i < key_list.keys_len; i++ ) {
        for( ulong j = 0; j < key_list.keys_len; j++ ) {
          if( i == j ) continue;

          if( memcmp( &key_list.keys[i].key, &key_list.keys[j].key, sizeof(fd_pubkey_t) ) == 0 ) {
            return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
          }
        }
      }
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L118-L126 */

    if( FD_UNLIKELY( current_signer_key_cnt > counter ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    /* Upgrade to writable handle
      https://github.com/solana-labs/solana/blob/v1.17.17/programs/config/src/config_processor.rs#L128-L133 */

    if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( config_acc_rec ) ) )
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

    if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx.instr, 0 ) ) )
      return FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;

    if( FD_UNLIKELY( config_acc_rec->const_meta->dlen < ctx.instr->data_sz ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    int modify_err = fd_instr_borrowed_account_modify_idx( &ctx, 0, config_acc_rec->const_meta->dlen, &config_acc_rec );
    if( FD_UNLIKELY( modify_err!=FD_ACC_MGR_SUCCESS ) )
      return FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;

    fd_memcpy( config_acc_rec->data, ctx.instr->data, ctx.instr->data_sz );

    /* Implicitly dropped in Labs */

    fd_borrowed_account_release_write( config_acc_rec );

    return FD_EXECUTOR_INSTR_SUCCESS;
  # undef ACC_IDX_CONFIG
  } FD_SCRATCH_SCOPE_END;
}

int
fd_config_program_execute( fd_exec_instr_ctx_t ctx ) {
  ctx.txn_ctx->compute_meter = fd_ulong_sat_sub( ctx.txn_ctx->compute_meter, DEFAULT_COMPUTE_UNITS );
  fd_scratch_push();
  int ret = _process_config_instr( ctx );
  fd_scratch_pop();
  return ret;
}
