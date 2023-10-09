#include "fd_config_program.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/* https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L18 */
int fd_executor_config_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  int ret = FD_EXECUTOR_INSTR_SUCCESS;
  uchar cleanup_config_account_state = 0;
  uchar cleanup_instruction = 0;
  fd_bincode_destroy_ctx_t destroy_ctx;

  /* Deserialize the Config Program instruction data, which consists only of the ConfigKeys
     https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L25 */
  uchar *data = ctx.instr->data;
  fd_bincode_decode_ctx_t instruction_decode_context = {
    .valloc  = ctx.valloc,
    .data    = data,
    .dataend = &data[ctx.instr->data_sz],
  };

  fd_config_keys_t instruction;
  int decode_result = fd_config_keys_decode( &instruction, &instruction_decode_context );
   if ( decode_result != FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(("fd_config_keys_decode failed: %d", decode_result));
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      goto config_program_execute_instruction_cleanup;
   }

   cleanup_instruction = 1;

   /* The config account is instruction account 0
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L26-L27 */
   if ( ctx.instr->acct_cnt == 0 ) {
     ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
     goto config_program_execute_instruction_cleanup;
   }

   uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
   fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;
   fd_pubkey_t const * config_acc = &txn_accs[instr_acc_idxs[0]];

   /* Deserialize the config account data, which must already be a valid ConfigKeys map (zeroed accounts pass this check)
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L28-L42 */
   /* Read the data from the config account */
   fd_borrowed_account_t * config_acc_rec = NULL;
   int err = fd_instr_borrowed_account_view(&ctx,  (fd_pubkey_t *) config_acc, & config_acc_rec);
   if (FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS)) {
      ret = err;
      goto config_program_execute_instruction_cleanup;
   }

   /* Check that the account owner is correct */
   if ( memcmp( &config_acc_rec->const_meta->info.owner, fd_solana_config_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      goto config_program_execute_instruction_cleanup;
   }

   /* Decode the config state into the ConfigKeys struct */
   fd_bincode_decode_ctx_t config_acc_state_decode_context = {
      .valloc  = ctx.valloc,
      .data    = config_acc_rec->const_data,
      .dataend = config_acc_rec->const_data + config_acc_rec->const_meta->dlen,
   };
   fd_config_keys_t config_account_state;
   decode_result = fd_config_keys_decode( &config_account_state, &config_acc_state_decode_context );
   if ( decode_result != FD_BINCODE_SUCCESS ) {
      FD_LOG_DEBUG(("fd_config_keys_decode failed: %d", decode_result));
      ret =  FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      goto config_program_execute_instruction_cleanup;
   }

   cleanup_config_account_state = 1;

   /* If we have no keys in the account, require the config account to have signed the transaction
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L50-L56 */
   uint config_acc_signed = fd_instr_acc_is_signer(ctx.instr, config_acc);
   if ( config_account_state.keys_len == 0 ) {
      if ( !config_acc_signed ) {
         ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
         goto config_program_execute_instruction_cleanup;
      }
   }

   /* Check that all accounts in the instruction ConfigKeys map have signed
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L58-L103 */
   ulong new_signer_count = 0;
   for ( ulong i = 0; i < instruction.keys_len; i++ ) {
      fd_config_keys_pair_t* elem = &instruction.keys[i];
      /* Skip account if it is not a signer */
      if ( elem->signer == 0 ) {
         continue;
      }

      new_signer_count += 1;

      /* If the account is the config account, we just need to check that the config account has signed */
      if ( memcmp( &elem->key, config_acc, sizeof(fd_pubkey_t) ) == 0 ) {
         if ( !config_acc_signed ) {
            ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
            goto config_program_execute_instruction_cleanup;
         }
         continue;
      }

      /* Check that we have been given enough accounts */
      if ( ctx.instr->acct_cnt < new_signer_count ) {
         ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
         goto config_program_execute_instruction_cleanup;
      }

      /* Check that the account has signed */
      uchar acc_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t const * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, &elem->key, sizeof(fd_pubkey_t) ) ) {
            acc_signed = 1;
            break;
          }
        }
      }
      if ( !acc_signed ) {
        ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        goto config_program_execute_instruction_cleanup;
      }

      /* Check that the order of the signer keys are preserved */
      if ( memcmp( &txn_accs[instr_acc_idxs[new_signer_count]], &elem->key, sizeof(fd_pubkey_t) ) != 0 ) {
        ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        goto config_program_execute_instruction_cleanup;
      }

      /* Check that the new signer key list is a superset of the current one */
      if ( config_account_state.keys_len > 0 ) {
         uchar key_present_in_stored_signers = 0;
         for ( ulong i = 0; i < config_account_state.keys_len; i++ ) {
            /* Skip the account if it is not a signer */
            if ( config_account_state.keys[i].signer == 0 ) {
               continue;
            }

            if ( memcmp( &config_account_state.keys[i].key, &elem->key, sizeof(fd_pubkey_t) ) == 0 ) {
               key_present_in_stored_signers = 1;
               break;
            }
         }

         if ( !key_present_in_stored_signers) {
           ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
           goto config_program_execute_instruction_cleanup;
         }
      }

   }

   /* Disallow duplicate keys
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L105-L115 */
   if( FD_FEATURE_ACTIVE( ctx.slot_ctx, dedupe_config_program_signers ) ) {
      for ( ulong i = 0; i < instruction.keys_len; i++ ) {
         for ( ulong j = 0; j < instruction.keys_len; j++ ) {
            if ( i == j ) {
               continue;
            }

            if ( memcmp( &instruction.keys[i].key, &instruction.keys[j].key, sizeof(fd_pubkey_t) ) == 0 ) {
              ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
              goto config_program_execute_instruction_cleanup;
            }
         }
      }
   }

   /* Check that all the new signer accounts, as well as all of the existing signer accounts, have signed
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L117-L126 */
   ulong current_signer_count = 0;
   for ( ulong i = 0; i < config_account_state.keys_len; i++ ) {
     if ( config_account_state.keys[i].signer == 1 ) {
       current_signer_count += 1;
     }
   }
   if ( current_signer_count > new_signer_count ) {
     ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
     goto config_program_execute_instruction_cleanup;
   }

   /* Check that the config account can fit the new ConfigKeys map
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L128-L131 */
   if ( ctx.instr->data_sz > config_acc_rec->const_meta->dlen ) {
     ret = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
     goto config_program_execute_instruction_cleanup;
   }

   /* Write the ConfigKeys map in the instruction into the config account.

      If the new config account state is smaller than the existing one, then we overwrite the new data
      https://github.com/solana-labs/solana/blob/252438e28fbfb2c695fe1215171b83456e4b761c/programs/config/src/config_processor.rs#L135

      Encode and write the new account data
      - create a new allocated area for the data, with a size that is max(old, new)
      - memcpy the old data in
      - memcpy the new data in
      This mimics the semantics of Solana's config_account.get_data_mut()?[..data.len()].copy_from_slice(data)
      (although this can obviously be optimised)
   */

   ulong new_data_size = fd_ulong_max( ctx.instr->data_sz, config_acc_rec->const_meta->dlen );

   err = fd_instr_borrowed_account_modify(&ctx,  config_acc,  1,  new_data_size, & config_acc_rec);
   if ( err != FD_ACC_MGR_SUCCESS) {
      FD_LOG_WARNING(( "failed to write account data" ));
      ret = err;
      goto config_program_execute_instruction_cleanup;
   }

   fd_memcpy( config_acc_rec->data, data, ctx.instr->data_sz);
   config_acc_rec->meta->info.rent_epoch = 0;
   config_acc_rec->meta->info.executable = 0;
   config_acc_rec->meta->dlen = new_data_size;
   err = fd_acc_mgr_commit(ctx.acc_mgr, config_acc_rec, ctx.slot_ctx );
   if ( err != FD_ACC_MGR_SUCCESS) {
      FD_LOG_WARNING(( "failed to write account data" ));
      ret = err;
   }

config_program_execute_instruction_cleanup:
   destroy_ctx.valloc = ctx.valloc;

   if (cleanup_config_account_state)
     fd_config_keys_destroy( &config_account_state, &destroy_ctx );
   if (cleanup_instruction)
     fd_config_keys_destroy( &instruction, &destroy_ctx );
   return ret;
}
