#include "fd_config_program.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/* https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L18 */
int fd_executor_config_program_execute_instruction( instruction_ctx_t ctx ) {
  int ret = FD_EXECUTOR_INSTR_SUCCESS;
  uchar cleanup_config_account_state = 0;
  uchar cleanup_instruction = 0;
  uchar *config_acc_data = NULL;
  uchar *new_data = NULL;

   /* Deserialize the Config Program instruction data, which consists only of the ConfigKeys
       https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L25 */
   uchar *data = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;
   fd_bincode_decode_ctx_t instruction_decode_context = {
      .allocf = ctx.global->allocf,
      .allocf_arg = ctx.global->allocf_arg,
      .data = data,
      .dataend = &data[ctx.instr->data_sz],
   };
   fd_config_keys_t instruction;
   int decode_result = fd_config_keys_decode( &instruction, &instruction_decode_context );
   if ( decode_result != FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(("fd_config_keys_decode failed: %d", decode_result));
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
   }

   cleanup_instruction = 1;

   /* The config account is instruction account 0
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L26-L27 */
   if ( ctx.instr->acct_cnt == 0 ) {
     ret = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
     goto config_program_execute_instruction_cleanup;
   }

   uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
   fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
   fd_pubkey_t * config_acc = &txn_accs[instr_acc_idxs[0]];

   /* Deserialize the config account data, which must already be a valid ConfigKeys map (zeroed accounts pass this check)
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L28-L42 */
   /* Read the data from the config account */
   fd_account_meta_t metadata;
   int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, config_acc, &metadata );
   if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      ret = read_result;
      goto config_program_execute_instruction_cleanup;
   }
   config_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
   read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, config_acc, (uchar*)config_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
   if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      ret = read_result;
      goto config_program_execute_instruction_cleanup;
   }

   /* Check that the account owner is correct */
   if ( memcmp( &metadata.info.owner, &ctx.global->solana_config_program, sizeof(fd_pubkey_t) ) != 0 ) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      goto config_program_execute_instruction_cleanup;
   }

   /* Decode the config state into the ConfigKeys struct */
   fd_bincode_decode_ctx_t config_acc_state_decode_context = {
      .allocf = ctx.global->allocf,
      .allocf_arg = ctx.global->allocf_arg,
      .data = config_acc_data,
      .dataend = &config_acc_data[metadata.dlen],
   };
   fd_config_keys_t config_account_state;
   decode_result = fd_config_keys_decode( &config_account_state, &config_acc_state_decode_context );
   if ( decode_result != FD_BINCODE_SUCCESS ) {
      FD_LOG_WARNING(("fd_config_keys_decode failed: %d", decode_result));
      ret =  FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      goto config_program_execute_instruction_cleanup;
   }

   cleanup_config_account_state = 1;

   /* If we have no keys in the account, require the config account to have signed the transaction
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L50-L56 */
   uchar config_acc_signed = 0;
   for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
      if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
         fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
         if ( !memcmp( signer, config_acc, sizeof(fd_pubkey_t) ) ) {
            config_acc_signed = 1;
            break;
         }
      }
   }
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
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
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
   if ( ctx.global->features.dedupe_config_program_signers == 1 ) {
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
   if ( ctx.instr->data_sz > metadata.dlen ) {
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
   ulong new_data_size = fd_ulong_max( ctx.instr->data_sz, metadata.dlen );
   new_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, new_data_size);
   fd_memcpy( new_data, config_acc_data, metadata.dlen );
   fd_memcpy( new_data, data, ctx.instr->data_sz );

   fd_solana_account_t structured_account;
   structured_account.lamports = metadata.info.lamports;
   structured_account.data = new_data;
   structured_account.data_len = new_data_size;
   structured_account.executable = 0;
   structured_account.rent_epoch = 0;
   memcpy( &structured_account.owner, ctx.global->solana_config_program, sizeof(fd_pubkey_t) );

   int write_result = fd_acc_mgr_write_structured_account( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, config_acc, &structured_account );
   if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      ret = write_result;
      goto config_program_execute_instruction_cleanup;
   }
   fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, config_acc, new_data, new_data_size);

   fd_bincode_destroy_ctx_t destroy_ctx;

config_program_execute_instruction_cleanup:
   destroy_ctx.freef = ctx.global->freef;
   destroy_ctx.freef_arg = ctx.global->allocf_arg;

   if (cleanup_config_account_state)
     fd_config_keys_destroy( &config_account_state, &destroy_ctx );
   if (cleanup_instruction)
     fd_config_keys_destroy( &instruction, &destroy_ctx );
   if (NULL != config_acc_data)
     ctx.global->freef(ctx.global->allocf_arg, config_acc_data);
   if (NULL != new_data)
     ctx.global->freef(ctx.global->allocf_arg, new_data);
   return ret;
}
