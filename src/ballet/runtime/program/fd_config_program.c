#include "fd_config_program.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/* https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L18 */
int fd_executor_config_program_execute_instruction( instruction_ctx_t ctx ) {

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

   /* The config account is instruction account 0
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L26-L27 */
   if ( ctx.instr->acct_cnt == 0 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
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
      return read_result;
   }
   uchar *config_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, metadata.dlen);
   read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, config_acc, (uchar*)config_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
   if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
   }

   /* Check that the account owner is correct */
   if ( memcmp( &metadata.info.owner, &ctx.global->solana_config_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
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
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
   }

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
   if ( deq_fd_config_keys_pair_t_cnt( config_account_state.keys ) == 0 ) {
      if ( !config_acc_signed ) {
         return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
   }

   /* Check that all accounts in the instruction ConfigKeys map have signed
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L58-L103 */
   ulong new_signer_count = 0;
   fd_config_keys_pair_t * keys = instruction.keys;
   for ( deq_fd_config_keys_pair_t_iter_t iter = deq_fd_config_keys_pair_t_iter_init( keys );
         !deq_fd_config_keys_pair_t_iter_done( keys, iter );
         iter = deq_fd_config_keys_pair_t_iter_next( keys, iter ) ) {
      fd_config_keys_pair_t * elem = deq_fd_config_keys_pair_t_iter_ele( keys, iter );
      /* Skip account if it is not a signer */
      if ( elem->value == 0 ) {
         continue;
      }

      new_signer_count += 1;

      /* If the account is the config account, we just need to check that the config account has signed */
      if ( memcmp( &elem->key, config_acc, sizeof(fd_pubkey_t) ) == 0 ) {
         if ( !config_acc_signed ) {
            return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
         }
         continue;
      }

      /* Check that we have been given enough accounts */
      if ( ctx.instr->acct_cnt < new_signer_count ) {
         return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
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
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* Check that the order of the signer keys are preserved */
      if ( memcmp( &txn_accs[instr_acc_idxs[new_signer_count]], &elem->key, sizeof(fd_pubkey_t) ) != 0 ) {
         return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* Check that the new signer key list is a superset of the current one */
      if ( deq_fd_config_keys_pair_t_cnt( config_account_state.keys ) > 0 ) {

         uchar key_present_in_stored_signers = 0;
         fd_config_keys_pair_t * keys2 = config_account_state.keys;
         for ( deq_fd_config_keys_pair_t_iter_t iter2 = deq_fd_config_keys_pair_t_iter_init( keys2 );
               !deq_fd_config_keys_pair_t_iter_done( keys2, iter2 );
               iter2 = deq_fd_config_keys_pair_t_iter_next( keys2, iter2 ) ) {
           fd_config_keys_pair_t * elem2 = deq_fd_config_keys_pair_t_iter_ele( keys2, iter2 );
            /* Skip the account if it is not a signer */
            if ( elem2->value == 0 ) {
               continue;
            }

            if ( memcmp( &elem2->key, &elem->key, sizeof(fd_pubkey_t) ) == 0 ) {
               key_present_in_stored_signers = 1;
               break;
            }
         }

         if ( !key_present_in_stored_signers) {
            return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
         }
      }

   }

   /* Disallow duplicate keys
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L105-L115 */
   if ( ctx.global->features.dedupe_config_program_signers == 1 ) {
      for ( deq_fd_config_keys_pair_t_iter_t iter = deq_fd_config_keys_pair_t_iter_init( keys );
            !deq_fd_config_keys_pair_t_iter_done( keys, iter );
            iter = deq_fd_config_keys_pair_t_iter_next( keys, iter ) ) {
      fd_config_keys_pair_t * elem = deq_fd_config_keys_pair_t_iter_ele( keys, iter );
      for ( deq_fd_config_keys_pair_t_iter_t iter2 = deq_fd_config_keys_pair_t_iter_next( keys, iter );
            !deq_fd_config_keys_pair_t_iter_done( keys, iter2 );
            iter2 = deq_fd_config_keys_pair_t_iter_next( keys, iter2 ) ) {
         fd_config_keys_pair_t * elem2 = deq_fd_config_keys_pair_t_iter_ele( keys, iter2 );
         if ( memcmp( &elem->key, &elem2->key, sizeof(fd_pubkey_t) ) == 0 ) {
            return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
         }
         }
      }
   }

   /* Check that all the new signer accounts, as well as all of the existing signer accounts, have signed
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L117-L126 */
   ulong current_signer_count = 0;
   fd_config_keys_pair_t * keys2 = config_account_state.keys;
   for ( deq_fd_config_keys_pair_t_iter_t iter2 = deq_fd_config_keys_pair_t_iter_init( keys2 );
         !deq_fd_config_keys_pair_t_iter_done( keys2, iter2 );
         iter2 = deq_fd_config_keys_pair_t_iter_next( keys2, iter2 ) ) {
     fd_config_keys_pair_t * elem2 = deq_fd_config_keys_pair_t_iter_ele( keys2, iter2 );
     if ( elem2->value == 1 ) {
       current_signer_count += 1;
     }
   }
   if ( current_signer_count > new_signer_count ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
   }

   /* Check that the config account can fit the new ConfigKeys map
      https://github.com/solana-labs/solana/blob/a03ae63daff987912c48ee286eb8ee7e8a84bf01/programs/config/src/config_processor.rs#L128-L131 */
   if ( ctx.instr->data_sz > metadata.dlen ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
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
   uchar *new_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, new_data_size);
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
      return write_result;
   }
   fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, config_acc, new_data, new_data_size);

   return FD_EXECUTOR_INSTR_SUCCESS;
}
