#include "fd_stake_program.h"

void write_stake_config( fd_global_ctx_t* global, fd_stake_config_t* stake_config) {
  ulong          sz = fd_stake_config_size( stake_config );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_stake_config_encode( stake_config, &ptr );

  fd_solana_account_t account = {
    .lamports = 960480,
    .rent_epoch = 0,
    .data_len = sz,
    .data = enc,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, global->solana_config_program, 32 );
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->current_slot, (fd_pubkey_t *) global->solana_stake_program_config, &account );
}

void fd_stake_program_config_init( fd_global_ctx_t* global ) {

  /* this is supposed to be 0.25? */

  /* Defaults taken from
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs#L8-L11 */
  fd_stake_config_t stake_config = {
    .warmup_cooldown_rate = 0.25,
    .slash_penalty = 12,
  };
  write_stake_config( global, &stake_config );
}
