#include <stdio.h>
#include "../fd_types.h"
#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "fd_sysvar.h"
#include "../fd_runtime.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd accounts --accounts /home/jsiegel/test-ledger/accounts/ --pages 15 --index-max 120000000 --start-slot 2 --end-slot 2 --start-id 35 --end-id 37
// run --ledger /home/jsiegel/test-ledger --db /home/jsiegel/funk --cmd replay --pages 15 --index-max 120000000 --start-slot 0 --end-slot 3

// {meta = {write_version_obsolete = 137, 
// data_len = 6008, pubkey = "\006\247\325\027\031,V\216\340\212\204_sҗ\210\317\003\\1E\262\032\263D\330\006.\251@\000"}, info = {lamports = 42706560, rent_epoch = 0, owner = "\006\247\325\027\030u\367)\307=\223@\217!a \006~،v\340\214(\177\301\224`\000\000\000", executable = 0 '\000', padding = "K\000\f\376\177\000"}, hash = {value = "\302Q\316\035qTY\347\352]\260\335\213\224R\227ԯ\366R\273\063H\345֑c\377\207/k\275"}}

// owner:      Sysvar1111111111111111111111111111111111111 pubkey:      SysvarRecentB1ockHashes11111111111111111111 hash:     E5YSehyvJ7xXcNnQjWCH9UhMJ1dxDBJ1RuuPh1Y3RZgg file: /home/jsiegel/test-ledger/accounts//2.37
//   {blockhash = JCidNXtcMXMWQwMDM3ZQq5pxaw3hQpNbeHg1KcstjuF4,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = GQN3oV8G1Ra3GCX76dE1YYJ6UjMyDreNCEWM4tZ39zj1,  fee_calculator={lamports_per_signature = 5000}}
//   {blockhash = Ha5DVgnD1xSA8oQc337jtA3atEfQ4TFX1ajeZG1Y2tUx,  fee_calculator={lamports_per_signature = 0}}

void fd_sysvar_recent_hashes_init( fd_global_ctx_t* global ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  fd_recent_block_hashes_t a;
  memset(&a, 0, sizeof(a));

  fd_block_block_hash_entry_t s;
  memset(&s, 0, sizeof(s));

  fd_vec_fd_block_block_hash_entry_t_new(&a.hashes);

  fd_memcpy(s.blockhash.hash, global->genesis_hash, sizeof(global->genesis_hash));
  fd_vec_fd_block_block_hash_entry_t_push_front(&a.hashes, s);

  ulong sz = fd_recent_block_hashes_size(&a);
  if (sz < 6008)
    sz = 6008;
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  void const *ptr = (void const *) enc;
  fd_recent_block_hashes_encode(&a, &ptr);

  fd_recent_block_hashes_destroy(&a, global->freef, global->allocf_arg);

  fd_sysvar_set(global, global->sysvar_owner, global->sysvar_recent_block_hashes, enc, sz, global->current_slot );
}

void fd_sysvar_recent_hashes_update(fd_global_ctx_t* global, ulong slot) {
  if (slot == 0)  // we already set this... as part of boot
    return; 

  /* Read the recent hashes sysvar from the account */
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t*) global->sysvar_recent_block_hashes, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t*) global->sysvar_recent_block_hashes, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  fd_recent_block_hashes_t a;
  memset(&a, 0, sizeof(a));

  void* input = (void *)raw_acc_data;
  fd_recent_block_hashes_decode( &a, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );

  fd_block_block_hash_entry_t s;
  memset(&s, 0, sizeof(s));

  s.fee_calculator.lamports_per_signature = global->genesis_block.fee_rate_governor.target_lamports_per_signature / 2;
  fd_memcpy(s.blockhash.hash, global->block_hash, sizeof(global->block_hash));

  while (a.hashes.cnt >= 150)
    fd_vec_fd_block_block_hash_entry_t_pop_unsafe(&a.hashes);

  fd_vec_fd_block_block_hash_entry_t_push_front(&a.hashes, s);

  ulong sz = fd_recent_block_hashes_size(&a);
  if (sz < 6008)
    sz = 6008;
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  void const *ptr = (void const *) enc;
  fd_recent_block_hashes_encode(&a, &ptr);

  fd_recent_block_hashes_destroy(&a, global->freef, global->allocf_arg);

  fd_sysvar_set(global, global->sysvar_owner, global->sysvar_recent_block_hashes, enc, sz, slot);
}
