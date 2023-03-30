#include "../fd_types.h"
#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "fd_sysvar.h"

#include "../../base58/fd_base58.h"

void fd_sysvar_recent_hashes_init( global_ctx_t* global, ulong slot ) {
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

  // todo: store these some place... so that we are not decoding over and over
  unsigned char pubkey[32];
  unsigned char owner[32];
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (unsigned char *) owner);
  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (unsigned char *) pubkey);

  fd_sysvar_set(global, owner, pubkey, enc, sz, slot);
}

void fd_sysvar_recent_hashes_update(FD_FN_UNUSED global_ctx_t* global) {
}
