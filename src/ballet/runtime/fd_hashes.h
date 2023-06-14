#ifndef HEADER_fd_src_ballet_runtime_fd_hashes_h
#define HEADER_fd_src_ballet_runtime_fd_hashes_h

#include "fd_banks_solana.h"

struct fd_pubkey_hash_pair {
  fd_pubkey_t pubkey;
  fd_hash_t hash;
};
typedef struct fd_pubkey_hash_pair fd_pubkey_hash_pair_t;

FD_PROTOTYPES_BEGIN


void fd_hash_bank( fd_deserializable_versioned_bank_t const * bank, fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash );
void fd_hash_account( fd_solana_account_t const * account, ulong slot, fd_pubkey_t const * pubkey, fd_hash_t * hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_hashes_h */
