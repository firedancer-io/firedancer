#ifndef HEADER_fd_src_flamenco_runtime_fd_hashes_h
#define HEADER_fd_src_flamenco_runtime_fd_hashes_h

#include "fd_banks_solana.h"

struct fd_pubkey_hash_pair {
  fd_pubkey_t pubkey;
  fd_hash_t   hash;
};
typedef struct fd_pubkey_hash_pair fd_pubkey_hash_pair_t;

typedef struct fd_global_ctx fd_global_ctx_t;

#define VECT_NAME fd_pubkey_hash_vector
#define VECT_ELEMENT fd_pubkey_hash_pair_t
#include "fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

FD_PROTOTYPES_BEGIN

void fd_hash_account_deltas(fd_global_ctx_t *global, fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash );

int fd_update_hash_bank( fd_global_ctx_t * global, fd_hash_t * hash, ulong signature_cnt );

void fd_hash_meta( fd_account_meta_t const * account, ulong slot, fd_pubkey_t const * pubkey, uchar const * data, fd_hash_t * hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_hashes_h */
