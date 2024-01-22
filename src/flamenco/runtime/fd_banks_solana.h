#ifndef HEADER_fd_src_flamenco_runtime_fd_banks_solana_h
#define HEADER_fd_src_flamenco_runtime_fd_banks_solana_h

#include "../../flamenco/types/fd_types.h"

FD_PROTOTYPES_BEGIN

static inline void
fd_account_meta_init( fd_account_meta_t * m ) {
  fd_memset(m, 0, sizeof(*m));
  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen = sizeof(fd_account_meta_t);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_banks_solana_h */
