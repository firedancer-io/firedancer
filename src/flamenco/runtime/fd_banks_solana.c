#include "fd_banks_solana.h"

void fd_account_meta_init(fd_account_meta_t *m) {
  fd_memset(m, 0, sizeof(*m));
  m->magic = FD_ACCOUNT_META_MAGIC;
  m->hlen = sizeof(fd_account_meta_t);
}
