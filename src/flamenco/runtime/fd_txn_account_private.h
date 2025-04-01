#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_account_private_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_account_private_h

#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"

struct __attribute__((aligned(8UL))) fd_txn_account_private_state {
  fd_account_meta_t const * const_meta;
  uchar const *             const_data;
  fd_funk_rec_t const *     const_rec;

  fd_account_meta_t *       meta;
  uchar *                   data;
  fd_funk_rec_t *           rec;

  ulong                     meta_gaddr;
  ulong                     data_gaddr;

  /* Provide borrowing semantics.
     Used for single-threaded logic only, thus not comparable to a
     data synchronization lock. */
  ushort                    refcnt_excl;
};
typedef struct fd_txn_account_private_state fd_txn_account_private_state_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_account_private_h */
