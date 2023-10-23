#ifndef HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h
#define HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h

#include "../../ballet/txn/fd_txn.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk_rec.h"

struct __attribute__((aligned(8UL))) fd_borrowed_account {
  ulong                       magic;

  fd_pubkey_t                 pubkey[1];

  fd_account_meta_t const   * const_meta;
  uchar             const   * const_data;
  fd_funk_rec_t     const   * const_rec;

  fd_account_meta_t         * meta;
  uchar                     * data;
  fd_funk_rec_t             * rec;

  ulong                       starting_dlen;
  ulong                       starting_lamports;
};
typedef struct fd_borrowed_account fd_borrowed_account_t;
#define FD_BORROWED_ACCOUNT_FOOTPRINT (sizeof(fd_borrowed_account_t))
#define FD_BORROWED_ACCOUNT_ALIGN     (8UL)
#define FD_BORROWED_ACCOUNT_MAGIC     (0xF15EDF1C51F51AA1UL)

#define FD_BORROWED_ACCOUNT_DECL(_x)  fd_borrowed_account_t _x[1]; fd_borrowed_account_init(_x);

FD_PROTOTYPES_BEGIN

fd_borrowed_account_t * fd_borrowed_account_init( void * ptr );

FD_PROTOTYPES_END

#endif
