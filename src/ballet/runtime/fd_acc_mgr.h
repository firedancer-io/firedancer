#ifndef HEADER_fd_src_ballet_runtime_fd_acc_mgr_h
#define HEADER_fd_src_ballet_runtime_fd_acc_mgr_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "fd_banks_solana.h"

FD_PROTOTYPES_BEGIN

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)
#define FD_ACC_MGR_ERR_WRITE_FAILED    (-2)
#define FD_ACC_MGR_ERR_READ_FAILED     (-3)

struct fd_acc_mgr {
    fd_funk_t* funk;
    const struct fd_funk_xactionid* funk_xroot;
};
typedef struct fd_acc_mgr fd_acc_mgr_t;

#define FD_ACC_MGR_FOOTPRINT (sizeof(fd_acc_mgr_t))

void* fd_acc_mgr_new(void* mem,
                     fd_funk_t* funk,
                     const fd_funk_xactionid_t* funk_xroot,
                     ulong footprint);

fd_acc_mgr_t* fd_acc_mgr_join(void* mem);

void* fd_acc_mgr_leave(fd_acc_mgr_t* acc_mgr);

void* fd_acc_mgr_delete(void* mem);

typedef ulong fd_acc_lamports_t;

int fd_acc_mgr_write_account(fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, uchar* data, ulong data_len);

int fd_acc_mgr_get_lamports(fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_acc_lamports_t* result);

int fd_acc_mgr_set_lamports(fd_acc_mgr_t* acc_mgr, fd_pubkey_t* pubkey, fd_acc_lamports_t lamports);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_acc_mgr_h */
