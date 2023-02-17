#ifndef HEADER_fd_src_ballet_runtime_fd_account_mgr_h
#define HEADER_fd_src_ballet_runtime_fd_account_mgr_h

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"

FD_PROTOTYPES_BEGIN

typedef ulong fd_acc_lamports_t;

fd_acc_lamports_t get_lamports( fd_txn_acct_addr_t * acc ) ;

void set_lamports( fd_txn_acct_addr_t * acc, fd_acc_lamports_t lamports ) ;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_account_mgr_h */
