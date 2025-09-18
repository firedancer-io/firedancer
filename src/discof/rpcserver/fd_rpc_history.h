#ifndef HEADER_fd_src_discof_rpcserver_fd_rpc_history_h
#define HEADER_fd_src_discof_rpcserver_fd_rpc_history_h

#include "fd_rpc_service.h"
#include "../replay/fd_replay_tile.h"
#include "../reasm/fd_reasm.h"

struct fd_rpc_history;
typedef struct fd_rpc_history fd_rpc_history_t;

struct fd_rpc_txn_key {
  ulong v[FD_ED25519_SIG_SZ / sizeof( ulong )];
};
typedef struct fd_rpc_txn_key fd_rpc_txn_key_t;

fd_rpc_history_t * fd_rpc_history_create(fd_rpcserver_args_t * args);

void fd_rpc_history_save_info(fd_rpc_history_t * hist, fd_replay_slot_completed_t * msg);

void fd_rpc_history_save_fec(fd_rpc_history_t * hist, fd_store_t * store, fd_reasm_fec_t * fec);

ulong fd_rpc_history_first_slot(fd_rpc_history_t * hist);

ulong fd_rpc_history_latest_slot(fd_rpc_history_t * hist);

fd_replay_slot_completed_t * fd_rpc_history_get_block_info(fd_rpc_history_t * hist, ulong slot);

fd_replay_slot_completed_t * fd_rpc_history_get_block_info_by_hash(fd_rpc_history_t * hist, fd_hash_t * h);

uchar * fd_rpc_history_get_block(fd_rpc_history_t * hist, ulong slot, ulong * blk_sz);

uchar * fd_rpc_history_get_txn(fd_rpc_history_t * hist, fd_rpc_txn_key_t * sig, ulong * txn_sz, ulong * slot);

const void * fd_rpc_history_first_txn_for_acct(fd_rpc_history_t * hist, fd_pubkey_t * acct, fd_rpc_txn_key_t * sig, ulong * slot);

const void * fd_rpc_history_next_txn_for_acct(fd_rpc_history_t * hist, fd_rpc_txn_key_t * sig, ulong * slot, const void * iter);

#endif /* HEADER_fd_src_discof_rpcserver_fd_rpc_history_h */
