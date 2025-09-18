#ifndef HEADER_fd_src_discof_rpcserver_fd_block_to_json_h
#define HEADER_fd_src_discof_rpcserver_fd_block_to_json_h

#include "../replay/fd_replay_tile.h"
#include "../../ballet/txn/fd_txn.h"

typedef struct fd_webserver fd_webserver_t;

/* Rewards assigned after block is executed */

struct fd_block_rewards {
  ulong collected_fees;
  fd_hash_t leader;
  ulong post_balance;
};
typedef struct fd_block_rewards fd_block_rewards_t;

typedef enum {
  FD_ENC_BASE58, FD_ENC_BASE64, FD_ENC_BASE64_ZSTD, FD_ENC_JSON, FD_ENC_JSON_PARSED
} fd_rpc_encoding_t;

enum fd_block_detail { FD_BLOCK_DETAIL_FULL, FD_BLOCK_DETAIL_ACCTS, FD_BLOCK_DETAIL_SIGS, FD_BLOCK_DETAIL_NONE };

const char* fd_txn_meta_to_json( fd_webserver_t * ws,
                                 const void * meta_raw,
                                 ulong meta_raw_sz );

const char* fd_txn_to_json( fd_webserver_t * ws,
                            fd_txn_t* txn,
                            const uchar* raw,
                            ulong raw_sz,
                            fd_rpc_encoding_t encoding,
                            long maxvers,
                            enum fd_block_detail detail,
                            fd_spad_t * spad );

const char* fd_block_to_json( fd_webserver_t * ws,
                              const char * call_id,
                              const uchar * blk_data,
                              ulong blk_sz,
                              fd_replay_slot_completed_t * info,
                              fd_replay_slot_completed_t * parent_info,
                              fd_rpc_encoding_t encoding,
                              long maxvers,
                              enum fd_block_detail detail,
                              fd_block_rewards_t * rewards,
                              fd_spad_t * spad );

#define FD_LONG_UNSET (1L << 63L)

const char* fd_account_to_json( fd_webserver_t * ws,
                                fd_pubkey_t acct,
                                fd_rpc_encoding_t enc,
                                uchar const * val,
                                ulong val_sz,
                                long off,
                                long len,
                                fd_spad_t * spad );

#endif /* HEADER_fd_src_discof_rpcserver_fd_block_to_json_h */
