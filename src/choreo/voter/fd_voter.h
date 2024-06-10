#ifndef HEADER_fd_src_choreo_vote_fd_voter_h
#define HEADER_fd_src_choreo_vote_fd_voter_h

#include "../fd_choreo_base.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define FD_VOTE_TXN_PARSE_OK              0
#define FD_VOTE_TXN_PARSE_ERR_BAD_INST   -1
#define FD_VOTE_TXN_PARSE_ERR_WRONG_PROG -2

struct fd_voter {
  fd_pubkey_t * vote_acct_addr;
  const uchar * node_keypair;
  const uchar * authorized_voter_keypair;
};
typedef struct fd_voter fd_voter_t;

ulong
fd_vote_txn_generate( fd_voter_t *                     voter,
                      fd_compact_vote_state_update_t * vote_update,
                      uchar *                          recent_blockhash,
                      uchar                            out_txn_meta_buf [static FD_TXN_MAX_SZ],
                      uchar                            out_txn_buf [static FD_TXN_MTU] );

int
fd_vote_txn_parse( uchar                            txn_buf [static FD_TXN_MTU],
                   ulong                            txn_size,
                   fd_valloc_t                      valloc,
                   fd_compact_vote_state_update_t * out_vote_update );

#endif
