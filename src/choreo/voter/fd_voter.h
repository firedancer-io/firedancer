#ifndef HEADER_fd_src_choreo_vote_fd_voter_h
#define HEADER_fd_src_choreo_vote_fd_voter_h

#include "../fd_choreo_base.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define FD_VOTE_TXN_PARSE_OK              0
#define FD_VOTE_TXN_PARSE_ERR_BAD_INST   -1
#define FD_VOTE_TXN_PARSE_ERR_WRONG_PROG -2

typedef void (*fd_voter_txn_sign_fun)( void * ctx, uchar * sig, uchar const * buffer, ulong len );

struct fd_voter {
  fd_pubkey_t const * vote_acct_addr;
  fd_pubkey_t const * vote_authority_pubkey;
  fd_pubkey_t const * validator_identity_pubkey;
  void * voter_sign_arg;
  fd_voter_txn_sign_fun vote_authority_sign_fun;
  fd_voter_txn_sign_fun validator_identity_sign_fun;
};
typedef struct fd_voter fd_voter_t;

ulong
fd_vote_txn_generate( fd_voter_t *                     voter,
                      fd_compact_vote_state_update_t * vote_update,
                      uchar *                          recent_blockhash,
                      uchar                            out_txn_meta_buf [static FD_TXN_MAX_SZ],
                      uchar                            out_txn_buf [static FD_TXN_MTU] );

void
fd_voter_txn_sign( fd_voter_t *                     voter,
                   ulong                            txn_size,
                   uchar                            txn_meta_out[static FD_TXN_MAX_SZ],
                   uchar                            txn_out[static FD_TXN_MTU] );

int
fd_vote_txn_parse( uchar                            txn_buf [static FD_TXN_MTU],
                   ulong                            txn_size,
                   fd_valloc_t                      valloc,
                   ushort *                         out_recent_blockhash_off,
                   fd_compact_vote_state_update_t * out_vote_update );

#endif
