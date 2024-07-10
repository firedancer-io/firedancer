#ifndef HEADER_fd_src_choreo_vote_fd_voter_h
#define HEADER_fd_src_choreo_vote_fd_voter_h

#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../fd_choreo_base.h"
#include "../tower/fd_tower.h"

#define FD_VOTER_OK                      0
#define FD_VOTER_ERR                     -1
#define FD_VOTE_TXN_PARSE_ERR_WRONG_PROG -2

typedef void ( *fd_voter_txn_sign_fun )( void * ctx, uchar * sig, uchar const * buffer, ulong len );

struct fd_voter {
  fd_pubkey_t const *   vote_acc_addr;
  fd_pubkey_t const *   validator_identity;
  fd_pubkey_t const *   vote_authority;
  void *                voter_sign_arg;
  fd_voter_txn_sign_fun vote_authority_sign_fun;
  fd_voter_txn_sign_fun validator_identity_sign_fun;
};
typedef struct fd_voter fd_voter_t;

/* fd_voter_txn_generate generates an  */

ulong
fd_voter_txn_generate( fd_voter_t *                     voter,
                       fd_compact_vote_state_update_t * vote_update,
                       uchar const *                          recent_blockhash,
                       uchar                            txn_meta_out[static FD_TXN_MAX_SZ],
                       uchar                            txn_out[static FD_TXN_MTU] );

void
fd_voter_txn_sign( fd_voter_t * voter,
                   ulong        txn_size,
                   uchar        txn_meta_out[static FD_TXN_MAX_SZ],
                   uchar        txn_out[static FD_TXN_MTU] );

/* fd_voter_txn_parse parses a txn and returns a pointer to an
   fd_vote_instruction_t.  Assumes caller is currently in a scratch
   scope and allocates memory using fd_scratch_virtual().  Lifetime of
   the returned pointer is lifetime of the caller's scratch scope when
   calling this function. */

fd_vote_instruction_t *
fd_voter_txn_parse( uchar txn[static FD_TXN_MTU], ulong txn_sz, fd_ );

#endif
