#ifndef HEADER_fd_src_choreo_vote_fd_voter_h
#define HEADER_fd_src_choreo_vote_fd_voter_h

#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"

struct fd_voter {
  fd_pubkey_t vote_acc_addr;
  fd_pubkey_t validator_identity;
  fd_pubkey_t vote_authority;
};
typedef struct fd_voter fd_voter_t;

/* fd_voter_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as voter.  align is
   double cache line to mitigate false sharing. */

FD_FN_CONST static inline ulong
fd_voter_align( void ) {
  return alignof( fd_voter_t );
}

FD_FN_CONST static inline ulong
fd_voter_footprint( void ) {
  return sizeof( fd_voter_t );
}

/* fd_voter_new formats an unused memory region for use as a voter.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_voter_new( void * mem );

/* fd_voter_join joins the caller to the voter.  voter points to the
   first byte of the memory region backing the voter in the caller's
   address space.

   Returns a pointer in the local address space to voter on success. */

fd_voter_t *
fd_voter_join( void * voter );

/* fd_voter_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include voter is NULL. */

void *
fd_voter_leave( fd_voter_t const * voter );

/* fd_voter_delete unformats a memory region used as a voter.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g.  voter is obviously not a voter ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_voter_delete( void * voter );

/* fd_voter_txn_generate generates a vote txn using the TowerSync ix. */

ulong
fd_voter_txn_generate( fd_voter_t const *                     voter,
                       fd_compact_vote_state_update_t const * vote_update,
                       fd_hash_t const *                      recent_blockhash,
                       uchar                                  txn_meta_out[static FD_TXN_MAX_SZ],
                       uchar                                  txn_out[static FD_TXN_MTU] );

/* fd_voter_txn_parse parses a txn and returns a pointer to an
   fd_vote_instruction_t.  Assumes caller is currently in a scratch
   scope and allocates memory using fd_scratch_virtual().  Lifetime of
   the returned pointer is lifetime of the caller's scratch scope when
   calling this function. */

// fd_vote_instruction_t *
// fd_voter_txn_parse( uchar txn[static FD_TXN_MTU], ulong txn_sz,  );

#endif
