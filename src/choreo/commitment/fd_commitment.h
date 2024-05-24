#ifndef HEADER_fd_src_choreo_commitment_fd_commitment_h
#define HEADER_fd_src_choreo_commitment_fd_commitment_h

#include "../fd_choreo_base.h"

/* fd_slot_commitment is a representation of a block's commitment status.

   Equivocation-safe: A (slot, hash) pair is equivocation-safe once it has reached 52%
   of vote stake.

   Optimistically-confirmed: A (slot, hash) pair is optimistically-confirmed once it has reached 2/3
   of vote stake.
*/

#define FD_SUPERMAJORITY ( 2.0 / 3.0 )

// TODO unify commitment and ghost?

struct fd_slot_commitment {
  ulong     slot; /* map key */
  uint      hash; /* internal use by fd_map */
  fd_hash_t bank_hash;
  ulong     confirmed_stake[32UL]; /* how much stake has voted on this slot */
  ulong     rooted_stake;          /* how much stake has rooted this slot or any descendant */
  int       confirmed;             /* confirmed ie. optimistically-confirmed in ghost  */
  int       finalized;             /* finalized ie. super-majority root */
};
typedef struct fd_slot_commitment fd_slot_commitment_t;

#define MAP_NAME fd_slot_commitment_map
#define MAP_T    fd_slot_commitment_t
#define MAP_KEY  slot
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_commitment {
  ulong                  slot; /* the last slot at which commitment was computed */
  fd_slot_commitment_t * map;
};
typedef struct fd_commitment fd_commitment_t;

/* fd_commitment_slot_insert inserts a slot. */
fd_slot_commitment_t *
fd_commitment_slot_insert( fd_commitment_t * commitment, ulong slot );

fd_slot_commitment_t *
fd_commitment_slot_query( fd_commitment_t * commitment, ulong slot );

/* fd_commitment_highest_confirmed_query returns the highest confirmed slot. */
ulong
fd_commitment_highest_confirmed_query( fd_commitment_t const * commitment );

/* fd_commitment_highest_finalized_query returns the highest finalized slot. */
ulong
fd_commitment_highest_finalized_query( fd_commitment_t const * commitment );

#endif /* HEADER_fd_src_choreo_commitment_fd_commitment_h */
