#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_states_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_states_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

#define FD_VOTE_STATES_MAGIC (0x01231965UL)

struct fd_vote_state_ele {
  fd_pubkey_t vote_account;
  ulong next_; /* Internal pool/map use */
  /* TODO: fill in vote state ele fields*/
};
typedef struct fd_vote_state fd_vote_state_t;

#define POOL_NAME fd_vote_state_pool
#define POOL_T    fd_vote_state_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_vote_state_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_state_ele_t
#define MAP_KEY                vote_account
#define MAP_KEY_EQ(k0,k1)      (!(memcmp(&(k0)->key,&(k1)->key,sizeof(fd_pubkey_t))))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_
#include "../../util/tmpl/fd_map_chain.c"

struct fd_vote_states {
  ulong magic;
  ulong max_vote_accounts;
};
typedef struct fd_vote_states fd_vote_states_t;

FD_PROTOTYPES_BEGIN

/* fd_vote_states_get_pool returns the underlying pool that the
   vote states uses to manage the vote states. */

fd_vote_state_ele_t *
fd_vote_states_get_pool( fd_vote_states_t const * vote_states );

/* fd_vote_states_get_map returns the underlying map that the
   vote states uses to manage the vote states. */

fd_vote_state_map_t *
fd_vote_states_get_map( fd_vote_states_t const * vote_states );

/* fd_vote_states_align returns the minimum alignment required for a
   vote states struct. */

ulong
fd_vote_states_align( void );

/* fd_vote_states_footprint returns the footprint of the vote states
   struct for a given amount of max vote accounts. */

ulong
fd_vote_states_footprint( ulong max_vote_accounts );

/* fd_vote_states_new creates a new vote states struct
   with a given amount of max vote accounts. It formats a memory region
   which is sized based off of the number of vote accounts. */

void *
fd_vote_states_new( void * mem, ulong max_vote_accounts );

/* fd_vote_states_join joins a vote states struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_vote_states_t *
fd_vote_states_join( void * mem );

/* fd_vote_states_leave returns the vote states struct from a memory
   region. This function returns a pointer to the vote states struct
   and does not take ownership of the memory region. */

void *
fd_vote_states_leave( fd_vote_states_t * self );

/* fd_vote_states_delete unformats a memory region that was
   formatted by fd_vote_states_new. */

void *
fd_vote_states_delete( void * mem );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_states_h */