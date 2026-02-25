#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

struct fd_vote_stakes;
typedef struct fd_vote_stakes fd_vote_stakes_t;

ulong
fd_vote_stakes_align( void );

ulong
fd_vote_stakes_footprint( ulong max_vote_accounts,
                          ulong max_fork_width,
                          ulong map_chain_cnt );

void *
fd_vote_stakes_new( void * shmem,
                    ulong  max_vote_accounts,
                    ulong  max_fork_width,
                    ulong  map_chain_cnt,
                    ulong  seed );

fd_vote_stakes_t *
fd_vote_stakes_join( void * shmem );

ushort
fd_vote_stakes_init( fd_vote_stakes_t * vote_stakes );

void
fd_vote_stakes_insert_root( fd_vote_stakes_t * vote_stakes,
                            fd_pubkey_t *      pubkey,
                            ulong              stake_t_1,
                            ulong              stake_t_2 );

ushort
fd_vote_stakes_new_child( fd_vote_stakes_t * vote_stakes );

void
fd_vote_stakes_advance_root( fd_vote_stakes_t * vote_stakes,
                             ushort             new_root_idx );

void
fd_vote_stakes_insert( fd_vote_stakes_t * vote_stakes,
                       ushort             fork_idx,
                       fd_pubkey_t *      pubkey,
                       ulong              stake );

/*
  on epoch boundary:
  - get new child fork idx
  -


*/

/**/

// 2^27 (pubkey, stake)
// Pool<(Pubkey, Stake, Refcnt)>, 2^27 -- 6GiB,  referenced by banks
// Map<(Pubkey, Stake), uint_pool_idx>, -- 1GiB

// 32 (max_fork_width)
// Pool<(List<uint>, Refcnt)>, -- 16 GiB

/*
struct vote_stakes_index_ele {
  fd_pubkey_t pubkey;
  ulong       stake;
  ushort      refcnt
};

map( (pubkey,stake) -> pool_idx)

*/


// 4096 (max_live_banks)
// struct Bank {
  // stakes_pool_idx: ushort,
// }
// each bank_idx reference

FD_PROTOTYPES_END

#endif
