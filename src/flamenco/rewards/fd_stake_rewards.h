#ifndef HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h

#include "../../util/fd_util_base.h"
#include "../../util/tmpl/fd_map.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

#define FD_STAKE_REWARDS_ALIGN (128UL)

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

FD_PROTOTYPES_END

ulong
fd_stake_rewards_align( void );

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_fork_width,
                            ulong expected_stake_accs );

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_fork_width,
                      ulong  expected_stake_accs,
                      ulong  seed );

fd_stake_rewards_t *
fd_stake_rewards_join( void * shmem );

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       fd_hash_t const *    parent_blockhash,
                       ulong                partitions_cnt );

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );


void
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards );

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            ushort               partition_idx );

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx );

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards );

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           uchar                fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out );

#endif /* HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h */
