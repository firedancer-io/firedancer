#ifndef HEADER_test_tower_util_h
#define HEADER_test_tower_util_h

#include "../voter/fd_voter.h"
#include "fd_tower_forks.h"
static inline void 
make_vote_account(fd_hash_t const *pubkey, 
                  ulong stake,
                  ulong vote, 
                  uint conf, 
                  fd_tower_accts_t *out)
{
    fd_voter_t voter = {
        .kind = FD_VOTER_V3,
        .v3 = {
            .node_pubkey = *pubkey,
            .votes_cnt = 1,
            .votes = {
                {.slot = vote, .conf = conf},
            },
        }};

    memcpy(out->data, &voter, sizeof(fd_voter_t));
    out->stake = stake;
    out->addr = *pubkey;
}

#endif /* HEADER_test_tower_util_h */