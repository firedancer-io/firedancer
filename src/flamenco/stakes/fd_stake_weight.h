#ifndef HEADER_fd_flamenco_stakes_fd_stake_weight_h
#define HEADER_fd_flamenco_stakes_fd_stake_weight_h

/* fd_stake_weight.h provides utils for dealing with stake weight sets. */

#include "../fd_flamenco_base.h"

struct fd_stake_weight {
  fd_pubkey_t key;      /* validator identity pubkey */
  ulong       stake;    /* total stake by identity */
};
typedef struct fd_stake_weight fd_stake_weight_t;

struct fd_vote_stake_weight {
  fd_pubkey_t vote_key;      /* vote account pubkey */
  fd_pubkey_t id_key;        /* validator identity pubkey */
  ulong       stake;         /* total stake by vote account */
  uchar       bls_key[ 48 ]; /* compressed BLS voting pubkey, zero if unregistered */
};
typedef struct fd_vote_stake_weight fd_vote_stake_weight_t;

#endif /* HEADER_fd_flamenco_stakes_fd_stake_weight_h */
