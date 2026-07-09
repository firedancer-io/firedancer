#ifndef HEADER_fd_flamenco_stakes_fd_stake_weight_h
#define HEADER_fd_flamenco_stakes_fd_stake_weight_h

/* fd_stake_weight.h provides utils for dealing with stake weight sets. */

#include "../fd_flamenco_base.h"

struct fd_stake_weight {
  fd_pubkey_t key;      /* validator identity pubkey */
  ulong       stake;    /* total stake by identity */
};
typedef struct fd_stake_weight fd_stake_weight_t;

#define SORT_NAME fd_stake_weight_key_sort
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

struct fd_vote_stake_weight {
  fd_pubkey_t vote_key; /* vote account pubkey */
  fd_pubkey_t id_key;   /* validator identity pubkey */
  ulong       stake;    /* total stake by vote account */
};
typedef struct fd_vote_stake_weight fd_vote_stake_weight_t;

#define SORT_NAME sort_vote_weights_by_stake_vote
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).vote_key.uc, (b).vote_key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#endif /* HEADER_fd_flamenco_stakes_fd_stake_weight_h */
