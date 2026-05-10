#ifndef HEADER_fd_src_flamenco_types_fd_types_custom_h
#define HEADER_fd_src_flamenco_types_fd_types_custom_h

#include "../fd_flamenco_base.h"
#include "../../ballet/bmtree/fd_bmtree.h"

FD_STATIC_ASSERT( sizeof(fd_hash_t) == sizeof(fd_bmtree_node_t), hash incompatibility ); /* various areas of Firedancer code use fd_hash_t as the type for merkle roots */

struct fd_hard_fork {
  ulong slot;
  ulong cnt; /* number of hard forks in that slot */
};
typedef struct fd_hard_fork fd_hard_fork_t;

#define FD_DUMMY_ACCOUNT { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }
static const fd_pubkey_t FD_DUMMY_ACCOUNT_PUBKEY = { .uc = FD_DUMMY_ACCOUNT };

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

struct fd_stake_weight {
  fd_pubkey_t key;      /* validator identity pubkey */
  ulong       stake;    /* total stake by identity */
};
typedef struct fd_stake_weight fd_stake_weight_t;

#define SORT_NAME fd_stake_weight_key_sort
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

struct fd_fee_rate_governor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  uchar burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;

struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double unused;
};
typedef struct fd_inflation fd_inflation_t;

#endif /* HEADER_fd_src_flamenco_types_fd_types_custom_h */
