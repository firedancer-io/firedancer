#include "fd_alpen.h"

/**
vote_pool is the certificate pool structure for the
Alpenglow consensus. The vote pool has two functions:
  1. It stores the votes for each slot and validator node id.
   - the first recieved notarization or skip vote,
   - Up to 3 notar-fallback votes
   - the first recieved skip-fallback vote
   - the first recieved finalization vote
  2. It aggregates the votes for each slot and vote type.


    To aggregate SafeToNotar & SafeToSkip
     iterate on vote type, slot
     iterate on vote type, slot/block_id

cant vote finalize if you have voted:
 - skip
 - notar fallback
 - or skip fallback

 There may be many block_ids for a given slot propagated by malicious nodes,
 but we only need to store up to the first 3 notarization fallbacks per
 validator id.

 No fast indexing on building the notarization fallback cert in this case,
 must search for the notarization block id in the 3 x 4096 array.
*/

/* Vote stuff */

#define VOTOR_MAX 4096
#define EQVOC_MAX 3

typedef ulong stake_t;

static const fd_hash_t pubkey_null = { 0 };

typedef struct {
  fd_hash_t key;
  uint      hash;
  stake_t   stake;
} map_t;

#define MAP_NAME              map
#define MAP_T                 map_t
#define MAP_KEY               key
#define MAP_KEY_T             fd_hash_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_INVAL(k)      !(memcmp(((k).uc),  MAP_KEY_NULL.uc, sizeof(fd_hash_t)))
#define MAP_KEY_EQUAL(k0,k1)  !(memcmp(((k0).uc), ((k1).uc),       sizeof(fd_hash_t)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     (uint)fd_ulong_hash(((key).ul[0]))
#define MAP_LG_SLOT_CNT       14 /* BLS = 4096. fill ratio 0.25 */
#include "../../util/tmpl/fd_map.c"

typedef struct {
  fd_hash_t key;
  uint      hash;
} set_t;

#define MAP_NAME              set
#define MAP_T                 set_t
#define MAP_KEY               key
#define MAP_KEY_T             fd_hash_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_INVAL(k)      !(memcmp(((k).uc),  MAP_KEY_NULL.uc, sizeof(fd_hash_t)))
#define MAP_KEY_EQUAL(k0,k1)  !(memcmp(((k0).uc), ((k1).uc),       sizeof(fd_hash_t)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     (uint)fd_ulong_hash(((key).ul[0]))
#define MAP_LG_SLOT_CNT       14 /* BLS = 4096. fill ratio 0.25 */
#include "../../util/tmpl/fd_map.c"

typedef struct {
  map_t * notar;
  map_t * notar_fallback;
  stake_t skip;
  stake_t skip_fallback;
  stake_t finalize;
  stake_t notar_or_skip;
  stake_t top_notar;
} slot_voted_stakes_t;

typedef fd_pubkey_t epoch_voter_ids[VOTOR_MAX]; /* */

struct notar_vote {
  fd_hash_t blockid;
  ulong     slot;
  fd_hash_t bank_hash; /* not necessary */
  fd_hash_t sig;       /* signed vote (?) */
};
typedef struct notar_vote notar_vote_t;
typedef struct notar_vote notar_fallback_vote_t;

struct skip_vote {
  ulong     slot;
  fd_hash_t sig;       /* signed vote (?) */
};
typedef struct skip_vote skip_vote_t;
typedef struct skip_vote skip_fallback_vote_t;

struct finalize_vote {
  ulong     slot;
  fd_hash_t sig;       /* signed vote (?) */
};
typedef struct finalize_vote finalize_vote_t;

#define VOTE_KIND_NOTAR (0)
#define VOTE_KIND_NOTAR_FALLBACK (1)


typedef struct {
  uchar kind;
  union {
    struct {
      ulong slot;
      fd_hash_t hash;
    } notar;

    struct {
      ulong slot;
      fd_hash_t hash;
    } notar_fallback;

    struct {
      ulong slot;
    } skip;

    struct {
      ulong slot;
    } skip_fallback;

    struct {
      ulong slot;
    } final;
  };
} vote_kind_t;

typedef union {
  struct {
    ulong slot;
    fd_hash_t hash;
  } notar;

  struct {
    ulong slot;
    fd_hash_t hash;
  } notar_fallback;

  struct {
    ulong slot;
  } skip;

  struct {
    ulong slot;
  } skip_fallback;

  struct {
    ulong slot;
  } final;

  notar_vote_t          notar;
  notar_fallback_vote_t notar_fallback[EQVOC_MAX];
  skip_vote_t           skip;
  skip_fallback_vote_t  skip_fallback;
  finalize_vote_t       finalizes;
} vote_kind_t;

vote_kind_t[VOTOR_MAX] = { }

typedef struct {
  fd_hash_t blockid;
  ulong     slot;
  fd_hash_t bank_hash; /* not necessary */
  fd_hash_t sig;       /* signed vote (?) */
} vote_t;

struct slot_votes {
  ulong slot;

  /* Votes for this slot */

  notar_vote_t          notar         [VOTOR_MAX];  /* may have different block_ids within this collection  */
  notar_fallback_vote_t notar_fallback[EQVOC_MAX][VOTOR_MAX]; /* block_id x voter */
  skip_vote_t           skip          [VOTOR_MAX];
  skip_fallback_vote_t  skip_fallback [VOTOR_MAX];
  finalize_vote_t       finalizes     [VOTOR_MAX];
};
typedef struct slot_votes slot_votes_t;

#define MAP_NAME        slot_votes_map
#define MAP_T           slot_votes_t
#define MAP_KEY         slot
#define MAP_KEY_NULL    0
#define MAP_MEMOIZE     0
#define MAP_LG_SLOT_CNT 12
#include "../../util/tmpl/fd_map.c"
/* maybe dynamic and then make map sz configurable
   until confirmed how many slots we can go before finalizing */

struct vote {
  slot_votes_t * slot_votes;
};
typedef struct vote vote_t;

/* Returns the votes store for the given slot. If the slot is not yet
   populated in the map, it will be inserted and initialized to zero. */
slot_votes_t *
slot_votes_query( slot_votes_t * slot_votes,
                           ulong                   slot ) {
  slot_votes_t * vote_map = slot_votes_map_query( slot_votes, slot, NULL );
  if( FD_UNLIKELY( !vote_map ) ) {
    vote_map = slot_votes_map_insert( slot_votes, slot );
    vote_map->slot = slot;
    memset( vote_map->notar,          0, sizeof(notar_vote_t) * VOTOR_MAX );
    memset( vote_map->notar_fallback, 0, sizeof(notar_fallback_vote_t) * EQVOC_MAX * VOTOR_MAX );
    memset( vote_map->skip,           0, sizeof(skip_vote_t) * VOTOR_MAX );
    memset( vote_map->skip_fallback,  0, sizeof(skip_fallback_vote_t) * VOTOR_MAX );
    memset( vote_map->finalizes,      0, sizeof(finalize_vote_t) * VOTOR_MAX );
  }
  return vote_map;
}

/* inline below vote inserters into alpen.c,
   wrap in a public insert_vote */

static void
notar_insert( slot_votes_t * slot_vote_map,
              fd_hash_t             * blockid,
              ulong                   slot,
              ulong                   validator_id, /* index into 4096 stake sorted voters of the epoch */
              fd_hash_t             * bank_hash ) {
  slot_votes_t * notar_map = slot_votes_query( slot_vote_map, slot );
  if( FD_UNLIKELY( notar_map->notar[validator_id].slot != 0 ) ) {
    /* already voted...any action to take?  */
    return;
  }
  notar_map->notar[validator_id] = (notar_vote_t){ .blockid = *blockid,
                                                            .slot = slot,
                                                            .bank_hash = *bank_hash };
}

static void
skip_insert( slot_votes_t * slot_vote_map,
             ulong                   slot,
             ulong                   validator_id ) {
  slot_votes_t * skip_map = slot_votes_query( slot_vote_map, slot );
  skip_map->skip[validator_id] = (skip_vote_t){ .slot = slot };
}

static void
skip_fallback_insert( slot_votes_t * slot_vote_map,
                      ulong                   slot,
                      ulong                   validator_id ) {
  slot_votes_t * skip_map = slot_votes_query( slot_vote_map, slot );
  skip_map->skip_fallback[validator_id] = (skip_fallback_vote_t){ .slot = slot };
}

static void
notar_fallback_insert( slot_votes_t * slot_vote_map,
                       fd_hash_t             * blockid,
                       ulong                   slot,
                       ulong                   validator_id,
                       fd_hash_t             * bank_hash ) {
  slot_votes_t * notar_map = slot_votes_query( slot_vote_map, slot );

  int block_id_idx;
  for( block_id_idx = 0; block_id_idx < EQVOC_MAX; block_id_idx++ ) {
    if( notar_map->notar_fallback[block_id_idx][validator_id].slot == 0 ) break;
  }
  if( FD_UNLIKELY( block_id_idx == EQVOC_MAX ) ) {
    /* already voted 3 notar fallbacks...any action to take?  */
    return;
  }
  notar_map->notar_fallback[block_id_idx][validator_id] = (notar_fallback_vote_t){ .blockid = *blockid,
                                                                                            .slot = slot,
                                                                                            .bank_hash = *bank_hash };
}

static void FD_FN_UNUSED
get_notar_votes_block_hash( slot_votes_t * slot_vote_map,
                            ulong                   slot,
                            fd_hash_t             * block_id ) {
  slot_votes_t * notar_map = slot_votes_query( slot_vote_map, slot );

  for(int i = 0; i < VOTOR_MAX; i++ ){
    if( memcmp( &notar_map->notar[i], block_id, sizeof(fd_hash_t) ) == 0 ) {
      notar_vote_t * notar_vote = &notar_map->notar[i];
      (void)notar_vote;
    }
  }
}

static void
finalize_insert( slot_votes_t * slot_vote_map,
                 ulong                   slot,
                 ulong                   validator_id ) {
  slot_votes_t * skip_map = slot_votes_map_query( slot_vote_map, slot, NULL );
  skip_map->skip[validator_id] = (skip_vote_t){ .slot = slot };
}

static int FD_FN_UNUSED
safe_to_skip_check( slot_votes_t * slot_vote_map,
                             ulong                   slot ) {
  slot_votes_t * vote_map = slot_votes_map_query( slot_vote_map, slot, NULL );
  if( FD_UNLIKELY( !vote_map ) ) return 0;
  for(int i = 0; i < VOTOR_MAX; i++ ) {
    if( vote_map->skip[i].slot != 0 ) {
      /* get stake */
    }
  }
  return 1;
}

typedef struct {
  uchar sig[128];
} blst_signature_t;

typedef struct {
  ulong slot;
  ulong stake;
} `;

typedef struct {
  blst_signature_t sig;
  ulong slot;
  fd_hash_t block_hash;
} aggregate_signature_t;

typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
  fd_hash_t bank_hash; /* not necessary */
  uchar     agg_sig_notar[1];
  stake_t stake;
} notar_cert_t;

typedef struct {
  fd_hash_t block_id;
  fd_hash_t bank_hash; /* not necessary */
  uchar     agg_sig_notar[1];
  uchar     agg_sig_notar_fallback[1];
} notar_fallback_cert_t;

typedef struct {
  uchar agg_sig_skip[1];
  uchar agg_sig_skip_fallback[1];
} skip_cert_t;

typedef struct {
  uchar agg_sig[1];
} fast_final_cert_t;

typedef struct {
  uchar agg_sig[1];
} final_cert_t;

typedef union {
  notar_cert_t          notar;
  notar_fallback_cert_t notar_fallback;
  skip_cert_t           skip;
  fast_final_cert_t     fast_final;
  final_cert_t          final;
} cert_t;

typedef struct {
  ulong  slot; /* map key */
  cert_t notar[1];
  cert_t notar_fallback[EQVOC_MAX];
  cert_t skip[1];
  cert_t fast_finalize[1];
  cert_t finalize[1];
} slot_certificates_t;

#define MAP_NAME        slot_certificates_map
#define MAP_T           slot_certificates_t
#define MAP_KEY         slot
#define MAP_KEY_NULL    0
#define MAP_MEMOIZE     0
#define MAP_LG_SLOT_CNT 12
#include "../../util/tmpl/fd_map.c"

typedef struct {
  slot_voted_stakes_t * voted_stakes;
  set_t *               pending_safe_to_notar;
  set_t *               sent_safe_to_notar;
  int                   sent_safe_to_skip;
} slot_state;

typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
} safe_to_notar_t;

typedef struct {
  ulong     slot;
} safe_to_skip_t;

typedef union {
  struct {
    ulong     slot;
    fd_hash_t block_hash;
  } notar;

  struct {
    ulong     slot;
    fd_hash_t block_hash;
  } notar_fallback;

  struct {
    ulong     slot;
    fd_hash_t block_hash;
  } skip;

  struct {
    ulong     slot;
  } skip_fallback;

  struct {
    ulong     slot;
  } final;
} vote_kind_t;

typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
} notar_cert_t;

typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
} fast_final_cert_t;

static int check_safe_to_notar( slot_state * self, fd_hash_t * block_hash ) {
  return 1;
}

static void is_weak_quorum( stake_t stake ) {
  /* check if we have a weak quorum */
  return 1;
}

static void count_notar_stake( slot_state * self, ulong slot, fd_hash_t * block_hash, stake_t stake, safe_to_notar_t * safe_to_notar_out, safe_to_skip_t * safe_to_skip_out, notar_cert_t * notar_cert,  ) {
  map_t * notar_stake = map_query( self->voted_stakes->notar, *block_hash, NULL );
  if ( FD_UNLIKELY( !notar_stake ) ) {
    notar_stake        = map_insert( self->voted_stakes->notar, *block_hash );
    notar_stake->stake = 0;
  }
  notar_stake->stake += stake;
  self->voted_stakes->notar_or_skip += stake;
  self->voted_stakes->top_notar = fd_ulong_max( notar_stake->stake, self->voted_stakes->top_notar );

  if( FD_UNLIKELY( !set_query( self->sent_safe_to_notar, *block_hash, NULL ) && check_safe_to_notar( self, block_hash ) ) ) {
    safe_to_notar_out->slot       = slot;
    safe_to_notar_out->block_hash = *block_hash;
  }
  if( FD_UNLIKELY( !self->sent_safe_to_skip && is_weak_quorum( self->voted_stakes->notar_or_skip - self->voted_stakes->top_notar ) && self ) ) {

  }
}
