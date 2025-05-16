#ifndef HEADER_fd_src_discof_alpenglow_vote_pool_h
#define HEADER_fd_src_discof_alpenglow_vote_pool_h

#include "../../disco/fd_disco_base.h"
#include "../../choreo/fd_choreo_base.h"
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

#define FD_ALPEN_EPOCH_VOTER_MAX 4096
#define FD_ALPEN_MAX_BLK_IN_SLOT 3

/* Vote definitions
   TODO */

enum vote_type {
  FD_ALPEN_VOTE_NULL,
  FD_ALPEN_VOTE_NOTARIZE,
  FD_ALPEN_VOTE_NOTARIZE_FALLBACK,
  FD_ALPEN_VOTE_SKIP,
  FD_ALPEN_VOTE_SKIP_FALLBACK,
  FD_ALPEN_VOTE_FINALIZE,
};
typedef enum vote_type fd_alpen_vote_type_t;

typedef struct {
  fd_alpen_vote_type_t type;
  union {
    struct {
      ulong slot;
      fd_hash_t block_hash;
    } notar;

    struct {
      ulong slot;
      fd_hash_t block_hash;
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
} fd_alpen_vote_kind_t;

struct fd_alpen_vote {
  fd_alpen_vote_kind_t kind;
  uchar sig[1];
  /* ulong validater_id; */
};
typedef struct fd_alpen_vote fd_alpen_vote_t;

struct fd_alpen_slot_votes {
  ulong slot;

  /* Votes for this slot */

  fd_alpen_vote_t skip          [FD_ALPEN_EPOCH_VOTER_MAX];
  fd_alpen_vote_t skip_fallback [FD_ALPEN_EPOCH_VOTER_MAX];
  fd_alpen_vote_t notar         [FD_ALPEN_EPOCH_VOTER_MAX];  /* may have different block_ids within this collection  */
  fd_alpen_vote_t notar_fallback[FD_ALPEN_MAX_BLK_IN_SLOT][FD_ALPEN_EPOCH_VOTER_MAX]; /* block_id x voter */
  fd_alpen_vote_t finalizes     [FD_ALPEN_EPOCH_VOTER_MAX];
};
typedef struct fd_alpen_slot_votes fd_alpen_slot_votes_t;

#define MAP_NAME        fd_alpen_slot_votes_map
#define MAP_T           fd_alpen_slot_votes_t
#define MAP_KEY         slot
#define MAP_KEY_NULL    0
#define MAP_MEMOIZE     0
#define MAP_LG_SLOT_CNT 12
#include "../../util/tmpl/fd_map.c"
/* maybe dynamic and then make map sz configurable
   until confirmed how many slots we can go before finalizing */

/* Returns the votes store for the given slot. If the slot is not yet
   populated in the map, it will be inserted and initialized to zero. */
fd_alpen_slot_votes_t *
fd_alpen_slot_votes_query( fd_alpen_slot_votes_t * slot_votes,
                           ulong                   slot ) {
  fd_alpen_slot_votes_t * vote_map = fd_alpen_slot_votes_map_query( slot_votes, slot, NULL );
  if( FD_UNLIKELY( !vote_map ) ) {
    vote_map = fd_alpen_slot_votes_map_insert( slot_votes, slot );
    vote_map->slot = slot;
    memset( vote_map->notar,          0, sizeof(fd_alpen_vote_t) * FD_ALPEN_EPOCH_VOTER_MAX );
    memset( vote_map->notar_fallback, 0, sizeof(fd_alpen_vote_t) * FD_ALPEN_MAX_BLK_IN_SLOT * FD_ALPEN_EPOCH_VOTER_MAX );
    memset( vote_map->skip,           0, sizeof(fd_alpen_vote_t) * FD_ALPEN_EPOCH_VOTER_MAX );
    memset( vote_map->skip_fallback,  0, sizeof(fd_alpen_vote_t) * FD_ALPEN_EPOCH_VOTER_MAX );
    memset( vote_map->finalizes,      0, sizeof(fd_alpen_vote_t) * FD_ALPEN_EPOCH_VOTER_MAX );
  }
  return vote_map;
}

/* inline below vote inserters into alpen.c,
   wrap in add_vote */
static void
notar_insert( fd_alpen_slot_votes_t * slot_vote_map,
              fd_hash_t             * blockid,
              ulong                   slot,
              ulong                   validator_id /* index into 4096 stake sorted voters of the epoch */ ) {
  fd_alpen_slot_votes_t * notar_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  if( FD_UNLIKELY( notar_map->notar[validator_id].kind.type != FD_ALPEN_VOTE_NULL ) ) {
    /* already voted...any action to take?  */
    return;
  }
  notar_map->notar[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_NOTARIZE,
                                                                .notar = { .slot = slot,
                                                                           .block_hash = *blockid } },
                                                      .sig  = {0} };
}

static void
skip_insert( fd_alpen_slot_votes_t * slot_vote_map,
             ulong                   slot,
             ulong                   validator_id ) {
  fd_alpen_slot_votes_t * skip_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  skip_map->skip[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_SKIP,
                                                              .skip = { .slot = slot } },
                                                    .sig  = {0} };
}

static void
notar_fallback_insert( fd_alpen_slot_votes_t * slot_vote_map,
                       fd_hash_t             * blockid,
                       ulong                   slot,
                       ulong                   validator_id ) {
  fd_alpen_slot_votes_t * notar_map = fd_alpen_slot_votes_query( slot_vote_map, slot );

  int block_id_idx;
  for( block_id_idx = 0; block_id_idx < FD_ALPEN_MAX_BLK_IN_SLOT; block_id_idx++ ) {
    if( notar_map->notar_fallback[block_id_idx][validator_id].kind.type == FD_ALPEN_VOTE_NULL ) break;
  }
  if( FD_UNLIKELY( block_id_idx == FD_ALPEN_MAX_BLK_IN_SLOT ) ) {
    /* already voted 3 notar fallbacks...any action to take?  */
    return;
  }
  notar_map->notar_fallback[block_id_idx][validator_id] =
    (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_NOTARIZE_FALLBACK,
                                 .notar_fallback = { .slot = slot,
                                                     .block_hash = *blockid } },
                       .sig  = {0} };

}

static void
skip_fallback_insert( fd_alpen_slot_votes_t * slot_vote_map,
                      ulong                   slot,
                      ulong                   validator_id ) {
  fd_alpen_slot_votes_t * skip_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  skip_map->skip_fallback[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_SKIP_FALLBACK,
                                                                       .skip_fallback = { .slot = slot } },
                                                             .sig  = {0} };
}

static void
finalize_insert( fd_alpen_slot_votes_t * slot_vote_map,
                 ulong                   slot,
                 ulong                   validator_id ) {
  fd_alpen_slot_votes_t * votes = fd_alpen_slot_votes_map_query( slot_vote_map, slot, NULL );
  votes->finalizes[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_FINALIZE,
                                                                .final = { .slot = slot } },
                                                      .sig  = {0} };
}

/* Certificate definitions
   TODO */

enum cert_type {
  NOTAR = 0,
  NOTAR_FALLBACK,
  SKIP,
  SKIP_FALLBACK,
  FAST_FINALIZE,
  FINALIZE
};

struct fd_alpen_cert {
  enum cert_type type;
  ulong          slot;
  union {
    struct {
      fd_hash_t block_id;
      uchar     agg_sig_notar[1];
    } notar;

    struct {
      fd_hash_t block_id;
      uchar     agg_sig_notar[1];
      uchar     agg_sig_notar_fallback[1];
    } notar_fallback;

    struct {
      uchar agg_sig_skip[1];
      uchar agg_sig_skip_fallback[1];
    } skip;

    struct {
      uchar agg_sig[1];
    } fast_finalize;

    struct {
      uchar agg_sig[1];
    } finalize;
  };
  ulong          stake;
};
typedef struct fd_alpen_cert fd_alpen_cert_t;

struct fd_alpen_slot_certificates {
  ulong           slot;
  fd_alpen_cert_t notar;
  fd_alpen_cert_t notar_fallback[FD_ALPEN_MAX_BLK_IN_SLOT];
  fd_alpen_cert_t skip;
  fd_alpen_cert_t fast_finalize;
  fd_alpen_cert_t finalize;
};
typedef struct fd_alpen_slot_certificates fd_alpen_slot_certificates_t;

#define MAP_NAME        fd_alpen_slot_certificates_map
#define MAP_T           fd_alpen_slot_certificates_t
#define MAP_KEY         slot
#define MAP_KEY_NULL    0
#define MAP_MEMOIZE     0
#define MAP_LG_SLOT_CNT 12
#include "../../util/tmpl/fd_map.c"

#endif /* HEADER_fd_src_discof_alpenglow_vote_pool_h */