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

  fd_alpen_vote_t skip          [VOTOR_MAX];
  fd_alpen_vote_t skip_fallback [VOTOR_MAX];
  fd_alpen_vote_t notar         [VOTOR_MAX];  /* may have different block_ids within this collection  */
  fd_alpen_vote_t notar_fallback[EQVOC_MAX][VOTOR_MAX]; /* block_id x voter */
  fd_alpen_vote_t finalizes     [VOTOR_MAX];
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

struct vote {
  fd_alpen_slot_votes_t * slot_votes;
};
typedef struct vote vote_t;

/* Returns the votes store for the given slot. If the slot is not yet
   populated in the map, it will be inserted and initialized to zero. */
fd_alpen_slot_votes_t *
fd_alpen_slot_votes_query( fd_alpen_slot_votes_t * slot_votes,
                              ulong                   slot ) {
  fd_alpen_slot_votes_t * vote_map = fd_alpen_slot_votes_map_query( slot_votes, slot, NULL );
  if( FD_UNLIKELY( !vote_map ) ) {
    vote_map = fd_alpen_slot_votes_map_insert( slot_votes, slot );
    vote_map->slot = slot;
    memset( vote_map->notar,          0, sizeof(fd_alpen_vote_t) * VOTOR_MAX );
    memset( vote_map->notar_fallback, 0, sizeof(fd_alpen_vote_t) * VOTOR_MAX * EQVOC_MAX );
    memset( vote_map->skip,           0, sizeof(fd_alpen_vote_t) * VOTOR_MAX );
    memset( vote_map->skip_fallback,  0, sizeof(fd_alpen_vote_t) * VOTOR_MAX );
    memset( vote_map->finalizes,      0, sizeof(fd_alpen_vote_t) * VOTOR_MAX );
  }
  return vote_map;
}

/* TODO .h */

void
notar_insert( fd_alpen_slot_votes_t * slot_vote_map,
              fd_hash_t             * blockid,
              ulong                   slot,
              ulong                   validator_id /* index into 4096 stake sorted voters of the epoch */ ) {
  fd_alpen_slot_votes_t * notar_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  if( FD_UNLIKELY( notar_map->notar[validator_id].kind.type != FD_ALPEN_VOTE_NULL ) ) {
    /* already voted for this slot */
    return;
  }
  notar_map->notar[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_NOTARIZE,
                                                                .notar = { .slot = slot,
                                                                          .block_hash = *blockid } },
                                                      .sig  = {0} };
}

void
skip_insert( fd_alpen_slot_votes_t * slot_vote_map,
            ulong                   slot,
            ulong                   validator_id ) {
  fd_alpen_slot_votes_t * skip_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  skip_map->skip[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_SKIP,
                                                              .skip = { .slot = slot } },
                                                    .sig  = {0} };
}

void
notar_fallback_insert( fd_alpen_slot_votes_t * slot_vote_map,
                      fd_hash_t             * blockid,
                      ulong                   slot,
                      ulong                   validator_id ) {
  fd_alpen_slot_votes_t * notar_map = fd_alpen_slot_votes_query( slot_vote_map, slot );

  int block_id_idx;
  for( block_id_idx = 0; block_id_idx < EQVOC_MAX; block_id_idx++ ) {
    if( notar_map->notar_fallback[block_id_idx][validator_id].kind.type == FD_ALPEN_VOTE_NULL ) break;
  }
  if( FD_UNLIKELY( block_id_idx == EQVOC_MAX ) ) {
    /* already voted 3 notar fallbacks...any action to take?  */
    return;
  }
  notar_map->notar_fallback[block_id_idx][validator_id] =
    (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_NOTARIZE_FALLBACK,
                                .notar_fallback = { .slot = slot,
                                                    .block_hash = *blockid } },
                      .sig  = {0} };

}

void
skip_fallback_insert( fd_alpen_slot_votes_t * slot_vote_map,
                      ulong                   slot,
                      ulong                   validator_id ) {
  fd_alpen_slot_votes_t * skip_map = fd_alpen_slot_votes_query( slot_vote_map, slot );
  skip_map->skip_fallback[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_SKIP_FALLBACK,
                                                                      .skip_fallback = { .slot = slot } },
                                                            .sig  = {0} };
}

void
finalize_insert( fd_alpen_slot_votes_t * slot_vote_map,
                ulong                   slot,
                ulong                   validator_id ) {
  fd_alpen_slot_votes_t * votes = fd_alpen_slot_votes_map_query( slot_vote_map, slot, NULL );
  votes->finalizes[validator_id] = (fd_alpen_vote_t){ .kind = { .type = FD_ALPEN_VOTE_FINALIZE,
                                                                .final = { .slot = slot } },
                                                      .sig  = {0} };
}

static int FD_FN_UNUSED
safe_to_skip_check( fd_alpen_slot_votes_t * slot_vote_map,
                    ulong                   slot ) {
  fd_alpen_slot_votes_t * vote_map = fd_alpen_slot_votes_map_query( slot_vote_map, slot, NULL );
  if( FD_UNLIKELY( !vote_map ) ) return 0;
  for(int i = 0; i < VOTOR_MAX; i++ ) {
    if( vote_map->skip[i].kind.skip.slot != 0 ) {
      /* get stake */
    }
  }
  return 1;
}

typedef struct {
  uchar sig[128];
} blst_signature_t;

/* Certificate definitions
   TODO */

enum cert_type {
  FD_ALPEN_CERT_NOTAR,
  FD_ALPEN_CERT_NOTAR_FALLBACK,
  FD_ALPEN_CERT_SKIP,
  FD_ALPEN_CERT_FAST_FINALIZE,
  FD_ALPEN_CERT_FINALIZE
};

struct fd_alpen_cert {
  uchar          is_some;
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
  ulong stake;
};
typedef struct fd_alpen_cert fd_alpen_cert_t;

struct fd_alpen_slot_certificates {
  ulong           slot;
  fd_alpen_cert_t notar[1];
  fd_alpen_cert_t notar_fallback[EQVOC_MAX];
  fd_alpen_cert_t skip[1];
  fd_alpen_cert_t fast_finalize[1];
  fd_alpen_cert_t finalize[1];
};
typedef struct fd_alpen_slot_certificates fd_alpen_slot_certificates_t;

#define MAP_NAME        fd_alpen_slot_certificates_map
#define MAP_T           fd_alpen_slot_certificates_t
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

/* TODO: alternate cert type options */
typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
} notar_cert_t;

typedef struct {
  ulong     slot;
  fd_hash_t block_hash;
} fast_final_cert_t;

static int check_safe_to_notar( slot_state * self, fd_hash_t * block_hash ) {
  (void)self;
  (void)block_hash;
  return 1;
}

static int is_weak_quorum( stake_t stake ) {
  /* check if we have a weak quorum */
  (void)stake;
  return 1;
}

static void FD_FN_UNUSED
count_notar_stake( slot_state      * self FD_PARAM_UNUSED,
                   ulong             slot,
                   fd_hash_t       * block_hash FD_PARAM_UNUSED,
                   stake_t           stake,
                   safe_to_notar_t * safe_to_notar_out,
                   safe_to_skip_t  * safe_to_skip_out FD_PARAM_UNUSED,
                   notar_cert_t    * notar_cert FD_PARAM_UNUSED ) {
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

struct fd_alpen_parent_ready {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_hash;
};
typedef struct fd_alpen_parent_ready fd_alpen_parent_ready_t;

#define DEQUE_NAME        fd_alpen_parent_ready_deque
#define DEQUE_T           fd_alpen_parent_ready_t
#define DEQUE_MAX         1024
#include "../../util/tmpl/fd_deque.c"

#define FD_ALPEN_WINDOW_SZ 4

#define FD_ALPEN_CERT_SUCCESS 0
#define FD_ALPEN_CERT_FAILED -1

/* Returns the certificates store for the given slot. If the slot is not yet
   populated in the map, it will be inserted and initialized to zero. */
fd_alpen_slot_certificates_t *
fd_alpen_slot_certificates_query( fd_alpen_slot_certificates_t * slot_cert_map,
                                  ulong                          slot ) {
  fd_alpen_slot_certificates_t * cert_map = fd_alpen_slot_certificates_map_query( slot_cert_map, slot, NULL );
  if( FD_UNLIKELY( !cert_map ) ) {
    cert_map = fd_alpen_slot_certificates_map_insert( slot_cert_map, slot );
    cert_map->slot = slot;
    memset( &cert_map->notar,          0, sizeof(fd_alpen_cert_t) );
    memset( &cert_map->notar_fallback, 0, sizeof(fd_alpen_cert_t) * EQVOC_MAX );
    memset( &cert_map->skip,           0, sizeof(fd_alpen_cert_t) );
    memset( &cert_map->fast_finalize,  0, sizeof(fd_alpen_cert_t) );
    memset( &cert_map->finalize,       0, sizeof(fd_alpen_cert_t) );
  }
  return cert_map;
}

/* TODO: place below in .c file & wrap in general cert insert */

int
notar_fallback_cert_insert( fd_alpen_slot_certificates_t * cert_pool,
                            fd_alpen_cert_t              * cert ) {
  FD_TEST( cert->type == FD_ALPEN_CERT_NOTAR_FALLBACK );
  fd_alpen_slot_certificates_t * slot_certs = fd_alpen_slot_certificates_query( cert_pool, cert->slot );

  int block_id_idx;
  for( block_id_idx = 0; block_id_idx < EQVOC_MAX; block_id_idx++ ) {
    if( !slot_certs->notar_fallback[block_id_idx].is_some ) break;
  }

  if( FD_UNLIKELY( block_id_idx == EQVOC_MAX ) ) {
    FD_LOG_WARNING(( "Notar fallback cert for slot %lu already reached max", cert->slot ));
    return FD_ALPEN_CERT_FAILED;
  }
  cert->is_some = 1;
  slot_certs->notar_fallback[block_id_idx] = *cert;
  return FD_ALPEN_CERT_SUCCESS;
}

int
notar_cert_insert( fd_alpen_slot_certificates_t * cert_pool,
                   fd_alpen_cert_t              * cert ) {
  FD_TEST( cert->type == FD_ALPEN_CERT_NOTAR );
  ulong notar_slot = cert->slot;

  fd_alpen_slot_certificates_t * slot_certs = fd_alpen_slot_certificates_query( cert_pool, notar_slot );
  if( FD_UNLIKELY( slot_certs->notar->is_some ) ) return FD_ALPEN_CERT_FAILED;
  cert->is_some        = 1;
  slot_certs->notar[0] = *cert;
  return FD_ALPEN_CERT_SUCCESS;
}

/* Adds skip certificate to the certificate pool. */
int
skip_cert_insert( fd_alpen_slot_certificates_t * cert_pool,
                  fd_alpen_cert_t              * cert ) {
  FD_TEST( cert->type == FD_ALPEN_CERT_SKIP );

  ulong skip_slot = cert->slot;
  fd_alpen_slot_certificates_t * slot_certs = fd_alpen_slot_certificates_query( cert_pool, skip_slot );
  if( FD_UNLIKELY( slot_certs->skip->is_some ) ) {
    FD_LOG_WARNING(( "Skip cert for slot %lu already populated", skip_slot ));
    return FD_ALPEN_CERT_FAILED;
  }
  cert->is_some       = 1;
  slot_certs->skip[0] = *cert;
  return FD_ALPEN_CERT_SUCCESS;
}

static int FD_FN_UNUSED
finalize_cert_insert( fd_alpen_slot_certificates_t * cert_pool,
                      fd_alpen_cert_t              * cert ) {
  FD_TEST( cert->type == FD_ALPEN_CERT_FINALIZE );
  fd_alpen_slot_certificates_t * slot_certs = fd_alpen_slot_certificates_query( cert_pool, cert->slot );
  if( FD_UNLIKELY( slot_certs->finalize->is_some ) ) {
    FD_LOG_WARNING(( "Finalize cert for slot %lu already populated", cert->slot ));
    return FD_ALPEN_CERT_FAILED;
  }
  cert->is_some = 1;
  slot_certs->finalize[0] = *cert;
  return FD_ALPEN_CERT_SUCCESS;
}

/* Checks if the provided cert can emit new ParentReady events. If new
   ParentReady events are possible, they are pushed to the tail of the
   parent_ready_out deque. Should be called immediately after
   cert_insert, and assumes that the cert has already been added to the
   cert pool.

   Typically the caller should ensure that the
   parent_ready_out deque is empty before calling check_parent_ready,
   and pop off all ParentReady objects after calling. */
void
check_parent_ready( fd_alpen_slot_certificates_t  * cert_pool,
                    fd_alpen_cert_t               * cert,
                    fd_alpen_parent_ready_t       * parent_ready_out ) {
  ulong slot = cert->slot;
  switch( cert->type ) {
    case FD_ALPEN_CERT_NOTAR:
    case FD_ALPEN_CERT_NOTAR_FALLBACK: {
      /* Check if this new notar cert enables a following chain of skips */
      for( ulong fwd_slot = slot + 1; ; fwd_slot++ ) {
        fd_alpen_slot_certificates_t * fwd_slot_certs = fd_alpen_slot_certificates_map_query( cert_pool, fwd_slot, NULL );
        if( fwd_slot % FD_ALPEN_WINDOW_SZ == 0 ) {
          fd_alpen_parent_ready_deque_push_tail( parent_ready_out,
                 (fd_alpen_parent_ready_t){ .slot = fwd_slot,
                                                 .parent_slot = slot,
                                                 .parent_hash = cert->notar_fallback.block_id } ); // todo need notar

        }
        if( FD_UNLIKELY( !fwd_slot_certs ) ) break;
        if( !fwd_slot_certs->skip->is_some ) break; // no skip cert in this slot
      }
      break;
    }
    case FD_ALPEN_CERT_SKIP: {
      /* Check if this new skip cert enables connections future windows,
        i.e., it creates a consecutive sequence of skip certs. */
      ulong max_future_window_enabled = slot;
      for( ulong fwd_slot = slot + 1; ; fwd_slot++ ) {
        fd_alpen_slot_certificates_t * fwd_slot_certs = fd_alpen_slot_certificates_map_query( cert_pool, fwd_slot, NULL );
        if( fwd_slot % FD_ALPEN_WINDOW_SZ == 0 ) {
          max_future_window_enabled = fwd_slot;
        }
        if( FD_UNLIKELY( !fwd_slot_certs ) ) break;
        if( !fwd_slot_certs->skip->is_some ) break;
      }

      /* Seeking backwards for consecutive skip windows, adding
         notarizefallbacks as we go */

      for( ulong i = slot; ; i-- ) {
        fd_alpen_slot_certificates_t * back_slot_certs = fd_alpen_slot_certificates_map_query( cert_pool, i, NULL );
        if( FD_UNLIKELY( !back_slot_certs ) )                    break;

        if( FD_UNLIKELY( back_slot_certs->notar_fallback->is_some ) ) {

          /* Found a notar_fallback certificate for this slot. Now all of
            these notar_fallback certificates can cause parentReadys for
            all the leaderWindow slots enabled that were found previously. */

          ulong potential_parent_slot = back_slot_certs->notar_fallback[0].slot;

          /* For each of the notarfallbacks in this slot, create a parentReady
            event for the enabled future windows */

          for( int j = 0; j < EQVOC_MAX; j++ ) {
            if( !back_slot_certs->notar_fallback[j].is_some ) break;
            fd_alpen_cert_t * nf_cert = &back_slot_certs->notar_fallback[j];

            /* FIXME: order might matter, double check iter fwd or back? */
            for( ulong window_slot = max_future_window_enabled; window_slot > slot; window_slot-=FD_ALPEN_WINDOW_SZ ) {
              fd_alpen_parent_ready_deque_push_tail( parent_ready_out,
                                                     (fd_alpen_parent_ready_t){ .slot = window_slot,
                                                                                     .parent_slot = potential_parent_slot,
                                                                                     .parent_hash = nf_cert->notar.block_id } );

            }
          }
        }

        if( FD_LIKELY( back_slot_certs->notar->is_some ) ) {
          /* Have a notar certificate for this slot. Add it as parentReady option */
          ulong potential_parent_slot = back_slot_certs->notar->slot;
          for( ulong window_slot = max_future_window_enabled; window_slot > slot; window_slot-=FD_ALPEN_WINDOW_SZ ) {
            fd_alpen_parent_ready_deque_push_tail( parent_ready_out,
                                                  (fd_alpen_parent_ready_t){ .slot        = window_slot,
                                                                                  .parent_slot = potential_parent_slot,
                                                                                  .parent_hash = back_slot_certs->notar->notar.block_id } );
          }
        }

        if( FD_UNLIKELY( !back_slot_certs->skip->is_some ) ) break; /* no more contiguous skips */
      }
      break;
    }
    default:
      break;
  }
}
