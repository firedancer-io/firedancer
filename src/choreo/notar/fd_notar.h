#ifndef HEADER_fd_src_choreo_notar_fd_notar_h
#define HEADER_fd_src_choreo_notar_fd_notar_h

#include "../fd_choreo_base.h"
#include "../tower/fd_tower.h"

/* fd_notar ("notarization") is an API for tracking when blocks reach
   key stake thresholds from votes.  Solana calls them "confirmation
   levels", and they are as follows:

   - propagation confirmed: a block is propagated if it has received
     votes from at least 1/3 of stake in the cluster.  This threshold is
     important for the leader pipeline, which ensures a previous leader
     block has propagated before producing the next one.  It is also
     used when voting, as we do not vote for forks in which our last
     leader block failed to propagate.

   - duplicate confirmed: a block is duplicate confirmed if it has
     received votes from at least 52% of stake in the cluster.  The
     "duplicate" adjective is a bit of a misnomer, and a more accurate
     technical term is equivocation: two (or more) different blocks for
     the same slot.  This threshold is important for consensus safety,
     because it ensures Solana eventually converges to a single block
     per slot.

   - optimistically confirmed: a block is optimistically confirmed it
     has received votes from at least 2/3 of stake in the cluster.  This
     threshold is important for end-users, who rely on the "confirmed"
     commitment status of blocks (queryable via RPC) to determine that
     their transaction has landed on a block that will not rollback. */

/* TODO duplicate confirmed / optimistc confirmed currently not
   implemented through this API */

/* FD_NOTAR_PARANOID:  Define this to non-zero at compile time
   to turn on additional runtime integrity checks. */

#ifndef FD_NOTAR_PARANOID
#define FD_NOTAR_PARANOID 1
#endif

struct fd_notar_vtr {
  fd_pubkey_t pubkey; /* map key */
  uint        memo;   /* reserved for fd_map_dynamic */
  ulong       bit;    /* bit position in fd_notar_blk_vtrs (fd_set) */
  ulong       vote;   /* the most recent slot the validator voted for */
  fd_hash_t   hash;   /* the most recent hash the validator voted for */
};
typedef struct fd_notar_vtr fd_notar_vtr_t;

static const fd_pubkey_t pubkey_null = {{ 0 }};

#define MAP_NAME              fd_notar_vtr
#define MAP_T                 fd_notar_vtr_t
#define MAP_HASH              memo
#define MAP_KEY               pubkey
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

#define SET_NAME fd_notar_blk_vtrs
#define SET_MAX  FD_VOTER_MAX
#include "../../util/tmpl/fd_set.c"

struct fd_notar_blk {
  ulong                 slot;
  ulong                 parent_slot;
  fd_hash_t             bank_hash;
  ulong                 stake;
  int                   pro_conf;
  int                   dup_conf; /* TODO unimplemented */
  int                   opt_conf; /* TODO unimplemented */
  fd_notar_blk_vtrs_t   vtrs[fd_notar_blk_vtrs_word_cnt]; /* pubkeys (validator identity) that have voted for this block */
};
typedef struct fd_notar_blk fd_notar_blk_t;

#define MAP_NAME    fd_notar_blk
#define MAP_T       fd_notar_blk_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_notar {
  fd_notar_blk_t * blks;
  fd_notar_vtr_t * vtrs;
  ulong            root;  /* current root slot */
  ulong            stake; /* total stake in the current epoch */
};
typedef struct fd_notar fd_notar_t;

/* fd_notar_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a notar.  align
   returns FD_NOTAR_ALIGN.  footprint returns FD_NOTAR_FOOTPRINT. */

FD_FN_CONST static inline ulong
fd_notar_align( void ) {
  return alignof(fd_notar_t);
}

FD_FN_CONST static inline ulong
fd_notar_footprint( ulong blk_max ) {
  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max      ) );
  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_notar_t),  sizeof(fd_notar_t)                   ),
      fd_notar_blk_align(), fd_notar_blk_footprint( lg_blk_max ) ),
      fd_notar_vtr_align(), fd_notar_vtr_footprint( lg_vtr_max ) ),
    fd_notar_align() );
}

/* fd_notar_new formats an unused memory region for use as a notar.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_notar_new( void * mem, ulong blk_max );

/* fd_notar_join joins the caller to the notar.  notar points to the
   first byte of the memory region backing the notar in the caller's
   address space.

   Returns a pointer in the local address space to notar on success. */

fd_notar_t *
fd_notar_join( void * notar );

/* fd_notar_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include notar is NULL. */

void *
fd_notar_leave( fd_notar_t const * notar );

/* fd_notar_delete unformats a memory region used as a notar.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. notar is obviously not a notar ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_notar_delete( void * notar );

/* fd_notar_vote updates notar with a "vote" which is a 4-tuple of
   (pubkey, stake, tower, hash).  pubkey is the voter's validator
   identity, stake is the voter's stake in the current epoch, vote_tower
   is the parsed tower from either the gossip vote transaction or replay
   vote state, and vote_hash is the voter's bank hash for the last slot
   in the tower. */

void
fd_notar_vote( fd_notar_t *        notar,
               fd_pubkey_t const * pubkey,
               ulong               stake,
               fd_tower_t const *  vote_tower,
               fd_hash_t const *   vote_hash );

/* fd_notar_publish publishes root as the new notar root slot, removing
   all blocks with slot numbers < the old notar root slot.  Some slots
   on minority forks that were pruned but > than the new root may remain
   but they will eventually be pruned as well as the root advances. */

void
fd_notar_publish( fd_notar_t * notar,
                  ulong        root );

#endif /* HEADER_fd_src_choreo_notar_fd_notar_h */
