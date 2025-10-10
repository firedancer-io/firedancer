#ifndef HEADER_fd_src_choreo_notar_fd_notar_h
#define HEADER_fd_src_choreo_notar_fd_notar_h

#include "../fd_choreo_base.h"
#include "../tower/fd_tower.h"

/* fd_notar is an API for notarizing blockswhen they reach key stake
   thresholds from votes.  Solana calls them "confirmation levels", and
   they are as follows:

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
     their transaction has landed on a block that will not rollback.

   The reason both fd_ghost and fd_notar exist even though they do
   seemingly similar things (summing vote stakes for different slots) is
   because Solana implements the rules quite differently.

   In fd_ghost, we use the GHOST rule to recursively sum the stake of
   the subtree (a slot and all its descendants).  The LMD rule counts a
   validator's stake to at most one fork.  When the validator switches
   forks, their stake is subtracted from the old fork and added to the
   new fork.  The tree is then traversed as part of fork choice to find
   the best leaf ("head").

   In fd_notar, we sum votes towards only the block itself, and not its
   ancestors, and also a validator's stake can be counted towards
   multiple blocks at the same time if they vote on a fork then switch
   to a different one.  There is also no tree traversal, and the output
   is simply confirmed notifications.

   fd_ghost also makes fork choice decision purely based on replay votes
   whereas fd_notar's confirmation is based on both gossip and replay
   votes (fd_ghost does use gossip votes for marking forks valid or
   invalid for fork choice though). */

/* FD_NOTAR_PARANOID:  Define this to non-zero at compile time to turn
   on additional runtime integrity checks. */

#ifndef FD_NOTAR_PARANOID
#define FD_NOTAR_PARANOID 1
#endif

#define SET_NAME fd_notar_blk_vtrs
#define SET_MAX  FD_VOTER_MAX
#include "../../util/tmpl/fd_set.c"

struct fd_notar_blk {
  fd_hash_t block_id; /* map key */
  uint      hash;     /* reserved for fd_map_dynamic */
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t bank_hash; /* bank_hash associated with this block_id */
  ulong     stake;   /* sum of stake that has voted for this block */
  ulong     total;   /* total stake across all vote accounts */
  int       pro_conf;
  int       dup_conf;
  int       opt_conf;

  fd_notar_blk_vtrs_t vtrs[fd_notar_blk_vtrs_word_cnt]; /* who has already voted for this blk */
};
typedef struct fd_notar_blk fd_notar_blk_t;

static const fd_hash_t hash_null = {{ 0 }};

#define MAP_NAME              fd_notar_blk
#define MAP_T                 fd_notar_blk_t
#define MAP_KEY               block_id
#define MAP_KEY_T             fd_hash_t
#define MAP_KEY_NULL          hash_null
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_notar_vtr {
  fd_pubkey_t pubkey;      /* map key */
  uint        hash;        /* reserved for fd_map_dynamic */
  ulong       bit;         /* bit position in fd_notar_blk_vtrs (fd_set) */
  ulong       stake;       /* stake in the current epoch */
  ulong       replay_vote; /* the most recent slot the validator voted for */
  fd_hash_t   replay_hash; /* the most recent hash the validator voted for */
  ulong       gossip_vote; /* the most recent slot the validator voted for */
  fd_hash_t   gossip_hash; /* the most recent hash the validator voted for */
};
typedef struct fd_notar_vtr fd_notar_vtr_t;

#define MAP_NAME              fd_notar_vtr
#define MAP_T                 fd_notar_vtr_t
#define MAP_KEY               pubkey
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_notar_bid maps slots to block_ids.  This is needed when
   processing vote transactions, because vote transactions only contain
   the block_id of the last vote slot (and do not specify what block_ids
   previous vote slots correspond to.  Agave assumes if the hash of the
   last vote slot matches, all the previous slots in the tower match as
   well.  Agave uses bank hashes instead of block_ids (the relevant code
   predates block_ids) and maps slots to bank hashes during replay.

   An important note is that block_ids for slots can change in case of
   "duplicate confirmation".  If notar observes a duplicate confirmation
   for a different block_id than the one it has for a given slot, it
   updates the block_id for that slot to the duplicate confirmed one. */

struct fd_notar_bid {
   ulong     slot;
   fd_hash_t block_id;
};
typedef struct fd_notar_bid fd_notar_bid_t;

#define MAP_NAME    fd_notar_bid
#define MAP_T       fd_notar_bid_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_notar_out is an out queue of block_ids that have achieved a new
   confirmation status.  The same block_id can appear multiple times in
   this queue.  The same block_id can also achieve multiple confirmation
   levels at once. */

struct fd_notar_out {
   ulong     slot;
   fd_hash_t block_id;
   fd_hash_t bank_hash;
   int       pro_conf; /* set if block just achieved pro_conf (not set if it was already pro_conf) */
   int       dup_conf; /* set if block just achieved dup_conf (not set if it was already dup_conf) */
   int       opt_conf; /* set if block just achieved opt_conf (not set if it was already opt_conf) */
};
typedef struct fd_notar_out fd_notar_out_t;

#define DEQUE_NAME fd_notar_out
#define DEQUE_T    fd_notar_out_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct __attribute__((aligned(128UL))) fd_notar {
  ulong            root;  /* current root slot */
  ulong            stake; /* total stake in the current epoch */
  fd_notar_bid_t * bid;   /* slot to block_id map. first lg(blk_max) bits of slot are a mask for equivocations */
  fd_notar_blk_t * blk;   /* block map */
  fd_notar_vtr_t * vtr;   /* voter map */
  fd_notar_out_t * out;   /* out queue of confirmations */
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
  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max      ) ) + 1;
  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_notar_t),  sizeof(fd_notar_t)                   ),
      fd_notar_bid_align(), fd_notar_bid_footprint( lg_blk_max ) ),
      fd_notar_blk_align(), fd_notar_blk_footprint( lg_blk_max ) ),
      fd_notar_vtr_align(), fd_notar_vtr_footprint( lg_vtr_max ) ),
      fd_notar_out_align(), fd_notar_out_footprint( blk_max    ) ),
    fd_notar_align() );
}

/* fd_notar_new formats an unused memory region for use as a notar.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_notar_new( void * mem,
              ulong  blk_max );

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

/* fd_notar_vote updates notar with a vote transaction.  pubkey is the
   vote account address associated with the vote transaction, stake is
   the amount of stake associated with the vote account in the current
   epoch, tower is the parsed tower from the vote transaction, bank_hash
   is the voter's proposed bank hash for the last slot in the tower, and
   block_id is the voter's proposed block id for the same. */

void
fd_notar_vote( fd_notar_t        * notar,
               fd_pubkey_t const * pubkey,
               fd_tower_t  const * tower,
               fd_hash_t   const * bank_hash,
               fd_hash_t   const * block_id );

/* fd_notar_publish publishes root as the new notar root slot, removing
   all blocks with slot numbers < the old notar root slot.  Some slots
   on minority forks that were pruned but > than the new root may remain
   but they will eventually be pruned as well as the root advances. */

void
fd_notar_publish( fd_notar_t * notar,
                  ulong        root );

#endif /* HEADER_fd_src_choreo_notar_fd_notar_h */
