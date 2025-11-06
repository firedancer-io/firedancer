#ifndef HEADER_fd_src_choreo_notar_fd_notar_h
#define HEADER_fd_src_choreo_notar_fd_notar_h

/* fd_notar ("notarized") processes vote transactions from both TPU and
   gossip and tracks when blocks become confirmed.  There are three key
   confirmation thresholds in Solana:

   - propagation confirmed: a block is propagated if it has received
     votes from at least 1/3 of stake in the cluster.  This threshold is
     important in two contexts:

     1. When becoming leader, we need to check that our "previous"
        leader block _as of_ the parent slot we're building on, has
        propagated.  If it's not propagated, we need to instead
        retransmit our last block that failed to propagate.  "Previous"
        is quoted, because there is a grace period of one leader
        rotation for leader blocks to propagate.

     2. When voting, we need to check our previous leader block _as of_
        the slot we're voting for has propagated (unless we're voting
        for one of our leader blocks).  We cannot vote for slots in
        which our last leader block failed to propagate.

   - duplicate confirmed: a block is duplicate confirmed if it has
     received votes from at least 52% of stake in the cluster.  The
     "duplicate" adjective is a bit of a misnomer, and a more accurate
     technical term is equivocation: two (or more) different blocks for
     the same slot.  This threshold is important for consensus safety,
     because it ensures Solana eventually converges to the same block
     per slot.  Specifically fork choice allows choosing a fork if it is
     duplicate confirmed, even if there is equivocation.

   - optimistically confirmed: a block is optimistically confirmed if it
     has received votes from at least 2/3 of stake in the cluster.  This
     threshold is important for end-users, who rely on the "confirmed"
     commitment status of blocks (queryable via RPC) to determine that
     their transaction has landed on a block that will not rollback.
     This is unimplemented in Firedancer and only relevant for RPC.
     (TODO verify this?)

   Unlike duplicate and optimistic confirmation, propagation is at the
   slot-level rather than block-level.  So two votes for different block
   ids would count towards the same slot.  This mirrors Agave behavior.

   On the similarities and differences between fd_ghost vs fd_notar:

   The reason both fd_ghost and fd_notar exist even though they do
   seemingly similar things (tracking vote stake on blocks) is because
   Solana implements the rules quite differently.

   In fd_ghost, we use the GHOST rule to recursively sum the stake of
   the subtree (a slot and all its descendants).  The LMD rule counts a
   validator's stake to at most one fork.  When the validator switches
   forks, their stake is subtracted from the old fork and added to the
   new fork.  The tree is then traversed as part of fork choice to find
   the best leaf ("head").  ghost bases fork choice purely on replay
   votes, but marks forks valid or invalid with gossip votes.

   In fd_notar, we count votes towards only the block itself, and not
   its ancestors.  Also a validator's stake can be counted towards
   multiple forks at the same time if they vote on a fork then switch to
   a different one, unlike ghost.  notar uses both replay and gossip
   votes when counting stake.

   A note on slots and block ids: vote transactions only contain the
   block_id of the last vote slot (and do not specify what block_ids
   previous vote slots correspond to.  Agave assumes if the hash of the
   last vote slot matches, all the previous slots in the tower match as
   well.  Agave uses bank hashes instead of block_ids (the relevant code
   predates block_ids) and maps slots to bank hashes during replay.

   As a result, there can be multiple block ids for a given slot.  notar
   tracks the block_id for each slot using fd_tower_forks, and also
   "duplicate confirmation".  If notar observes a duplicate confirmation
   for a different block_id than the one it has for a given slot, it
   updates the block_id for that slot to the duplicate confirmed one. */

/* FD_NOTAR_PARANOID:  Define this to non-zero at compile time to turn
   on additional runtime integrity checks. */

#include "../fd_choreo_base.h"
#include "../tower/fd_tower_accts.h"

#ifndef FD_NOTAR_PARANOID
#define FD_NOTAR_PARANOID 1
#endif

#define FD_NOTAR_FLAG_CONFIRMED_PROPAGATED (0)
#define FD_NOTAR_FLAG_CONFIRMED_DUPLICATE  (1)
#define FD_NOTAR_FLAG_CONFIRMED_OPTIMISTIC (2)

#define SET_NAME fd_notar_slot_vtrs
#define SET_MAX  FD_VOTER_MAX
#include "../../util/tmpl/fd_set.c"

struct fd_notar_slot {
  ulong slot;             /* map key, vote slot */
  ulong parent_slot;      /* parent slot */
  ulong prev_leader_slot; /* previous slot in which we were leader */
  ulong stake;            /* amount of stake that has voted for this slot */
  int   is_leader;        /* whether this slot was our own leader slot */
  int   is_propagated;    /* whether this slot has reached 1/3 of stake */

  fd_hash_t block_ids[FD_VOTER_MAX]; /* one block id per voter per slot */
  ulong     block_ids_cnt;           /* count of block ids */

  fd_notar_slot_vtrs_t prev_vtrs[fd_notar_slot_vtrs_word_cnt]; /* who has voted for this slot, prev epoch */
  fd_notar_slot_vtrs_t vtrs     [fd_notar_slot_vtrs_word_cnt]; /* who has voted for this slot, curr epoch */
};
typedef struct fd_notar_slot fd_notar_slot_t;

struct fd_notar_blk {
  fd_hash_t block_id; /* map key */
  uint      hash;     /* reserved for fd_map_dynamic */
  ulong     slot;     /* slot associated with this block */
  ulong     stake;    /* sum of stake that has voted for this block_id */
  int       dup_conf; /* whether this block has reached 52% of stake */
  int       opt_conf; /* whether this block has reached 2/3 of stake */
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

/* TODO map key DOS */

#define MAP_NAME    fd_notar_slot
#define MAP_T       fd_notar_slot_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_notar_vtr {
  fd_pubkey_t addr;         /* map key, vote account address */
  uint        hash;         /* reserved for fd_map_dynamic */
  ulong       prev_stake;   /* amount of stake this voter has in epoch - 1 */
  ulong       stake;        /* amount of stake this voter has in epoch */
  ulong       prev_bit;     /* bit position in fd_notar_slot_vtrs in epoch - 1 (ULONG_MAX if not set) */
  ulong       bit;          /* bit position in fd_notar_slot_vtrs in epoch (ULONG_MAX if not set) */
};
typedef struct fd_notar_vtr fd_notar_vtr_t;

#define MAP_NAME              fd_notar_vtr
#define MAP_T                 fd_notar_vtr_t
#define MAP_KEY               addr
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_notar {
  ulong epoch;    /* highest replayed epoch */
  ulong lo_wmark; /* notar ignores votes < lo_wmark */
  ulong hi_wmark; /* notar ignores votes > hi_wmark */
  ulong slot_max; /* maximum number of slots notar can track */

  fd_notar_slot_t * slot_map; /* tracks who has voted for a given slot */
  fd_notar_blk_t *  blk_map;  /* tracks amount of stake for a given block (keyed by block id) */
  fd_notar_vtr_t *  vtr_map;  /* tracks each voter's stake and prev vote */
};
typedef struct fd_notar fd_notar_t;

/* fd_notar_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a notar.  align
   returns fd_notar_ALIGN.  footprint returns fd_notar_FOOTPRINT. */

FD_FN_CONST static inline ulong
fd_notar_align( void ) {
  return alignof(fd_notar_t);
}

FD_FN_CONST static inline ulong
fd_notar_footprint( ulong slot_max ) {
  int lg_slot_max = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  int lg_blk_max  = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max * FD_VOTER_MAX ) ) + 1;
  int lg_vtr_max  = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_notar_t),   sizeof(fd_notar_t)                     ),
      fd_notar_slot_align(), fd_notar_slot_footprint( lg_slot_max ) ),
      fd_notar_blk_align(),  fd_notar_blk_footprint( lg_blk_max )   ),
      fd_notar_vtr_align(),  fd_notar_vtr_footprint( lg_vtr_max )   ),
    fd_notar_align() );
}

/* fd_notar_new formats an unused memory region for use as a notar.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_notar_new( void * mem,
              ulong  slot_max );

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

/* fd_notar_count_vote counts addr's stake towards the voted slots in
   their tower.  Returns 1 if block_id is duplicate confirmed by this
   vote, otherwise 0 (useful for the downstream tower tile to implement
   duplicate confirmation notifications).  addr is the vote account
   address, stake is the amount of stake associated with the vote
   account in the current epoch, slot is slot being voted for, block_id
   is the voter's proposed block id for this vote slot. */

fd_notar_blk_t *
fd_notar_count_vote( fd_notar_t *        notar,
                     ulong               total_stake,
                     fd_pubkey_t const * addr,
                     ulong               slot,
                     fd_hash_t const *   block_id );

void
fd_notar_advance_epoch( fd_notar_t *       notar,
                        fd_tower_accts_t * accts,
                        ulong              epoch );

/* fd_notar_publish publishes root as the new notar root slot, removing
   all blocks with slot numbers < the old notar root slot.  Some slots
   on minority forks that were pruned but > than the new root may remain
   but they will eventually be pruned as well as the root advances. */

void
fd_notar_advance_wmark( fd_notar_t * notar,
                        ulong        root );

#endif /* HEADER_fd_src_choreo_notar_fd_notar_h */
