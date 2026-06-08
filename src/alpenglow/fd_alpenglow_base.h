#ifndef HEADER_fd_src_alpenglow_fd_alpenglow_base_h
#define HEADER_fd_src_alpenglow_fd_alpenglow_base_h

/* fd_alpenglow_base.h is the common base for the Firedancer C port of the
   Alpenglow consensus protocol.  The port mirrors the Rust reference
   (vendored at repo-root alpenglow/) module-for-module:

     alpenglow/src/types.rs              -> this file (Slot/Stake/ValidatorIndex/BlockId)
     alpenglow/src/consensus.rs (consts) -> this file (DELTA_*, *_QUORUM_THRESHOLD)
     alpenglow/src/crypto/aggsig.rs      -> crypto/fd_aggsig.{h,c}
     alpenglow/src/consensus/vote.rs     -> consensus/fd_vote.{h,c}
     alpenglow/src/consensus/cert.rs     -> consensus/fd_cert.{h,c}
     alpenglow/src/consensus/epoch_info.rs -> consensus/fd_epoch_info.{h,c}
     alpenglow/src/consensus/votor.rs    -> consensus/fd_votor.{h,c}
     alpenglow/src/consensus/pool.rs     -> consensus/fd_pool.{h,c}
     alpenglow/src/consensus/pool/ ...   -> consensus/pool/ submodules
     alpenglow/src/consensus.rs (coord)  -> driven by the fd_alpenglow_tile.c tile

   Per the project conventions, the core consensus data structures are
   built directly on the lowest-level util generics (fd_pool, fd_map_chain,
   fd_treap, fd_deque, fd_set) rather than on the choreo module-level
   primitives (fd_tower, fd_ghost, fd_votes).

   In the Rust reference Slot, Stake and ValidatorIndex are #[repr(transparent)]
   u64 newtypes.  In C we represent them as plain ulong and document intent at
   the use site, exactly as the rest of Firedancer does for slot numbers. */

/* Use the lightweight flamenco base (fd_hash_t / fd_pubkey_t + util) rather
   than the full fd_flamenco.h umbrella: the latter transitively pulls in the
   vote-program codec header which defines its own (unrelated) fd_vote_t,
   colliding with our consensus/fd_vote.h.  The consensus core needs only the
   hash/pubkey types and the util generics. */

#include "../flamenco/fd_flamenco_base.h" /* fd_hash_t, fd_pubkey_t, util */

/* SLOTS_PER_WINDOW is the number of consecutive slots a single leader owns
   (alpenglow/src/types/slot.rs).  SLOTS_PER_EPOCH is the number of slots in
   an epoch. */

#define FD_ALPENGLOW_SLOTS_PER_WINDOW (4UL)
#define FD_ALPENGLOW_SLOTS_PER_EPOCH  (18000UL)

/* Timing constants from alpenglow/src/consensus.rs, expressed in
   nanoseconds (the Rust reference uses std::time::Duration).  In the tile
   these drive deadline checks against fd_log_wallclock()/stem now rather
   than spawned timer tasks. */

#define FD_ALPENGLOW_DELTA_NS             (250000000L)               /* DELTA            = 250 ms */
#define FD_ALPENGLOW_DELTA_BLOCK_NS       (400000000L)               /* DELTA_BLOCK      = 400 ms */
#define FD_ALPENGLOW_DELTA_FIRST_SLICE_NS (10000000L)                /* DELTA_FIRST_SLICE= 10  ms */
#define FD_ALPENGLOW_DELTA_TIMEOUT_NS     (3L*FD_ALPENGLOW_DELTA_NS) /* DELTA_TIMEOUT    = 750 ms */
#define FD_ALPENGLOW_DELTA_STANDSTILL_NS  (10000000000L)             /* DELTA_STANDSTILL = 10  s  */

/* Quorum thresholds as numerator/denominator pairs (alpenglow/src/consensus.rs).
   All thresholds share denominator 5 and are inclusive (Fraction::is_met uses
   stake/total >= numer/denom). */

#define FD_ALPENGLOW_WEAKEST_QUORUM_NUMER (1UL) /* 20% */
#define FD_ALPENGLOW_WEAK_QUORUM_NUMER    (2UL) /* 40% */
#define FD_ALPENGLOW_QUORUM_NUMER         (3UL) /* 60% */
#define FD_ALPENGLOW_STRONG_QUORUM_NUMER  (4UL) /* 80% */
#define FD_ALPENGLOW_QUORUM_DENOM         (5UL)

/* fd_block_id_t mirrors the Rust BlockId = (Slot, BlockHash) (alpenglow/src/lib.rs).
   BlockHash is the 32-byte double-Merkle root of a block; the genesis block
   hash is all-zero (alpenglow/src/crypto/merkle.rs GENESIS_BLOCK_HASH). */

struct fd_block_id {
  ulong     slot;
  fd_hash_t hash;
};
typedef struct fd_block_id fd_block_id_t;

FD_PROTOTYPES_BEGIN

/* fd_alpenglow_fraction_is_met returns 1 iff stake/total >= numer/denom,
   computed with 128-bit cross multiplication to avoid overflow and rounding.
   Mirrors alpenglow/src/types/fraction.rs Fraction::is_met. */

FD_FN_CONST static inline int
fd_alpenglow_fraction_is_met( ulong stake, ulong total, ulong numer, ulong denom ) {
  return (uint128)stake*(uint128)denom >= (uint128)total*(uint128)numer;
}

FD_FN_CONST static inline int
fd_alpenglow_is_weakest_quorum( ulong stake, ulong total ) {
  return fd_alpenglow_fraction_is_met( stake, total, FD_ALPENGLOW_WEAKEST_QUORUM_NUMER, FD_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
fd_alpenglow_is_weak_quorum( ulong stake, ulong total ) {
  return fd_alpenglow_fraction_is_met( stake, total, FD_ALPENGLOW_WEAK_QUORUM_NUMER, FD_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
fd_alpenglow_is_quorum( ulong stake, ulong total ) {
  return fd_alpenglow_fraction_is_met( stake, total, FD_ALPENGLOW_QUORUM_NUMER, FD_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
fd_alpenglow_is_strong_quorum( ulong stake, ulong total ) {
  return fd_alpenglow_fraction_is_met( stake, total, FD_ALPENGLOW_STRONG_QUORUM_NUMER, FD_ALPENGLOW_QUORUM_DENOM );
}

/* Slot window helpers, faithful to alpenglow/src/types/slot.rs. */

/* fd_alpenglow_first_slot_in_window returns the first slot of the leader
   window that slot belongs to. */

FD_FN_CONST static inline ulong
fd_alpenglow_first_slot_in_window( ulong slot ) {
  return ( slot / FD_ALPENGLOW_SLOTS_PER_WINDOW ) * FD_ALPENGLOW_SLOTS_PER_WINDOW;
}

/* fd_alpenglow_last_slot_in_window returns the last slot of the leader
   window that slot belongs to. */

FD_FN_CONST static inline ulong
fd_alpenglow_last_slot_in_window( ulong slot ) {
  return fd_alpenglow_first_slot_in_window( slot ) + FD_ALPENGLOW_SLOTS_PER_WINDOW - 1UL;
}

/* fd_alpenglow_is_start_of_window returns 1 iff slot is the first slot of a
   leader window. */

FD_FN_CONST static inline int
fd_alpenglow_is_start_of_window( ulong slot ) {
  return ( slot % FD_ALPENGLOW_SLOTS_PER_WINDOW )==0UL;
}

/* fd_alpenglow_is_genesis_window returns 1 iff slot is in the genesis (first)
   window. */

FD_FN_CONST static inline int
fd_alpenglow_is_genesis_window( ulong slot ) {
  return slot < FD_ALPENGLOW_SLOTS_PER_WINDOW;
}

/* fd_block_id_eq returns 1 iff a and b refer to the same block. */

FD_FN_PURE static inline int
fd_block_id_eq( fd_block_id_t const * a, fd_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_fd_alpenglow_base_h */
