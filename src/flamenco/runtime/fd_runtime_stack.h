#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "../types/fd_types_custom.h"
#include "../leaders/fd_leaders_base.h"
#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_const.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../rewards/fd_rewards_base.h"   /* MAX_PARTITIONS_PER_EPOCH */

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L27 */
struct fd_calculated_stake_points {
  fd_w_u128_t points;
  ulong       new_credits_observed;
  uchar       force_credits_update_with_skipped_reward;
};
typedef struct fd_calculated_stake_points fd_calculated_stake_points_t;

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L24 */
struct fd_calculated_stake_rewards {
  ulong staker_rewards;
  ulong voter_rewards;
  ulong new_credits_observed;
  uchar success;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;

/* fd_vote_ele and fd_vote_ele_map are used to temporarily cache
   computed fields for vote accounts during epoch boundary stake
   and rewards calculations. */

struct fd_vote_rewards {
  fd_pubkey_t pubkey;
  ulong       vote_rewards;
  uint        next;
  uchar       commission;
};
typedef struct fd_vote_rewards fd_vote_rewards_t;

#define MAP_NAME               fd_vote_rewards_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_rewards_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct fd_stake_accum {
  fd_pubkey_t pubkey;
  ulong       stake;
  uint        next;
};
typedef struct fd_stake_accum fd_stake_accum_t;

#define MAP_NAME               fd_stake_accum_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_accum_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* fd_runtime_stack is split into two pieces, following the
   fd_txncache pattern:

     (1) fd_runtime_stack_shmem_t -- a shared-memory region created
         once by the topology orchestrator.  Contains the variable-
         sized storage used for epoch-boundary reward/stake
         computations (the vote_rewards_map, stake_accum_map, and all
         the scratch arrays).  Safe to map at any virtual address and
         contains no absolute pointers into itself.

     (2) fd_runtime_stack_t -- a per-tile local join handle allocated
         from each tile's own scratch region.  It holds pointers that
         resolve into the shared region using the current tile's
         mapping.  The large replay-tile-private staging buffers
         (bpf_migration, epoch_weights) are pointed to via pointers
         that are only populated when fd_runtime_stack_new is invoked
         with include_replay_private=1.  Exec tiles, which never need
         these buffers, pass 0 and keep the pointers NULL -- this
         avoids a ~20 MiB-per-tile memory cost for bpf_migration.

   Lifecycle:
     fd_runtime_stack_shmem_{align,footprint,new,join}
         are used by the topology to allocate and initialize the
         shared region.  The orchestrator process calls
         fd_runtime_stack_shmem_new(shmem, ...) once.

     fd_runtime_stack_{align,footprint,new,join}
         are used by each tile.  The tile carves
         fd_runtime_stack_footprint() bytes out of its own scratch,
         calls fd_runtime_stack_new(ljoin, shmem_join) to format it
         (filling in tile-local pointers into the shared region), and
         then fd_runtime_stack_join(ljoin) to obtain the handle used
         by the rest of the runtime code. */

struct fd_runtime_stack_shmem_private;
typedef struct fd_runtime_stack_shmem_private fd_runtime_stack_shmem_t;

/* fd_runtime_stack_bpf_migration is replay-tile-private staging for
   the core BPF migrations that run at epoch boundaries.  Two 10 MiB
   buffers dominate the footprint, so this is held behind a pointer
   in fd_runtime_stack_t and only allocated when the tile asks for
   it. */

struct fd_runtime_stack_bpf_migration {
  fd_tmp_account_t source;
  fd_tmp_account_t program_account;
  fd_tmp_account_t new_target_program;
  fd_tmp_account_t new_target_program_data;
  fd_tmp_account_t empty;

  /* Staging memory for ELF validation during BPF program migrations. */
  struct {
    uchar rodata        [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_SBPF_PROG_RODATA_ALIGN)));
    uchar sbpf_footprint[ FD_SBPF_PROGRAM_FOOTPRINT ] __attribute__((aligned(alignof(fd_sbpf_program_t))));
    uchar programdata   [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  } progcache_validate;
};
typedef struct fd_runtime_stack_bpf_migration fd_runtime_stack_bpf_migration_t;

/* fd_runtime_stack_epoch_weights is replay-tile-private staging for
   the leader schedule stake weight computation.  Smaller than
   bpf_migration but still per-tile scratch that exec tiles never
   need. */

struct fd_runtime_stack_epoch_weights {
  fd_vote_stake_weight_t stake_weights[ MAX_COMPRESSED_STAKE_WEIGHTS ];
  ulong                  stake_weights_cnt;

  fd_stake_weight_t      id_weights[ MAX_SHRED_DESTS ];
  ulong                  id_weights_cnt;
  ulong                  id_weights_excluded;

  fd_vote_stake_weight_t next_stake_weights[ MAX_COMPRESSED_STAKE_WEIGHTS ];
  ulong                  next_stake_weights_cnt;

  fd_stake_weight_t      next_id_weights[ MAX_SHRED_DESTS ];
  ulong                  next_id_weights_cnt;
  ulong                  next_id_weights_excluded;
};
typedef struct fd_runtime_stack_epoch_weights fd_runtime_stack_epoch_weights_t;

/* fd_runtime_stack_t is the per-tile local join handle.  Every field
   whose type is a pointer resolves into shared memory via the
   per-tile mapping.  bpf_migration and epoch_weights are NULL for
   tiles that did not request the replay-private extras; replay tiles
   that pass include_replay_private=1 to fd_runtime_stack_new get
   these populated with pointers into the trailing region of their
   own ljoin. */

struct fd_runtime_stack {

  fd_runtime_stack_shmem_t * shmem;       /* backing shared region; capacity
                                             scalars live in shmem and are
                                             accessed via shmem->... */

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ts_est_ele_t * staked_ts;
  } clock_ts;

  struct {
    fd_calculated_stake_points_t *  stake_points_result;

    fd_calculated_stake_rewards_t * stake_rewards_result;

    fd_stake_accum_t *     stake_accum;
    fd_stake_accum_map_t * stake_accum_map;

    fd_vote_rewards_t *     vote_ele;
    fd_vote_rewards_map_t * vote_map;

    ulong       total_rewards;
    ulong       distributed_rewards;
    fd_w_u128_t total_points;
    /* stake_rewards_cnt lives in the shared shmem header
       (runtime_stack->shmem->stake_rewards_cnt) because exec tiles
       atomically accumulate into it during
       calculate_stake_vote_rewards_partitioned. */

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t * stake_weights;
    fd_stake_weight_t *      id_weights;

  } stakes;

  /* Replay-tile-private staging.  NULL unless the tile passed
     include_replay_private=1 to fd_runtime_stack_new. */
  fd_runtime_stack_bpf_migration_t * bpf_migration;
  fd_runtime_stack_epoch_weights_t * epoch_weights;

  /* Per-tile private scratch for setup_stake_partitions_partitioned.
     Each worker pushes inserts onto a per-partition local LIFO chain
     during the main loop, then CAS-splices each chain onto the
     shared fork_info.partition_idxs_head[] at the end of the
     worker.  This trades N per-insert CAS-spin retries for ~
     partition_cnt (≤ MAX_PARTITIONS_PER_EPOCH) per-worker splices.
     local_heads[p] is the top of the local chain for partition p
     (UINT_MAX if empty); local_tails[p] is the bottom element, whose
     .next is overwritten at splice time. */
  struct {
    uint * local_heads;  /* [MAX_PARTITIONS_PER_EPOCH] */
    uint * local_tails;  /* [MAX_PARTITIONS_PER_EPOCH] */
  } setup_stake_scratch;

  /* Per-tile local scratch for fd_refresh_delegations_partitioned.
     Each participating tile owns one of shmem->max_refresh_tiles
     slots (indexed by refresh_slot_idx passed to
     fd_runtime_stack_new).  Workers populate their local_stake_accum
     and local_stake_accum_map via dedup-only inserts; the replay
     tile's merge pass reads all slots to fold into the shared
     stake_accum_map.  local_stake_accum_cnt is a per-slot counter
     that lives in shmem (so replay can read the final count written
     by the exec tile). */
  struct {
    fd_stake_accum_t *               local_stake_accum;       /* pool -> shmem slot */
    fd_stake_accum_map_t *           local_stake_accum_map;   /* joined chain map -> shmem slot */
    ulong *                          local_stake_accum_cnt;   /* ptr to ulong slot in shmem */
    struct fd_refresh_tile_state *   local_state;             /* ptr to this tile's resume state in shmem */
    ulong                            slot_idx;                /* which slot this tile owns */
  } refresh;
};
typedef struct fd_runtime_stack fd_runtime_stack_t;

/* Shared region API.  The footprint depends on the capacity triple
   (max_vote_accounts, expected_vote_accounts,
   expected_stake_accounts) because the region holds several
   capacity-sized scratch arrays. */

FD_FN_CONST static inline ulong
fd_runtime_stack_shmem_align( void ) {
  return 128UL;
}

/* Per-tile local join API.  The local region is small (just an
   fd_runtime_stack_t with its inline staging buffers) and lives in
   the tile's own scratch, not in a shared workspace.  Definitions for
   fd_runtime_stack_shmem_* and fd_runtime_stack_* are inlined below
   this declaration block. */

/* include_replay_private tells fd_runtime_stack_footprint and
   fd_runtime_stack_new whether to carve out space in ljoin for the
   replay-tile-private bpf_migration + epoch_weights staging.  Pass 1
   from the replay tile (which drives BPF migrations and leader
   schedule updates), 0 from every other tile (execrp etc.). */

FD_FN_CONST static inline ulong
fd_runtime_stack_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
fd_runtime_stack_footprint( int include_replay_private ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t) );
  if( include_replay_private ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_bpf_migration_t), sizeof(fd_runtime_stack_bpf_migration_t) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_epoch_weights_t), sizeof(fd_runtime_stack_epoch_weights_t) );
  }
  /* setup_stake_partitions per-tile scratch (heads + tails arrays). */
  l = FD_LAYOUT_APPEND( l, alignof(uint), MAX_PARTITIONS_PER_EPOCH * sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint), MAX_PARTITIONS_PER_EPOCH * sizeof(uint) );
  return FD_LAYOUT_FINI( l, fd_runtime_stack_align() );
}

/* fd_runtime_stack_shmem_private is the header stored at the start of
   the shared region.  It is followed by the variable-sized storage
   arrays and map backing regions laid out according to
   fd_runtime_stack_shmem_footprint.  All accesses through this header
   use offsets relative to its own address, so the struct is safe to
   map at any virtual address. */

struct fd_runtime_stack_shmem_private {
  ulong magic;
  ulong max_vote_accounts;
  ulong expected_vote_accounts;
  ulong expected_stake_accounts;

  /* stake_rewards_cnt must live in shmem so that atomic adds from
     execrp tiles running calculate_stake_vote_rewards_partitioned
     are visible to the replay tile.  If this were a scalar in the
     per-tile fd_runtime_stack_t handle, each tile would be writing
     into its own private copy and replay would see 0. */
  ulong stake_rewards_cnt;

  /* Number of per-tile refresh_vote_accounts stash slots stored in
     this shmem.  Fixed at shmem_new time based on exec_cnt.  Each
     slot contains a local stake_accum pool + map + counter used by
     fd_refresh_delegations_partitioned for per-worker dedup. */
  ulong max_refresh_tiles;
};

#define FD_RUNTIME_STACK_SHMEM_MAGIC (0xf17edacec06ecdafUL) /* random */

/* fd_runtime_stack_refresh_local_cap: the per-tile capacity of the
   local stake_accum dedup stash used by
   fd_refresh_delegations_partitioned.  Sized against
   expected_vote_accounts -- roughly 10x the live vote-account count,
   which is plenty for a single worker's slice of delegations.  If a
   worker does exceed this (hostile vote-account flood), the worker
   publishes a "flush" reply, replay drains the worker's stash into
   the shared map, and sends the worker a "resume" message; the
   worker picks up iteration where it left off.  See
   fd_refresh_delegations_partitioned for the protocol. */

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_local_cap( ulong expected_vote_accounts ) {
  return expected_vote_accounts;
}

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_chain_cnt( ulong expected_vote_accounts ) {
  return fd_stake_accum_map_chain_cnt_est( expected_vote_accounts );
}

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_pool_sz( ulong expected_vote_accounts ) {
  return sizeof(fd_stake_accum_t) * fd_runtime_stack_refresh_local_cap( expected_vote_accounts );
}

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_map_sz( ulong expected_vote_accounts ) {
  return fd_stake_accum_map_footprint( fd_runtime_stack_refresh_chain_cnt( expected_vote_accounts ) );
}

/* Per-tile scratch for fd_refresh_delegations_partitioned.  Persists
   across flush/resume round-trips so the exec tile can pick up
   iteration where it left off.  `in_progress` is set by the exec
   tile when it saves state before publishing a flush reply; replay
   clears it after merging + before sending a "continue" (resume)
   message. */

struct fd_refresh_tile_state {
  ulong in_progress;        /* 0 = fresh start expected, 1 = resume state valid */
  ulong saved_iter_cur;     /* fd_stake_delegations_pool_iter resume state */
  ulong saved_iter_hi;
  ulong accum_total_stake;
  ulong accum_total_activating;
  ulong accum_total_deactivating;
};
typedef struct fd_refresh_tile_state fd_refresh_tile_state_t;

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_state_sz( void ) {
  return sizeof(fd_refresh_tile_state_t);
}

FD_FN_PURE static inline ulong
fd_runtime_stack_refresh_per_tile_sz( ulong expected_vote_accounts ) {
  /* Per-tile: pool + map backing + one ulong counter (rounded to
     alignment) + per-tile resume state.  Approximation for logging
     -- actual layout uses separate aligned regions. */
  return fd_runtime_stack_refresh_pool_sz( expected_vote_accounts )
       + fd_runtime_stack_refresh_map_sz( expected_vote_accounts )
       + sizeof(ulong)
       + fd_runtime_stack_refresh_state_sz();
}

FD_FN_PURE static inline ulong
fd_runtime_stack_shmem_footprint( ulong max_vote_accounts,
                                  ulong expected_vote_accounts,
                                  ulong expected_stake_accounts,
                                  ulong max_refresh_tiles ) {
  ulong chain_cnt         = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );
  ulong refresh_chain_cnt = fd_runtime_stack_refresh_chain_cnt( expected_vote_accounts );
  ulong refresh_pool_cap  = fd_runtime_stack_refresh_local_cap( expected_vote_accounts );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_shmem_t),     sizeof(fd_runtime_stack_shmem_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ts_est_ele_t),                 sizeof(ts_est_ele_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vote_stake_weight_t),       sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),            sizeof(fd_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_vote_rewards_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_vote_rewards_map_align(),           fd_vote_rewards_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_stake_accum_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_stake_accum_map_align(),            fd_stake_accum_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_calculated_stake_points_t), sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_calculated_stake_rewards_t),sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  /* Per-tile refresh stash (sized at expected_vote_accounts so it
     stays small; flush-and-resume handles overflow gracefully). */
  l = FD_LAYOUT_APPEND( l, 128UL,                                 max_refresh_tiles * sizeof(fd_stake_accum_t) * refresh_pool_cap );
  l = FD_LAYOUT_APPEND( l, fd_stake_accum_map_align(),            max_refresh_tiles * fd_stake_accum_map_footprint( refresh_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                        max_refresh_tiles * sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_refresh_tile_state_t),      max_refresh_tiles * sizeof(fd_refresh_tile_state_t) );
  return FD_LAYOUT_FINI( l, fd_runtime_stack_shmem_align() );
}

/* Lays out the shared region and initializes the map headers.  No
   absolute pointers are stored in the region; tile-local pointers are
   recomputed by fd_runtime_stack_new at attach time. */

static inline void *
fd_runtime_stack_shmem_new( void * shmem,
                            ulong  max_vote_accounts,
                            ulong  expected_vote_accounts,
                            ulong  expected_stake_accounts,
                            ulong  max_refresh_tiles,
                            ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  ulong chain_cnt         = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );
  ulong refresh_chain_cnt = fd_runtime_stack_refresh_chain_cnt( expected_vote_accounts );
  ulong refresh_pool_cap  = fd_runtime_stack_refresh_local_cap( expected_vote_accounts );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_runtime_stack_shmem_t *      s                    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_shmem_t),      sizeof(fd_runtime_stack_shmem_t) );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(ts_est_ele_t),                  sizeof(ts_est_ele_t) * max_vote_accounts );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( chain_cnt ) );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_stake_accum_t) * max_vote_accounts );
  void *                          stake_accum_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( chain_cnt ) );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_points_t),  sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_rewards_t), sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  max_refresh_tiles * sizeof(fd_stake_accum_t) * refresh_pool_cap );
  void *                          refresh_maps_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             max_refresh_tiles * fd_stake_accum_map_footprint( refresh_chain_cnt ) );
  ulong *                         refresh_cnts_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                         max_refresh_tiles * sizeof(ulong) );
  fd_refresh_tile_state_t *       refresh_states_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_refresh_tile_state_t),       max_refresh_tiles * sizeof(fd_refresh_tile_state_t) );
  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_shmem_align() )!=(ulong)shmem + fd_runtime_stack_shmem_footprint( max_vote_accounts, expected_vote_accounts, expected_stake_accounts, max_refresh_tiles ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_shmem_new: bad layout" ));
    return NULL;
  }

  s->magic                   = FD_RUNTIME_STACK_SHMEM_MAGIC;
  s->max_vote_accounts       = max_vote_accounts;
  s->expected_vote_accounts  = expected_vote_accounts;
  s->expected_stake_accounts = expected_stake_accounts;
  s->max_refresh_tiles       = max_refresh_tiles;

  if( FD_UNLIKELY( !fd_stake_accum_map_new( stake_accum_map_mem, chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_shmem_new: bad map" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_vote_rewards_map_new( vote_map_mem, chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_shmem_new: bad map" ));
    return NULL;
  }

  /* Initialize each per-tile local stake_accum_map backing. */
  ulong refresh_map_stride = fd_stake_accum_map_footprint( refresh_chain_cnt );
  for( ulong i=0UL; i<max_refresh_tiles; i++ ) {
    void * tile_map_mem = (uchar *)refresh_maps_mem + i*refresh_map_stride;
    if( FD_UNLIKELY( !fd_stake_accum_map_new( tile_map_mem, refresh_chain_cnt, seed ) ) ) {
      FD_LOG_WARNING(( "fd_runtime_stack_shmem_new: bad per-tile refresh map" ));
      return NULL;
    }
  }

  /* Zero per-tile counters and resume state. */
  for( ulong i=0UL; i<max_refresh_tiles; i++ ) {
    refresh_cnts_mem[ i ] = 0UL;
    memset( &refresh_states_mem[ i ], 0, sizeof(fd_refresh_tile_state_t) );
  }

  /* Log the per-tile + total refresh stash size. */
  ulong per_tile_pool_sz  = fd_runtime_stack_refresh_pool_sz( expected_vote_accounts );
  ulong per_tile_map_sz   = fd_runtime_stack_refresh_map_sz( expected_vote_accounts );
  ulong per_tile_state_sz = fd_runtime_stack_refresh_state_sz();
  FD_LOG_NOTICE(( "fd_runtime_stack refresh stash: max_refresh_tiles=%lu expected_vote_accounts=%lu "
                  "per_tile_pool=%lu B per_tile_map=%lu B per_tile_state=%lu B per_tile_total=%lu B aggregate=%lu B",
                  max_refresh_tiles, expected_vote_accounts,
                  per_tile_pool_sz, per_tile_map_sz, per_tile_state_sz,
                  per_tile_pool_sz + per_tile_map_sz + sizeof(ulong) + per_tile_state_sz,
                  max_refresh_tiles * (per_tile_pool_sz + per_tile_map_sz + sizeof(ulong) + per_tile_state_sz) ));

  return shmem;
}

static inline fd_runtime_stack_shmem_t *
fd_runtime_stack_shmem_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  fd_runtime_stack_shmem_t * s = (fd_runtime_stack_shmem_t *)shmem;
  if( FD_UNLIKELY( s->magic!=FD_RUNTIME_STACK_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_shmem_join: bad magic 0x%lx", s->magic ));
    return NULL;
  }
  return s;
}

/* fd_runtime_stack_new formats the caller-provided tile-local region
   ljoin and attaches it to the shared region shmem.  Writes only to
   ljoin; shmem contents are read but not modified.  Returns ljoin on
   success. */

/* fd_runtime_stack_new attaches a tile-local join to the shared
   region.  refresh_slot_idx is the per-tile slot in shmem reserved
   for that tile's fd_refresh_delegations_partitioned scratch; must
   be < shmem->max_refresh_tiles.  Tiles that never participate in
   the parallel refresh (e.g. standalone tests) can pass 0 provided
   max_refresh_tiles >= 1. */

static inline void *
fd_runtime_stack_new( void *                     ljoin,
                      fd_runtime_stack_shmem_t * shmem,
                      int                        include_replay_private,
                      ulong                      refresh_slot_idx ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_runtime_stack_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( shmem->magic!=FD_RUNTIME_STACK_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad shmem magic" ));
    return NULL;
  }

  ulong max_vote_accounts      = shmem->max_vote_accounts;
  ulong expected_vote_accounts = shmem->expected_vote_accounts;
  ulong expected_stake_accounts= shmem->expected_stake_accounts;
  ulong chain_cnt              = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );

  /* Carve out tile-local replay-private buffers from the trailing
     region of ljoin, if the caller requested them. */
  fd_runtime_stack_t *               runtime_stack = NULL;
  fd_runtime_stack_bpf_migration_t * bpf_migration = NULL;
  fd_runtime_stack_epoch_weights_t * epoch_weights = NULL;
  uint *                             setup_local_heads = NULL;
  uint *                             setup_local_tails = NULL;
  {
    FD_SCRATCH_ALLOC_INIT( ll, ljoin );
    runtime_stack = FD_SCRATCH_ALLOC_APPEND( ll, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t) );
    if( include_replay_private ) {
      bpf_migration = FD_SCRATCH_ALLOC_APPEND( ll, alignof(fd_runtime_stack_bpf_migration_t), sizeof(fd_runtime_stack_bpf_migration_t) );
      epoch_weights = FD_SCRATCH_ALLOC_APPEND( ll, alignof(fd_runtime_stack_epoch_weights_t), sizeof(fd_runtime_stack_epoch_weights_t) );
    }
    setup_local_heads = FD_SCRATCH_ALLOC_APPEND( ll, alignof(uint), MAX_PARTITIONS_PER_EPOCH * sizeof(uint) );
    setup_local_tails = FD_SCRATCH_ALLOC_APPEND( ll, alignof(uint), MAX_PARTITIONS_PER_EPOCH * sizeof(uint) );
    (void)FD_SCRATCH_ALLOC_FINI( ll, fd_runtime_stack_align() );
  }

  /* Walk the same layout as fd_runtime_stack_shmem_footprint to
     recover per-tile pointers into the shared region. */
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /**/                                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_shmem_t),      sizeof(fd_runtime_stack_shmem_t) );
  ts_est_ele_t *                  staked_ts            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ts_est_ele_t),                  sizeof(ts_est_ele_t) * max_vote_accounts );
  fd_vote_stake_weight_t *        stake_weights        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  fd_stake_weight_t *             id_weights           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  fd_vote_rewards_t *             vote_ele             = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( chain_cnt ) );
  fd_stake_accum_t *              stake_accum          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_stake_accum_t) * max_vote_accounts );
  void *                          stake_accum_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( chain_cnt ) );
  fd_calculated_stake_points_t *  stake_points_result  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_points_t),  sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  fd_calculated_stake_rewards_t * stake_rewards_result = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_rewards_t), sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  /* Per-tile refresh stash region. */
  ulong                           refresh_chain_cnt    = fd_runtime_stack_refresh_chain_cnt( expected_vote_accounts );
  ulong                           refresh_pool_cap     = fd_runtime_stack_refresh_local_cap( expected_vote_accounts );
  ulong                           max_refresh_tiles    = shmem->max_refresh_tiles;
  fd_stake_accum_t *              refresh_pool_base    = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  max_refresh_tiles * sizeof(fd_stake_accum_t) * refresh_pool_cap );
  uchar *                         refresh_maps_base    = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             max_refresh_tiles * fd_stake_accum_map_footprint( refresh_chain_cnt ) );
  ulong *                         refresh_cnts_base    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                         max_refresh_tiles * sizeof(ulong) );
  fd_refresh_tile_state_t *       refresh_states_base  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_refresh_tile_state_t),       max_refresh_tiles * sizeof(fd_refresh_tile_state_t) );

  memset( runtime_stack, 0, sizeof(*runtime_stack) );

  runtime_stack->shmem                       = shmem;
  runtime_stack->clock_ts.staked_ts          = staked_ts;
  runtime_stack->stakes.stake_weights        = stake_weights;
  runtime_stack->stakes.id_weights           = id_weights;
  runtime_stack->stakes.vote_ele             = vote_ele;
  runtime_stack->stakes.stake_accum          = stake_accum;
  runtime_stack->stakes.stake_points_result  = stake_points_result;
  runtime_stack->stakes.stake_rewards_result = stake_rewards_result;
  runtime_stack->bpf_migration              = bpf_migration;
  runtime_stack->epoch_weights              = epoch_weights;
  runtime_stack->setup_stake_scratch.local_heads = setup_local_heads;
  runtime_stack->setup_stake_scratch.local_tails = setup_local_tails;

  runtime_stack->stakes.vote_map        = fd_vote_rewards_map_join( vote_map_mem );
  if( FD_UNLIKELY( !runtime_stack->stakes.vote_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: vote_map join failed" ));
    return NULL;
  }
  runtime_stack->stakes.stake_accum_map = fd_stake_accum_map_join( stake_accum_map_mem );
  if( FD_UNLIKELY( !runtime_stack->stakes.stake_accum_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: stake_accum_map join failed" ));
    return NULL;
  }

  /* Point refresh.local_* at this tile's slot in shmem. */
  if( FD_UNLIKELY( refresh_slot_idx>=max_refresh_tiles ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: refresh_slot_idx %lu >= max_refresh_tiles %lu",
                     refresh_slot_idx, max_refresh_tiles ));
    return NULL;
  }
  runtime_stack->refresh.local_stake_accum     = refresh_pool_base + refresh_slot_idx * refresh_pool_cap;
  runtime_stack->refresh.local_stake_accum_map = fd_stake_accum_map_join( refresh_maps_base + refresh_slot_idx * fd_stake_accum_map_footprint( refresh_chain_cnt ) );
  if( FD_UNLIKELY( !runtime_stack->refresh.local_stake_accum_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: refresh stake_accum_map join failed" ));
    return NULL;
  }
  runtime_stack->refresh.local_stake_accum_cnt = refresh_cnts_base + refresh_slot_idx;
  runtime_stack->refresh.local_state           = refresh_states_base + refresh_slot_idx;
  runtime_stack->refresh.slot_idx              = refresh_slot_idx;

  return ljoin;
}

static inline fd_runtime_stack_t *
fd_runtime_stack_join( void * ljoin ) {
  if( FD_UNLIKELY( !ljoin ) ) return NULL;
  return (fd_runtime_stack_t *)ljoin;
}

/* Cross-tile accessors into the per-tile refresh stash in shmem.
   These let the replay tile read any exec tile's slot during the
   merge pass (and during flush/resume handling) without having to
   ljoin as that tile.  Each function walks the same shmem layout as
   fd_runtime_stack_shmem_new to recover a pointer into the per-tile
   arrays. */

static inline void *
fd_runtime_stack_shmem_refresh_region_base( fd_runtime_stack_shmem_t * shmem,
                                            int                        which ) {
  /* which: 0=pool, 1=maps, 2=cnts, 3=states */
  ulong max_vote_accounts      = shmem->max_vote_accounts;
  ulong expected_vote_accounts = shmem->expected_vote_accounts;
  ulong expected_stake_accounts= shmem->expected_stake_accounts;
  ulong max_refresh_tiles      = shmem->max_refresh_tiles;
  ulong chain_cnt              = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );
  ulong refresh_chain_cnt      = fd_runtime_stack_refresh_chain_cnt( expected_vote_accounts );
  ulong refresh_pool_cap       = fd_runtime_stack_refresh_local_cap( expected_vote_accounts );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_shmem_t),      sizeof(fd_runtime_stack_shmem_t) );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(ts_est_ele_t),                  sizeof(ts_est_ele_t) * max_vote_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( chain_cnt ) );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_stake_accum_t) * max_vote_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( chain_cnt ) );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_points_t),  sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  /**/                            FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_rewards_t), sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  void * pool   =                 FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  max_refresh_tiles * sizeof(fd_stake_accum_t) * refresh_pool_cap );
  void * maps   =                 FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             max_refresh_tiles * fd_stake_accum_map_footprint( refresh_chain_cnt ) );
  void * cnts   =                 FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                         max_refresh_tiles * sizeof(ulong) );
  void * states =                 FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_refresh_tile_state_t),       max_refresh_tiles * sizeof(fd_refresh_tile_state_t) );
  (void)FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_shmem_align() );
  switch( which ) {
    case 0: return pool;
    case 1: return maps;
    case 2: return cnts;
    case 3: return states;
    default: return NULL;
  }
}

static inline fd_stake_accum_t *
fd_runtime_stack_shmem_refresh_pool( fd_runtime_stack_shmem_t * shmem,
                                     ulong                      slot_idx ) {
  ulong refresh_pool_cap = fd_runtime_stack_refresh_local_cap( shmem->expected_vote_accounts );
  fd_stake_accum_t * base = (fd_stake_accum_t *)fd_runtime_stack_shmem_refresh_region_base( shmem, 0 );
  return base + slot_idx * refresh_pool_cap;
}

static inline fd_stake_accum_map_t *
fd_runtime_stack_shmem_refresh_map_join( fd_runtime_stack_shmem_t * shmem,
                                         ulong                      slot_idx ) {
  ulong stride = fd_stake_accum_map_footprint( fd_runtime_stack_refresh_chain_cnt( shmem->expected_vote_accounts ) );
  uchar * base = (uchar *)fd_runtime_stack_shmem_refresh_region_base( shmem, 1 );
  return fd_stake_accum_map_join( base + slot_idx * stride );
}

static inline ulong *
fd_runtime_stack_shmem_refresh_cnt( fd_runtime_stack_shmem_t * shmem,
                                    ulong                      slot_idx ) {
  ulong * base = (ulong *)fd_runtime_stack_shmem_refresh_region_base( shmem, 2 );
  return base + slot_idx;
}

static inline fd_refresh_tile_state_t *
fd_runtime_stack_shmem_refresh_state( fd_runtime_stack_shmem_t * shmem,
                                      ulong                      slot_idx ) {
  fd_refresh_tile_state_t * base = (fd_refresh_tile_state_t *)fd_runtime_stack_shmem_refresh_region_base( shmem, 3 );
  return base + slot_idx;
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
