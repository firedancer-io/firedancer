#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h

#include "fd_sysvar_cache.h"
#include "../fd_system_ids_pp.h"

#define FD_SYSVAR_CACHE_MAGIC (0x1aa5ecb2a49b600aUL) /* random number */

#define FD_SYSVAR_SIMPLE_ITER( SIMPLE_SYSVAR ) \
SIMPLE_SYSVAR( clock,             CLOCK,             sol_sysvar_clock             ) \
SIMPLE_SYSVAR( epoch_rewards,     EPOCH_REWARDS,     sysvar_epoch_rewards         ) \
SIMPLE_SYSVAR( epoch_schedule,    EPOCH_SCHEDULE,    epoch_schedule               ) \
SIMPLE_SYSVAR( last_restart_slot, LAST_RESTART_SLOT, sol_sysvar_last_restart_slot ) \
SIMPLE_SYSVAR( rent,              RENT,              rent                         )

/* Declare a perfect hash table mapping sysvar IDs to sysvar cache slots
   Hashes bytes [8,12) of each sysvar address. */

struct sysvar_lut {
  fd_pubkey_t key;
  uchar       desc_idx;
};
typedef struct sysvar_lut sysvar_tbl_t;

#define MAP_PERFECT_NAME        sysvar_map
#define MAP_PERFECT_LG_TBL_SZ   4
#define MAP_PERFECT_T           sysvar_tbl_t
#define MAP_PERFECT_HASH_C      212885
#define MAP_PERFECT_KEY         key.uc
#define MAP_PERFECT_KEY_T       fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY    (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))
#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>28)&0xFU)
#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,  \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31 ) \
  PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr + 8UL ) )
#define MAP_SYSVAR( id, desc ) ( id ), ( desc )
#define MAP_PERFECT_0  MAP_SYSVAR( SYSVAR_CLOCK_ID,          FD_SYSVAR_clock_IDX               )
#define MAP_PERFECT_1  MAP_SYSVAR( SYSVAR_SLOT_HIST_ID,      FD_SYSVAR_slot_history_IDX        )
#define MAP_PERFECT_2  MAP_SYSVAR( SYSVAR_SLOT_HASHES_ID,    FD_SYSVAR_slot_hashes_IDX         )
#define MAP_PERFECT_3  MAP_SYSVAR( SYSVAR_EPOCH_SCHED_ID,    FD_SYSVAR_epoch_schedule_IDX      )
#define MAP_PERFECT_4  MAP_SYSVAR( SYSVAR_RECENT_BLKHASH_ID, FD_SYSVAR_recent_hashes_IDX       )
#define MAP_PERFECT_5  MAP_SYSVAR( SYSVAR_RENT_ID,           FD_SYSVAR_rent_IDX                )
#define MAP_PERFECT_6  MAP_SYSVAR( SYSVAR_EPOCH_REWARDS_ID,  FD_SYSVAR_epoch_rewards_IDX       )
#define MAP_PERFECT_7  MAP_SYSVAR( SYSVAR_STAKE_HIST_ID,     FD_SYSVAR_stake_history_IDX       )
#define MAP_PERFECT_8  MAP_SYSVAR( SYSVAR_LAST_RESTART_ID,   FD_SYSVAR_last_restart_slot_IDX   )
#include "../../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

/* Declare a table giving the buffer offsets and sizes of sysvars in the
   cache. */

struct fd_sysvar_pos {
  /* Offsets relative to start of sysvar cache */
  uint data_off;  /* Raw data offset */
  uint obj_off;   /* Typed object offset */
  uint data_max;
  uint obj_max;

  char const * name;

  int    (* decode_footprint)( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
  void * (* decode)( void * mem, fd_bincode_decode_ctx_t * ctx );
  int    (* encode)( void const * self, fd_bincode_encode_ctx_t * ctx );
};
typedef struct fd_sysvar_pos fd_sysvar_pos_t;

#define TYPES_CALLBACKS( name, suf )                                   \
  .decode_footprint = fd_##name##_decode_footprint,                    \
  .decode           = fd_##name##_decode##suf, \
  .encode           = (__typeof__(((fd_sysvar_pos_t *)NULL)->encode))(ulong)fd_##name##_encode##suf

static fd_sysvar_pos_t const fd_sysvar_pos_tbl[ FD_SYSVAR_CACHE_ENTRY_CNT ] = {
  [FD_SYSVAR_clock_IDX] =
    { .name="clock",
      .data_off=offsetof(fd_sysvar_cache_t, bin_clock            ), .data_max=FD_SYSVAR_CLOCK_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_clock            ), .obj_max =FD_SYSVAR_CLOCK_FOOTPRINT,
      TYPES_CALLBACKS( sol_sysvar_clock, ) },
  [FD_SYSVAR_epoch_rewards_IDX] =
    { .name="epoch rewards",
      .data_off=offsetof(fd_sysvar_cache_t, bin_epoch_rewards    ), .data_max=FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_epoch_rewards    ), .obj_max =FD_SYSVAR_EPOCH_REWARDS_FOOTPRINT,
      TYPES_CALLBACKS( sysvar_epoch_rewards, ) },
  [FD_SYSVAR_epoch_schedule_IDX] =
    { .name="epoch schedule",
      .data_off=offsetof(fd_sysvar_cache_t, bin_epoch_schedule   ), .data_max=FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_epoch_schedule   ), .obj_max =FD_SYSVAR_EPOCH_SCHEDULE_FOOTPRINT,
      TYPES_CALLBACKS( epoch_schedule, ) },
  [FD_SYSVAR_last_restart_slot_IDX] =
    { .name="last restart slot",
      .data_off=offsetof(fd_sysvar_cache_t, bin_last_restart_slot), .data_max=FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_last_restart_slot), .obj_max =FD_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT,
      TYPES_CALLBACKS( sol_sysvar_last_restart_slot, ) },
  [FD_SYSVAR_recent_hashes_IDX] =
    { .name="recent blockhashes",
      .data_off=offsetof(fd_sysvar_cache_t, bin_recent_hashes    ), .data_max=FD_SYSVAR_RECENT_HASHES_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_recent_hashes    ), .obj_max =FD_SYSVAR_RECENT_HASHES_FOOTPRINT,
      TYPES_CALLBACKS( recent_block_hashes, _global ) },
  [FD_SYSVAR_rent_IDX] =
    { .name="rent",
      .data_off=offsetof(fd_sysvar_cache_t, bin_rent             ), .data_max=FD_SYSVAR_RENT_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_rent             ), .obj_max =FD_SYSVAR_RENT_FOOTPRINT,
      TYPES_CALLBACKS( rent, ) },
  [FD_SYSVAR_slot_hashes_IDX] =
    { .name="slot hashes",
      .data_off=offsetof(fd_sysvar_cache_t, bin_slot_hashes      ), .data_max=FD_SYSVAR_SLOT_HASHES_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_slot_hashes      ), .obj_max =FD_SYSVAR_SLOT_HASHES_FOOTPRINT,
      TYPES_CALLBACKS( slot_hashes, _global ) },
  [FD_SYSVAR_slot_history_IDX] =
    { .name="slot history",
      .data_off=offsetof(fd_sysvar_cache_t, bin_slot_history     ), .data_max=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_slot_history     ), .obj_max =FD_SYSVAR_SLOT_HISTORY_FOOTPRINT,
      TYPES_CALLBACKS( slot_history, _global ) },
  [FD_SYSVAR_stake_history_IDX] =
    { .name="stake history",
      .data_off=offsetof(fd_sysvar_cache_t, bin_stake_history    ), .data_max=FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ,
      .obj_off =offsetof(fd_sysvar_cache_t, obj_stake_history    ), .obj_max =FD_SYSVAR_STAKE_HISTORY_FOOTPRINT,
      TYPES_CALLBACKS( stake_history, ) },
};

#undef TYPES_CALLBACKS

static fd_pubkey_t const fd_sysvar_key_tbl[ FD_SYSVAR_CACHE_ENTRY_CNT ] = {
  [ FD_SYSVAR_clock_IDX             ] = {{ SYSVAR_CLOCK_ID          }},
  [ FD_SYSVAR_epoch_rewards_IDX     ] = {{ SYSVAR_EPOCH_REWARDS_ID  }},
  [ FD_SYSVAR_epoch_schedule_IDX    ] = {{ SYSVAR_EPOCH_SCHED_ID    }},
  [ FD_SYSVAR_last_restart_slot_IDX ] = {{ SYSVAR_LAST_RESTART_ID   }},
  [ FD_SYSVAR_recent_hashes_IDX     ] = {{ SYSVAR_RECENT_BLKHASH_ID }},
  [ FD_SYSVAR_rent_IDX              ] = {{ SYSVAR_RENT_ID           }},
  [ FD_SYSVAR_slot_hashes_IDX       ] = {{ SYSVAR_SLOT_HASHES_ID    }},
  [ FD_SYSVAR_slot_history_IDX      ] = {{ SYSVAR_SLOT_HIST_ID      }},
  [ FD_SYSVAR_stake_history_IDX     ] = {{ SYSVAR_STAKE_HIST_ID     }},
};

/* fd_sysvar_obj_restore restores a typed representation of a sysvar
   from serialized data.  This is called internally whenever sysvar
   serialized data is updated directly.  DO NOT USE DIRECTLY. */

int
fd_sysvar_obj_restore( fd_sysvar_cache_t *     cache,
                       fd_sysvar_desc_t *      desc,
                       fd_sysvar_pos_t const * pos );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h */
