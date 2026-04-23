#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include <errno.h>

void *
fd_sysvar_cache_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_sysvar_cache_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_sysvar_cache_t * sysvar_cache = mem;
  sysvar_cache->magic = 0UL;
  memset( sysvar_cache->desc, 0, FD_SYSVAR_CACHE_ENTRY_CNT*sizeof(fd_sysvar_desc_t) );

  FD_COMPILER_MFENCE();
  sysvar_cache->magic = FD_SYSVAR_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return sysvar_cache;
}

fd_sysvar_cache_t *
fd_sysvar_cache_join( void * mem ) {
  /* FIXME This is a good place to ref-count writable joins */
  return (fd_sysvar_cache_t *)fd_sysvar_cache_join_const( mem );
}

fd_sysvar_cache_t const *
fd_sysvar_cache_join_const( void const * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_sysvar_cache_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  fd_sysvar_cache_t const * sysvar_cache = mem;
  if( FD_UNLIKELY( sysvar_cache->magic != FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sysvar_cache;
}

void *
fd_sysvar_cache_leave( fd_sysvar_cache_t * sysvar_cache ) {
  return sysvar_cache;
}

void const *
fd_sysvar_cache_leave_const( fd_sysvar_cache_t const * sysvar_cache ) {
  return sysvar_cache;
}

void *
fd_sysvar_cache_delete( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  fd_sysvar_cache_t * sysvar_cache = mem;
  if( FD_UNLIKELY( sysvar_cache->magic != FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  memset( sysvar_cache, 0, sizeof(fd_sysvar_cache_t) );

  return mem;
}

uchar const *
fd_sysvar_cache_data_query(
    fd_sysvar_cache_t const * sysvar_cache,
    void const *              address, /* 32 bytes */
    ulong *                   psz
) {
  *psz = 0UL;
  fd_pubkey_t const pubkey = FD_LOAD( fd_pubkey_t, address );
  sysvar_tbl_t const * entry = sysvar_map_query( &pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) return NULL; /* address is not a sysvar */
  fd_sysvar_desc_t const * desc = &sysvar_cache->desc[ entry->desc_idx ];
  fd_sysvar_pos_t const *  pos  = &fd_sysvar_pos_tbl [ entry->desc_idx ];
  if( !( desc->flags & FD_SYSVAR_FLAG_VALID ) ) return NULL; /* sysvar data invalid */
  *psz = desc->data_sz;
  return (uchar const *)sysvar_cache + pos->data_off;
}

/* Generate accessors for sysvars that are backed by POD structs. */

#define SIMPLE_SYSVAR_READ( name, name2, typet )                       \
  typet *                                                              \
  fd_sysvar_cache_##name##_read( fd_sysvar_cache_t const * cache,      \
                                 typet *                   out ) {     \
    ulong const idx = FD_SYSVAR_##name##_IDX;                          \
    fd_sysvar_desc_t const * desc = &cache->desc[ idx ];               \
    fd_sysvar_pos_t const *  pos  = &fd_sysvar_pos_tbl[ idx ];         \
    if( FD_UNLIKELY( !( desc->flags & FD_SYSVAR_FLAG_VALID ) ) ) return NULL; \
    if( !pos->obj_max ) memcpy( out, (uchar *)cache+pos->data_off, pos->data_max ); \
    else                memcpy( out, (uchar *)cache+pos->obj_off,  pos->obj_max  ); \
    return out;                                                        \
  }

#define SIMPLE_SYSVAR( name, name2, type ) \
  SIMPLE_SYSVAR_READ( name, name2, fd_##type##_t )
FD_SYSVAR_SIMPLE_ITER( SIMPLE_SYSVAR )
#undef SIMPLE_SYSVAR
#undef SIMPLE_SYSVAR_READ

ulong const *
fd_sysvar_cache_last_restart_slot_read( fd_sysvar_cache_t const * cache ) {
  ulong const idx = FD_SYSVAR_last_restart_slot_IDX;
  fd_sysvar_desc_t const * desc = &cache->desc[ idx ];
  fd_sysvar_pos_t const *  pos  = &fd_sysvar_pos_tbl[ idx ];
  if( FD_UNLIKELY( !( desc->flags & FD_SYSVAR_FLAG_VALID ) ) ) return NULL;
  return fd_type_pun_const( (uchar const *)cache + pos->data_off );
}

int
fd_sysvar_cache_recent_hashes_is_empty( fd_sysvar_cache_t const * sysvar_cache ) {
  fd_sysvar_desc_t const * desc = &sysvar_cache->desc[ FD_SYSVAR_recent_hashes_IDX ];
  if( FD_UNLIKELY( !( desc->flags & FD_SYSVAR_FLAG_VALID ) ) ) return 1;
  FD_TEST( desc->data_sz >= sizeof(ulong) );
  ulong len = FD_LOAD( ulong, sysvar_cache->bin_recent_hashes );
  return len == 0UL;
}

fd_slot_hash_t const *
fd_sysvar_cache_slot_hashes_join_const(
    fd_sysvar_cache_t const * cache
) {
  if( FD_UNLIKELY( !fd_sysvar_cache_slot_hashes_is_valid( cache ) ) ) return NULL;
  fd_slot_hashes_global_t * var = (void *)cache->obj_slot_hashes;
  fd_slot_hash_t * deq = deq_fd_slot_hash_t_join( (uchar *)var+var->hashes_offset );
  /* If the above is_valid check is passed, then join is guaranteed to succeed */
  if( FD_UNLIKELY( !deq ) ) FD_LOG_CRIT(( "slot hashes sysvar corruption detected" ));
  return deq; /* demote to const ptr */
}

void
fd_sysvar_cache_slot_hashes_leave_const(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_slot_hash_t const *    slot_hashes
) {
  (void)sysvar_cache; (void)slot_hashes;
}

fd_slot_history_global_t const *
fd_sysvar_cache_slot_history_join_const(
    fd_sysvar_cache_t const * cache
) {
  if( FD_UNLIKELY( !fd_sysvar_cache_slot_history_is_valid( cache ) ) ) return NULL;
  return (void const *)( cache->obj_slot_history );
}

void
fd_sysvar_cache_slot_history_leave_const(
    fd_sysvar_cache_t const *        sysvar_cache,
    fd_slot_history_global_t const * slot_history
) {
  (void)sysvar_cache; (void)slot_history;
}

fd_stake_history_t const *
fd_sysvar_cache_stake_history_join_const(
    fd_sysvar_cache_t const * cache
) {
  if( FD_UNLIKELY( !fd_sysvar_cache_stake_history_is_valid( cache ) ) ) return NULL;
  return (void const *)cache->obj_stake_history;
}

void
fd_sysvar_cache_stake_history_leave_const(
    fd_sysvar_cache_t const *  sysvar_cache,
    fd_stake_history_t const * stake_history
) {
  (void)sysvar_cache; (void)stake_history;
}

int
fd_sysvar_obj_restore( fd_sysvar_cache_t *     cache,
                       fd_sysvar_desc_t *      desc,
                       fd_sysvar_pos_t const * pos ) {
  desc->flags &= ~FD_SYSVAR_FLAG_VALID;

  uchar const * data    = (uchar const *)cache + pos->data_off;
  ulong const   data_sz = desc->data_sz;

  if( FD_UNLIKELY( !pos->decode ) ) {
    if( FD_UNLIKELY( !pos->validate( data, data_sz ) ) ) {
      FD_LOG_DEBUG(( "Failed to validate sysvar %s with data_sz=%lu",
                     pos->name, data_sz ));
      return EINVAL;
    }
    desc->flags |= FD_SYSVAR_FLAG_VALID;
    return 0;
  }

  fd_bincode_decode_ctx_t ctx = { .data=data, .dataend=data+data_sz };
  ulong obj_sz = 0UL;
  if( FD_UNLIKELY( pos->decode_footprint( &ctx, &obj_sz )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_DEBUG(( "Failed to decode sysvar %s with data_sz=%lu: decode failed",
                   pos->name, data_sz ));
    return EINVAL;
  }
  if( FD_UNLIKELY( obj_sz > pos->obj_max ) ) {
    FD_LOG_WARNING(( "Failed to restore sysvar %s: obj_sz=%lu exceeds max=%u",
                     pos->name, obj_sz, pos->obj_max ));
    return ENOMEM;
  }

  fd_memset( (uchar *)cache+pos->obj_off, 0, pos->obj_max );
  pos->decode( (uchar *)cache+pos->obj_off, &ctx );
  desc->flags |= FD_SYSVAR_FLAG_VALID;

  return 0;
}

#define TYPES_CALLBACKS( name, suf )                                   \
  .decode_footprint = fd_##name##_decode_footprint,                    \
  .decode           = (__typeof__(((fd_sysvar_pos_t *)NULL)->decode))(ulong)fd_##name##_decode##suf

static int
fd_sysvar_validate_clock( uchar const * data, ulong data_sz ) {
  (void)data;
  return data_sz >= sizeof(fd_sol_sysvar_clock_t );
}

static int
fd_sysvar_validate_rent( uchar const * data, ulong data_sz ) {
  (void)data;
  return data_sz >= sizeof(fd_rent_t );
}

static int
fd_sysvar_validate_last_restart_slot( uchar const * data, ulong data_sz ) {
  (void)data;
  return data_sz >= sizeof(ulong);
}

static int
fd_sysvar_validate_epoch_rewards( uchar const * data, ulong data_sz ) {
  if( FD_UNLIKELY( data_sz < sizeof(fd_sysvar_epoch_rewards_t) ) ) return 0;
  fd_sysvar_epoch_rewards_t ew = FD_LOAD( fd_sysvar_epoch_rewards_t, data );
  uchar active = ew.active;
  if( FD_UNLIKELY( active!=0 && active!=1 ) ) return 0;
  return 1;
}

static int
fd_sysvar_validate_epoch_schedule( uchar const * data, ulong data_sz ) {
  if( FD_UNLIKELY( data_sz < sizeof(fd_epoch_schedule_t) ) ) return 0;
  fd_epoch_schedule_t es = FD_LOAD( fd_epoch_schedule_t, data );
  uchar warmup = es.warmup;
  if( FD_UNLIKELY( warmup!=0 && warmup!=1 ) ) return 0;
  return 1;
}

fd_sysvar_pos_t const fd_sysvar_pos_tbl[ FD_SYSVAR_CACHE_ENTRY_CNT ] = {
  [FD_SYSVAR_clock_IDX] =
    { .name="clock",
      .data_off=offsetof(fd_sysvar_cache_t, bin_clock            ), .data_max=FD_SYSVAR_CLOCK_BINCODE_SZ,
      .validate=fd_sysvar_validate_clock },
  [FD_SYSVAR_epoch_rewards_IDX] =
    { .name="epoch rewards",
      .data_off=offsetof(fd_sysvar_cache_t, bin_epoch_rewards    ), .data_max=FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ,
      .validate=fd_sysvar_validate_epoch_rewards },
  [FD_SYSVAR_epoch_schedule_IDX] =
    { .name="epoch schedule",
      .data_off=offsetof(fd_sysvar_cache_t, bin_epoch_schedule   ), .data_max=FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ,
      .validate=fd_sysvar_validate_epoch_schedule },
  [FD_SYSVAR_last_restart_slot_IDX] =
    { .name="last restart slot",
      .data_off=offsetof(fd_sysvar_cache_t, bin_last_restart_slot), .data_max=FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ,
      .validate=fd_sysvar_validate_last_restart_slot },
  [FD_SYSVAR_recent_hashes_IDX] =
    { .name="recent blockhashes",
      .data_off=offsetof(fd_sysvar_cache_t, bin_recent_hashes    ), .data_max=FD_SYSVAR_RECENT_HASHES_BINCODE_SZ,
      .validate=fd_sysvar_recent_hashes_validate },
  [FD_SYSVAR_rent_IDX] =
    { .name="rent",
      .data_off=offsetof(fd_sysvar_cache_t, bin_rent             ), .data_max=FD_SYSVAR_RENT_BINCODE_SZ,
      .validate=fd_sysvar_validate_rent },
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
