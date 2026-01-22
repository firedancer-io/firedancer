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
    memcpy( out, (uchar *)cache+pos->obj_off, pos->obj_max );          \
    return out;                                                        \
  }

#define SIMPLE_SYSVAR( name, name2, type ) \
  SIMPLE_SYSVAR_READ( name, name2, fd_##type##_t )
FD_SYSVAR_SIMPLE_ITER( SIMPLE_SYSVAR )
#undef SIMPLE_SYSVAR
#undef SIMPLE_SYSVAR_READ

fd_block_block_hash_entry_t const * /* deque */
fd_sysvar_cache_recent_hashes_join_const(
    fd_sysvar_cache_t const * cache
) {
  if( FD_UNLIKELY( !fd_sysvar_cache_recent_hashes_is_valid( cache ) ) ) return NULL;
  fd_recent_block_hashes_global_t * var = (void *)cache->obj_recent_hashes;
  fd_block_block_hash_entry_t * deq = deq_fd_block_block_hash_entry_t_join( (uchar *)var+var->hashes_offset );
  if( FD_UNLIKELY( !deq ) ) FD_LOG_CRIT(( "recent blockhashes sysvar corruption detected" ));
  return deq; /* demote to const ptr */
}

void
fd_sysvar_cache_recent_hashes_leave_const(
    fd_sysvar_cache_t const *           sysvar_cache,
    fd_block_block_hash_entry_t const * hashes_deque
) {
  (void)sysvar_cache; (void)hashes_deque;
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

  if( FD_UNLIKELY( !pos->obj_max ) ) {
    /* Sysvar is directly stored - does not need to be deserialized */
    desc->flags |= FD_SYSVAR_FLAG_VALID;
    FD_LOG_DEBUG(( "Restored sysvar %s (data_sz=%lu)", pos->name, data_sz ));
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
  pos->decode( (uchar *)cache+pos->obj_off, &ctx );
  desc->flags |= FD_SYSVAR_FLAG_VALID;

  //FD_LOG_DEBUG(( "Restored sysvar %s (data_sz=%lu obj_sz=%lu)",
  //               pos->name, data_sz, obj_sz ));
  return 0;
}
