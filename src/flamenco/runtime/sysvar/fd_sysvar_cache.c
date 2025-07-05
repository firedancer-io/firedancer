#include "fd_sysvar_cache_private.h"
#include "../context/fd_exec_slot_ctx.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

FD_FN_CONST ulong
fd_sysvar_cache_align( void ) {
  return FD_SYSVAR_CACHE_ALIGN;
}

FD_FN_CONST ulong
fd_sysvar_cache_footprint( void ) {
  return FD_SYSVAR_CACHE_FOOTPRINT;
}

void *
fd_sysvar_cache_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_SYSVAR_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  memset( mem, 0, sizeof(fd_sysvar_cache_footprint()) );
  fd_sysvar_cache_t * sysvar_cache = mem;

  FD_COMPILER_MFENCE();
  sysvar_cache->magic = FD_SYSVAR_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return sysvar_cache;
}

void *
fd_sysvar_cache_clone( void *                    mem2,
                       fd_sysvar_cache_t const * orig ) {

  if( FD_UNLIKELY( !mem2 ) ) {
    FD_LOG_WARNING(( "NULL mem2" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem2, FD_SYSVAR_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

}

fd_sysvar_cache_t *
fd_sysvar_cache_join( void * mem ) {
}

fd_sysvar_cache_t const *
fd_sysvar_cache_join_const( void const * mem ) {
}

void *
fd_sysvar_cache_leave( fd_sysvar_cache_t * sysvar_cache ) {
}

void const *
fd_sysvar_cache_leave_const( fd_sysvar_cache_t const * sysvar_cache ) {
}

void *
fd_sysvar_cache_delete( void * mem ) {
}

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_sysvar_cache_t const * cache,
                      fd_sol_sysvar_clock_t *   clock ) {
  fd_sysvar_cache_desc_t const * desc = &cache->clock;
  if( FD_UNLIKELY( !desc->obj_off ) ) return NULL;
  return memcpy( clock, (uchar *)cache+desc->obj_off, sizeof(fd_sol_sysvar_clock_t) );
}

void
fd_sysvar_clock_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_sol_sysvar_clock_t const * clock
) {
  fd_sysvar_cache_t *      cache = slot_ctx->sysvar_cache;
  fd_sysvar_cache_desc_t * desc  = &cache->clock;
  fd_sysvar_cache_desc_write_lock( desc );

  uchar * buf     = (uchar *)fd_sysvar_cache_data_laddr( cache, desc );
  ulong   buf_max = FD_SYSVAR_CLOCK_SZ_MAX;

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = buf,
    .dataend = buf+buf_max,
  };
  fd_sol_sysvar_clock_encode( clock, &encode_ctx );

  fd_sysvar_cache_desc_write_unlock( desc );
}

fd_slot_hash_t *
fd_sysvar_slot_hashes_join(
    fd_sysvar_cache_t * sysvar_cache
);

fd_slot_hash_t const *
fd_sysvar_slot_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);
