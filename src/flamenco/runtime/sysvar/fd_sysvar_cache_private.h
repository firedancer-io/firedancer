#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h

#include "fd_sysvar_cache.h"

/* Locking ************************************************************/

/* fd_sysvar_cache_flags_writer_cnt returns 1 if the sysvar is currently
   being written to (conflicting reads and writes not allowed at this
   time). */

static inline uint
fd_sysvar_cache_flags_writer_cnt( uint flags ) {
  return !!( flags & 2 );
}

/* fd_sysvar_cache_flags_reader_cnt returns the number of readers
   currently holding a reference to the sysvar (writes not allowed until
   this counter reaches zero). */

static inline uint
fd_sysvar_cache_flags_reader_cnt( uint flags ) {
  return flags>>2;
}

#define FD_SYSVAR_CACHE_READER_MAX (0x3fffffffU)

/* fd_sysvar_cache_desc_write_{lock,unlock} {acquires,releases} a write
   lock on a sysvar cache entry. */

static inline void
fd_sysvar_cache_desc_write_lock( fd_sysvar_cache_desc_t * desc ) {
  for(;;) {
    uint const state_old = FD_VOLATILE_CONST( desc->flags );
    if( FD_UNLIKELY( fd_sysvar_cache_flags_writer_cnt( state_old ) ) ) {
      FD_LOG_CRIT(( "Data race or reentrancy on sysvar cache write lock, this is a bug" ));
    }
    uint const state_new = fd_uint_set_bit( state_old, 2 );
#if FD_HAS_ATOMIC
    if( FD_UNLIKELY( !FD_ATOMIC_CAS( &desc->flags, state_old, state_new ) ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
#else
    FD_VOLATILE( desc->flags ) = state_new;
#endif
    break;
  }
}

static inline void
fd_sysvar_cache_desc_write_unlock( fd_sysvar_cache_desc_t * desc ) {
  for(;;) {
    uint const state_old = FD_VOLATILE_CONST( desc->flags );
    if( FD_UNLIKELY( !fd_sysvar_cache_flags_writer_cnt( state_old ) ) ) {
      FD_LOG_CRIT(( "Unmatched write_unlock on sysvar cache, this is a bug" ));
    }
    uint const state_new = fd_uint_clear_bit( state_old, 2 );
#if FD_HAS_ATOMIC
    if( FD_UNLIKELY( !FD_ATOMIC_CAS( &desc->flags, state_old, state_new ) ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
#else
    FD_VOLATILE( desc->flags ) = state_new;
#endif
    break;
  }
}

/* fd_sysvar_cache_desc_read_{lock,unlock} {acquires,releases} a read
   lock on a sysvar cache entry. */

static inline void
fd_sysvar_cache_desc_read_lock( fd_sysvar_cache_desc_t * desc ) {
  for(;;) {
    uint const state_old = FD_VOLATILE_CONST( desc->flags );
    if( FD_UNLIKELY( fd_sysvar_cache_flags_reader_cnt( state_old )>=FD_SYSVAR_CACHE_READER_MAX ) ) {
      FD_LOG_CRIT(( "Too many concurrent read locks on sysvar cache entry, this is a bug" ));
    }
    uint const state_new = ( (state_old>>2)+1U ) | (state_old&3U);
#if FD_HAS_ATOMIC
    if( FD_UNLIKELY( !FD_ATOMIC_CAS( &desc->flags, state_old, state_new ) ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
#else
    FD_VOLATILE( desc->flags ) = state_new;
#endif
    break;
  }
}

static inline void
fd_sysvar_cache_desc_read_unlock( fd_sysvar_cache_desc_t * desc ) {
  for(;;) {
    uint const state_old = FD_VOLATILE_CONST( desc->flags );
    if( FD_UNLIKELY( !fd_sysvar_cache_flags_reader_cnt( state_old ) ) ) {
      FD_LOG_CRIT(( "Unmatched read_unlock on sysvar cache, this is a bug" ));
    }
    uint const state_new = ( (state_old>>2)-1U ) | (state_old&3U);
#if FD_HAS_ATOMIC
    if( FD_UNLIKELY( !FD_ATOMIC_CAS( &desc->flags, state_old, state_new ) ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
#else
    FD_VOLATILE( desc->flags ) = state_new;
#endif
    break;
  }
}

/* Accessors **********************************************************/

ulong
fd_sysvar_cache_data_laddr( fd_sysvar_cache_t const *      sysvar_cache,
                            fd_sysvar_cache_desc_t const * desc ) {
  if( FD_UNLIKELY( !desc->data_off ) ) FD_LOG_CRIT(( "zero sysvar_cache_desc data_off" ));
  return (ulong)sysvar_cache + desc->data_off;
}

ulong
fd_sysvar_cache_obj_laddr( fd_sysvar_cache_t const *      sysvar_cache,
                           fd_sysvar_cache_desc_t const * desc ) {
  if( FD_UNLIKELY( !desc->obj_off ) ) FD_LOG_CRIT(( "zero sysvar_cache_desc obj_off" ));
  return (ulong)sysvar_cache + desc->obj_off;
}

/* Database ***********************************************************/

/* fd_sysvar_account_update persists a sysvar data update to the account
   database.

   THIS API SHOULD NEVER BE USED DIRECTLY.  All runtime writes should
   use sysvar cache APIs, snapshot restore should use
   fd_sysvar_cache_recover. */

void
fd_sysvar_account_update( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const *  address,
                          void const *         data,
                          ulong                sz );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_private_h */
