#include "fd_epoch.h"

void *
fd_epoch_new( void * shmem, ulong voter_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_epoch_footprint( voter_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad mem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( voter_max ) ) + 2; /* fill ratio <= 0.25 */

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_t * epoch  = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), sizeof(fd_epoch_t) );
  void * epoch_voters = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_voters_align(),  fd_epoch_voters_footprint( lg_slot_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_align() ) == (ulong)shmem + footprint );

  epoch->voters_gaddr = fd_wksp_gaddr_fast( wksp, fd_epoch_voters_join( fd_epoch_voters_new( epoch_voters, lg_slot_cnt ) ) );

  epoch->epoch_gaddr = fd_wksp_gaddr_fast( wksp, epoch );
  epoch->first_slot  = FD_SLOT_NULL;
  epoch->last_slot   = FD_SLOT_NULL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( epoch->magic ) = FD_EPOCH_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_epoch_t *
fd_epoch_join( void * shepoch ) {
  fd_epoch_t * epoch = (fd_epoch_t *)shepoch;

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)epoch, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned epoch" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( epoch );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "epoch must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch->magic!=FD_EPOCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return epoch;
}

void *
fd_epoch_leave( fd_epoch_t const * epoch ) {

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  return (void *)epoch;
}

void *
fd_epoch_delete( void * epoch ) {

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)epoch, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned epoch" ));
    return NULL;
  }

  return epoch;
}

void
fd_epoch_fini( fd_epoch_t * epoch ) {
  fd_epoch_voters_clear( fd_epoch_voters( epoch ) );
}
