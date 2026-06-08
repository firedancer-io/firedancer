#include "fd_epoch_info.h"

ulong
fd_epoch_info_align( void ) {
  return alignof(fd_epoch_info_t);
}

ulong
fd_epoch_info_footprint( ulong validator_cnt ) {
  return sizeof(fd_epoch_info_t) + validator_cnt*sizeof(fd_validator_info_t);
}

void *
fd_epoch_info_new( void *                      mem,
                   fd_validator_info_t const * validators,
                   ulong                       validator_cnt ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_epoch_info_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" )); return NULL;
  }
  FD_TEST( validator_cnt>0UL );

  fd_epoch_info_t *     ei = (fd_epoch_info_t *)mem;
  fd_validator_info_t * v  = (fd_validator_info_t *)(ei+1);

  ulong total = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i ); /* EpochInfo::new: id must match index */
    v[i]   = validators[i];
    total += validators[i].stake;
  }
  ei->validator_cnt = validator_cnt;
  ei->total_stake   = total;
  return mem;
}

fd_epoch_info_t *
fd_epoch_info_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  return (fd_epoch_info_t *)mem;
}
