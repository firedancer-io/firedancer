#include "fd_vinyl_cq.h"

ulong
fd_vinyl_cq_align( void ) {
  return alignof(fd_vinyl_cq_t);
}

ulong
fd_vinyl_cq_footprint( ulong comp_cnt ) {
  if( FD_UNLIKELY( !((4UL<=comp_cnt) & (comp_cnt<(1UL<<63)/sizeof(fd_vinyl_comp_t)) & fd_ulong_is_pow2( comp_cnt )) ) ) return 0UL;
  return fd_ulong_align_up( sizeof(fd_vinyl_cq_t) + comp_cnt*sizeof(fd_vinyl_comp_t), alignof(fd_vinyl_cq_t) ); /* no overflow */
}

void *
fd_vinyl_cq_new( void * shmem,
                 ulong  comp_cnt ) {
  fd_vinyl_cq_t * cq = (fd_vinyl_cq_t *)shmem;

  if( FD_UNLIKELY( !cq ) ) {
    FD_LOG_WARNING(( "NULL shmem"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)cq, fd_vinyl_cq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  ulong footprint = fd_vinyl_cq_footprint( comp_cnt );
  if( FD_UNLIKELY( !footprint) ) {
    FD_LOG_WARNING(( "bad comp_cnt"));
    return NULL;
  }

  memset( cq, 0, footprint );

  cq->comp_cnt = comp_cnt;
  cq->seq      = 0UL;

  fd_vinyl_comp_t * comp = fd_vinyl_cq_comp( cq );

  for( ulong seq=0UL; seq<comp_cnt; seq++ ) comp[ seq ].seq = seq - 1UL; /* Just before the next seq to be written to this entry */

  FD_COMPILER_MFENCE();
  cq->magic = FD_VINYL_CQ_MAGIC;
  FD_COMPILER_MFENCE();

  return cq;
}

fd_vinyl_cq_t *
fd_vinyl_cq_join ( void * shcq ) {
  fd_vinyl_cq_t * cq = (fd_vinyl_cq_t *)shcq;

  if( FD_UNLIKELY( !cq ) ) {
    FD_LOG_WARNING(( "NULL shcq"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)cq, fd_vinyl_cq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  if( FD_UNLIKELY( cq->magic!=FD_VINYL_CQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic"));
    return NULL;
  }

  return (fd_vinyl_cq_t *)shcq;
}

void *
fd_vinyl_cq_leave( fd_vinyl_cq_t * cq ) {

  if( FD_UNLIKELY( !cq ) ) {
    FD_LOG_WARNING(( "NULL cq"));
    return NULL;
  }

  return cq;
}

void *
fd_vinyl_cq_delete( void * shcq ) {
  fd_vinyl_cq_t * cq = (fd_vinyl_cq_t *)shcq;

  if( FD_UNLIKELY( !cq ) ) {
    FD_LOG_WARNING(( "NULL shcq"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)cq, fd_vinyl_cq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  if( FD_UNLIKELY( cq->magic!=FD_VINYL_CQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic"));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  cq->magic = 0UL;
  FD_COMPILER_MFENCE();

  return cq;
}
