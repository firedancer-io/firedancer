#include "fd_vinyl_rq.h"

ulong
fd_vinyl_rq_align( void ) {
  return alignof(fd_vinyl_rq_t);
}

ulong
fd_vinyl_rq_footprint( ulong req_cnt ) {
  if( FD_UNLIKELY( !((4UL<=req_cnt) & (req_cnt<(1UL<<63)/sizeof(fd_vinyl_req_t)) & fd_ulong_is_pow2( req_cnt )) ) ) return 0UL;
  return fd_ulong_align_up( sizeof(fd_vinyl_rq_t) + req_cnt*sizeof(fd_vinyl_req_t), alignof(fd_vinyl_rq_t) );
}

void *
fd_vinyl_rq_new( void * shmem,
                 ulong  req_cnt ) {
  fd_vinyl_rq_t * rq = (fd_vinyl_rq_t *)shmem;

  if( FD_UNLIKELY( !rq ) ) {
    FD_LOG_WARNING(( "NULL shmem"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rq, fd_vinyl_rq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  ulong footprint = fd_vinyl_rq_footprint( req_cnt );
  if( FD_UNLIKELY( !footprint) ) {
    FD_LOG_WARNING(( "bad req_cnt"));
    return NULL;
  }

  memset( rq, 0, footprint );

  rq->req_cnt = req_cnt;
  rq->seq     = 0UL;

  fd_vinyl_req_t * req = fd_vinyl_rq_req( rq );

  for( ulong seq=0UL; seq<req_cnt; seq++ ) req[ seq ].seq = seq - 1UL; /* Just before the next seq to be written to this entry */

  FD_COMPILER_MFENCE();
  rq->magic = FD_VINYL_RQ_MAGIC;
  FD_COMPILER_MFENCE();

  return rq;
}

fd_vinyl_rq_t *
fd_vinyl_rq_join( void * shrq ) {
  fd_vinyl_rq_t * rq = (fd_vinyl_rq_t *)shrq;

  if( FD_UNLIKELY( !rq ) ) {
    FD_LOG_WARNING(( "NULL shrq"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rq, fd_vinyl_rq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  if( FD_UNLIKELY( rq->magic!=FD_VINYL_RQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic"));
    return NULL;
  }

  return (fd_vinyl_rq_t *)shrq;
}

void *
fd_vinyl_rq_leave( fd_vinyl_rq_t * rq ) {

  if( FD_UNLIKELY( !rq ) ) {
    FD_LOG_WARNING(( "NULL rq"));
    return NULL;
  }

  return rq;
}

void *
fd_vinyl_rq_delete( void * shrq ) {
  fd_vinyl_rq_t * rq = (fd_vinyl_rq_t *)shrq;

  if( FD_UNLIKELY( !rq ) ) {
    FD_LOG_WARNING(( "NULL shrq"));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rq, fd_vinyl_rq_align() ) ) ) {
    FD_LOG_WARNING(( "bad align"));
    return NULL;
  }

  if( FD_UNLIKELY( rq->magic!=FD_VINYL_RQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic"));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  rq->magic = 0UL;
  FD_COMPILER_MFENCE();

  return rq;
}
