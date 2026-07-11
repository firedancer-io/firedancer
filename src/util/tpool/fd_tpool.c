#include "fd_tpool.h"

#if FD_HAS_THREADS
#include <pthread.h>
#endif

struct fd_tpool_private_worker_cfg {
  fd_tpool_t * tpool;
  ulong        tile_idx;
};

typedef struct fd_tpool_private_worker_cfg fd_tpool_private_worker_cfg_t;

static int
fd_tpool_private_worker_( int     argc,
                          char ** argv ) {
  ulong                           worker_idx = (ulong)(uint)argc;
  fd_tpool_private_worker_cfg_t * cfg        = (fd_tpool_private_worker_cfg_t *)argv;

  fd_tpool_t * tpool    = cfg->tpool;
  ulong        tile_idx = cfg->tile_idx;

  /* We are BOOT */

  fd_tpool_private_worker_t worker[1];

  memset( worker, 0, sizeof(fd_tpool_private_worker_t) );

  worker->tile_idx = (uint) tile_idx;

# if FD_HAS_THREADS
  int sleeper = !!(tpool->opt & FD_TPOOL_OPT_SLEEP);

  pthread_mutex_t lock[1];
  pthread_cond_t  wake[1];

  if( FD_UNLIKELY( sleeper ) ) {
    if( FD_UNLIKELY( pthread_mutex_init( lock, NULL ) ) ) FD_LOG_ERR(( "pthread_mutex_init failed" ));
    if( FD_UNLIKELY( pthread_cond_init ( wake, NULL ) ) ) FD_LOG_ERR(( "pthread_cond_init failed"  ));
    if( FD_UNLIKELY( pthread_mutex_lock( lock       ) ) ) FD_LOG_ERR(( "pthread_mutex_lock failed" ));
  }

  worker->lock = (ulong)lock;
  worker->wake = (ulong)wake;
# endif

  FD_COMPILER_MFENCE();

  fd_tpool_private_worker( tpool )[ worker_idx ] = worker;

  ulong const * arg  = worker->arg;
  uint          seq1 = worker->seq1;

  for(;;) {

    /* We are IDLE ... see what we should do next */

#   if FD_HAS_THREADS
    if( FD_UNLIKELY( sleeper ) && FD_UNLIKELY( pthread_cond_wait( wake, lock ) ) )
      FD_LOG_WARNING(( "pthread_cond_wait failed; attempting to continue" ));
#   endif

    FD_COMPILER_MFENCE();
    uint  seq0     = worker->seq0;
    FD_COMPILER_MFENCE();
    uint  _arg_cnt = worker->arg_cnt;
    ulong _task    = worker->task;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( seq0==seq1 ) ) { /* Got idle */
      FD_SPIN_PAUSE();
      continue;
    }

    if( FD_UNLIKELY( !_task ) ) break; /* Got halt */

    /* We are EXEC ... do the task and then transition to IDLE */

    if( _arg_cnt==UINT_MAX ) {

      fd_tpool_task_t task = (fd_tpool_task_t)_task;

      void * task_tpool  = (void *)arg[ 0];
      ulong  task_t0     =         arg[ 1]; ulong task_t1     = arg[ 2];
      void * task_args   = (void *)arg[ 3];
      void * task_reduce = (void *)arg[ 4]; ulong task_stride = arg[ 5];
      ulong  task_l0     =         arg[ 6]; ulong task_l1     = arg[ 7];
      ulong  task_m0     =         arg[ 8]; ulong task_m1     = arg[ 9];
      ulong  task_n0     =         arg[10]; ulong task_n1     = arg[11];

      task( task_tpool,task_t0,task_t1, task_args, task_reduce,task_stride, task_l0,task_l1, task_m0,task_m1, task_n0,task_n1 );

    } else {

      fd_tpool_task_v2_t task = (fd_tpool_task_v2_t)_task;

      task( tpool, worker_idx, (ulong)_arg_cnt, arg );

    }

    FD_COMPILER_MFENCE();

    worker->seq1 = seq0;
    seq1 = seq0;
  }

  /* We are HALT ... clean up and terminate */

# if FD_HAS_THREADS
  if( FD_UNLIKELY( sleeper ) ) {
    if( FD_UNLIKELY( pthread_mutex_unlock ( lock ) ) ) FD_LOG_WARNING(( "pthread_mutex_unlock failed; attempting to continue" ));
    if( FD_UNLIKELY( pthread_cond_destroy ( wake ) ) ) FD_LOG_WARNING(( "pthread_cond_destroy failed; attempting to continue" ));
    if( FD_UNLIKELY( pthread_mutex_destroy( lock ) ) ) FD_LOG_WARNING(( "pthread_mutex_destroy failed; attempting to continue" ));
  }
# endif

  return 0;
}

#if FD_HAS_THREADS
void
fd_tpool_private_wake( fd_tpool_private_worker_t * worker ) {
  pthread_mutex_t * lock = (pthread_mutex_t *)worker->lock;
  pthread_cond_t *  wake = (pthread_cond_t  *)worker->wake;
  if( FD_UNLIKELY( pthread_mutex_lock  ( lock ) ) ) FD_LOG_WARNING(( "pthread_mutex_lock failed; attempting to continue" ));
  if( FD_UNLIKELY( pthread_cond_signal ( wake ) ) ) FD_LOG_WARNING(( "pthread_cond_signal failed; attempting to continue" ));
  if( FD_UNLIKELY( pthread_mutex_unlock( lock ) ) ) FD_LOG_WARNING(( "pthread_mutex_unlock failed; attempting to continue" ));
}
#endif

ulong
fd_tpool_align( void ) {
  return FD_TPOOL_ALIGN;
}

ulong
fd_tpool_footprint( ulong worker_max ) {
  if( FD_UNLIKELY( !((1UL<=worker_max) & (worker_max<=FD_TILE_MAX)) ) ) return 0UL;
  return fd_ulong_align_up( sizeof(fd_tpool_private_worker_t) +
                            sizeof(fd_tpool_t) + worker_max*sizeof(fd_tpool_private_worker_t *), FD_TPOOL_ALIGN );
}

fd_tpool_t *
fd_tpool_init( void * mem,
               ulong  worker_max,
               ulong  opt ) {

  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tpool_align() ) ) ) {
    FD_LOG_WARNING(( "bad alignment" ));
    return NULL;
  }

  ulong footprint = fd_tpool_footprint( worker_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad worker_max" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_tpool_private_worker_t * worker0 = (fd_tpool_private_worker_t *)mem;

  worker0->seq0 = 1U;
  worker0->seq1 = 0U;

  fd_tpool_t * tpool = (fd_tpool_t *)(worker0+1);

  tpool->opt        = opt;
  tpool->worker_max = (uint)worker_max;
  tpool->worker_cnt = 1U;

  FD_COMPILER_MFENCE();
  fd_tpool_private_worker( tpool )[0] = worker0;
  FD_COMPILER_MFENCE();

  return tpool;
}

void *
fd_tpool_fini( fd_tpool_t * tpool ) {

  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
    return NULL;
  }

  while( fd_tpool_worker_cnt( tpool )>1UL ) {
    if( FD_UNLIKELY( !fd_tpool_worker_pop( tpool ) ) ) {
      FD_LOG_WARNING(( "fd_tpool_worker_pop failed" ));
      return NULL;
    }
  }

  return (void *)fd_tpool_private_worker0( tpool );
}

fd_tpool_t *
fd_tpool_worker_push( fd_tpool_t * tpool,
                      ulong        tile_idx ) {

  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !tile_idx ) ) {
    FD_LOG_WARNING(( "cannot push tile_idx 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( tile_idx==fd_tile_idx() ) ) {
    FD_LOG_WARNING(( "cannot push self" ));
    return NULL;
  }

  if( FD_UNLIKELY( tile_idx>=fd_tile_cnt() ) ) {
    FD_LOG_WARNING(( "invalid tile_idx" ));
    return NULL;
  }

  fd_tpool_private_worker_t ** worker     = fd_tpool_private_worker( tpool );
  ulong                        worker_cnt = (ulong)tpool->worker_cnt;

  if( FD_UNLIKELY( worker_cnt>=(ulong)tpool->worker_max ) ) {
    FD_LOG_WARNING(( "too many workers" ));
    return NULL;
  }

  for( ulong worker_idx=0UL; worker_idx<worker_cnt; worker_idx++ )
    if( worker[ worker_idx ]->tile_idx==tile_idx ) {
      FD_LOG_WARNING(( "tile_idx already added to tpool" ));
      return NULL;
    }

  fd_tpool_private_worker_cfg_t cfg[1];

  cfg->tpool    = tpool;
  cfg->tile_idx = tile_idx;

  int     argc = (int)(uint)worker_cnt;
  char ** argv = (char **)fd_type_pun( cfg );

  FD_COMPILER_MFENCE();
  worker[ worker_cnt ] = NULL;
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !fd_tile_exec_new( tile_idx, fd_tpool_private_worker_, argc, argv ) ) ) {
    FD_LOG_WARNING(( "fd_tile_exec_new failed (tile probably already in use)" ));
    return NULL;
  }

  while( !FD_VOLATILE_CONST( worker[ worker_cnt ] ) ) FD_SPIN_PAUSE();

  tpool->worker_cnt = (uint)(worker_cnt + 1UL);
  return tpool;
}

fd_tpool_t *
fd_tpool_worker_pop( fd_tpool_t * tpool ) {

  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
    return NULL;
  }

  ulong worker_cnt = (ulong)tpool->worker_cnt;
  if( FD_UNLIKELY( worker_cnt<=1UL ) ) {
    FD_LOG_WARNING(( "no workers to pop" ));
    return NULL;
  }

  /* Testing for IDLE isn't strictly necessary given requirements to use
     this and this isn't being done atomically with the actually pop but
     does help catch obvious user errors. */

  if( FD_UNLIKELY( !fd_tpool_worker_idle( tpool, worker_cnt-1UL ) ) ) {
    FD_LOG_WARNING(( "worker to pop is not idle" ));
    return NULL;
  }

  /* Send HALT to the worker */

  fd_tpool_private_worker_t * worker = fd_tpool_private_worker( tpool )[ worker_cnt-1UL ];
  uint                        seq0   = worker->seq0 + 1U;
  fd_tile_exec_t *            exec   = fd_tile_exec( worker->tile_idx );

  worker->task = 0UL;
  FD_COMPILER_MFENCE();
  worker->seq0 = seq0;
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( tpool->opt & FD_TPOOL_OPT_SLEEP ) ) fd_tpool_private_wake( worker );

  /* Wait for the worker to shutdown */

  int          ret;
  char const * err = fd_tile_exec_delete( exec, &ret );
  if(      FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "tile err \"%s\" unexpected; attempting to continue", err ));
  else if( FD_UNLIKELY( ret ) ) FD_LOG_WARNING(( "tile ret %i unexpected; attempting to continue", ret ));

  tpool->worker_cnt = (uint)(worker_cnt - 1UL);
  return tpool;
}

#define FD_TPOOL_EXEC_ALL_IMPL_HDR(style)                                                          \
void                                                                                               \
fd_tpool_private_exec_all_##style##_node( void * _node_tpool,                                      \
                                          ulong  node_t0, ulong node_t1,                           \
                                          void * args,                                             \
                                          void * reduce,  ulong stride,                            \
                                          ulong  l0,      ulong l1,                                \
                                          ulong  _task,   ulong _tpool,                            \
                                          ulong  t0,      ulong t1 ) {                             \
  fd_tpool_t *    node_tpool = (fd_tpool_t *   )_node_tpool;                                       \
  fd_tpool_task_t task       = (fd_tpool_task_t)_task;                                             \
  ulong           wait_cnt   = 0UL;                                                                \
  ushort          wait_child[16];   /* Assumes tpool_cnt<=65536 */                                 \
  for(;;) {                                                                                        \
    ulong node_t_cnt = node_t1 - node_t0;                                                          \
    if( node_t_cnt<=1L ) break;                                                                    \
    ulong node_ts = node_t0 + fd_tpool_private_split( node_t_cnt );                                \
    fd_tpool_exec( node_tpool, node_ts, fd_tpool_private_exec_all_##style##_node,                  \
                   node_tpool, node_ts,node_t1, args, reduce,stride, l0,l1, _task,_tpool, t0,t1 ); \
    wait_child[ wait_cnt++ ] = (ushort)node_ts;                                                    \
    node_t1 = node_ts;                                                                             \
  }

#define FD_TPOOL_EXEC_ALL_IMPL_FTR                                                \
  while( wait_cnt ) fd_tpool_wait( node_tpool, (ulong)wait_child[ --wait_cnt ] ); \
}

FD_TPOOL_EXEC_ALL_IMPL_HDR(rrobin)
  ulong m_stride = t1-t0;
  ulong m        = l0 + fd_ulong_min( node_t0-t0, ULONG_MAX-l0 ); /* robust against overflow */
  while( m<l1 ) {
    task( (void *)_tpool,t0,t1, args,reduce,stride, l0,l1, m,m+1UL, node_t0,node_t1 );
    m += fd_ulong_min( m_stride, ULONG_MAX-m ); /* robust against overflow */
  }
FD_TPOOL_EXEC_ALL_IMPL_FTR

FD_TPOOL_EXEC_ALL_IMPL_HDR(block)
  ulong m0; ulong m1; FD_TPOOL_PARTITION( l0,l1,1UL, node_t0-t0,t1-t0, m0,m1 );
  for( ulong m=m0; m<m1; m++ ) task( (void *)_tpool,t0,t1, args,reduce,stride, l0,l1, m,m+1UL, node_t0,node_t1 );
FD_TPOOL_EXEC_ALL_IMPL_FTR

#if FD_HAS_ATOMIC
FD_TPOOL_EXEC_ALL_IMPL_HDR(taskq)
  ulong * l_next = (ulong *)_tpool;
  void  * tpool  = (void *)l_next[1];
  for(;;) {

    /* Note that we use an ATOMIC_CAS here instead of an
       ATOMIC_FETCH_AND_ADD to avoid overflow risks by having threads
       increment l0 into the tail.  ATOMIC_FETCH_AND_ADD could be used
       if there is no requirement to the effect that l1+FD_TILE_MAX does
       not overflow. */

    FD_COMPILER_MFENCE();
    ulong m0 = *l_next;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( m0>=l1 ) ) break;
    ulong m1 = m0+1UL;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( l_next, m0, m1 )!=m0 ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    task( tpool,t0,t1, args,reduce,stride, l0,l1, m0,m1, node_t0,node_t1 );
  }
FD_TPOOL_EXEC_ALL_IMPL_FTR
#endif

FD_TPOOL_EXEC_ALL_IMPL_HDR(batch)
  ulong m0; ulong m1; FD_TPOOL_PARTITION( l0,l1,1UL, node_t0-t0,t1-t0, m0,m1 );
  task( (void *)_tpool,t0,t1, args,reduce,stride, l0,l1, m0,m1, node_t0,node_t1 );
FD_TPOOL_EXEC_ALL_IMPL_FTR

FD_TPOOL_EXEC_ALL_IMPL_HDR(raw)
  task( (void *)_tpool,t0,t1, args,reduce,stride, l0,l1, l0,l1, node_t0,node_t1 );
FD_TPOOL_EXEC_ALL_IMPL_FTR

#undef FD_TPOOL_EXEC_ALL_IMPL_FTR
#undef FD_TPOOL_EXEC_ALL_IMPL_HDR
