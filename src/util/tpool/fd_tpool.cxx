#include "fd_tpool.h"

struct fd_tpool_private_worker_cfg {
  fd_tpool_t * tpool;
  ulong        tile_idx;
  void *       scratch;
  ulong        scratch_sz;
};

typedef struct fd_tpool_private_worker_cfg fd_tpool_private_worker_cfg_t;

/* This is not static to allow tile 0 to attach to this if desired. */

FD_TL ulong fd_tpool_private_scratch_frame[ FD_TPOOL_WORKER_SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

static int
fd_tpool_private_worker( int     argc,
                         char ** argv ) {
  ulong                           worker_idx = (ulong)(uint)argc;
  fd_tpool_private_worker_cfg_t * cfg        = (fd_tpool_private_worker_cfg_t *)argv;

  fd_tpool_t * tpool      = cfg->tpool;
  ulong        tile_idx   = cfg->tile_idx;
  void *       scratch    = cfg->scratch;
  ulong        scratch_sz = cfg->scratch_sz;

  fd_tpool_private_worker_t worker[1];
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_BOOT;
  FD_COMPILER_MFENCE();

  worker->tile_idx   = (uint)tile_idx;
  worker->scratch    = scratch;
  worker->scratch_sz = scratch_sz;

  if( scratch_sz ) fd_scratch_attach( scratch, fd_tpool_private_scratch_frame, scratch_sz, FD_TPOOL_WORKER_SCRATCH_DEPTH );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_IDLE;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fd_tpool_private_worker( tpool )[ worker_idx ] ) = worker;
  FD_COMPILER_MFENCE();

  for(;;) {

    /* We are IDLE ... see what we should do next */

    int state = FD_VOLATILE_CONST( worker->state );
    if( FD_UNLIKELY( state!=FD_TPOOL_WORKER_STATE_EXEC ) ) {
      if( FD_UNLIKELY( state!=FD_TPOOL_WORKER_STATE_IDLE ) ) break;
      FD_SPIN_PAUSE();
      continue;
    }

    /* We are EXEC ... do the task and then transition to IDLE */

    fd_tpool_task_t task = FD_VOLATILE_CONST( worker->task );

    void * task_tpool  = FD_VOLATILE_CONST( worker->task_tpool  );
    ulong  task_t0     = FD_VOLATILE_CONST( worker->task_t0     ); ulong task_t1     = FD_VOLATILE_CONST( worker->task_t1     );
    void * task_args   = FD_VOLATILE_CONST( worker->task_args   );
    void * task_reduce = FD_VOLATILE_CONST( worker->task_reduce ); ulong task_stride = FD_VOLATILE_CONST( worker->task_stride );
    ulong  task_l0     = FD_VOLATILE_CONST( worker->task_l0     ); ulong task_l1     = FD_VOLATILE_CONST( worker->task_l1     );
    ulong  task_m0     = FD_VOLATILE_CONST( worker->task_m0     ); ulong task_m1     = FD_VOLATILE_CONST( worker->task_m1     );
    ulong  task_n0     = FD_VOLATILE_CONST( worker->task_n0     ); ulong task_n1     = FD_VOLATILE_CONST( worker->task_n1     );

    try {
      task( task_tpool,task_t0,task_t1, task_args, task_reduce,task_stride, task_l0,task_l1, task_m0,task_m1, task_n0,task_n1 );
    } catch( ... ) {
      FD_LOG_WARNING(( "uncaught exception; attempting to continue" ));
    }

    FD_COMPILER_MFENCE();
    FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_IDLE;
    FD_COMPILER_MFENCE();
  }

  /* state is HALT, clean up and then reset back to BOOT */

  if( scratch_sz ) fd_scratch_detach( NULL );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_BOOT;
  FD_COMPILER_MFENCE();
  return 0;
}

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
               ulong  worker_max ) {

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
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker0->state ) = FD_TPOOL_WORKER_STATE_EXEC;
  FD_COMPILER_MFENCE();

  fd_tpool_t * tpool  = (fd_tpool_t *)(worker0+1);
  tpool->worker_max = worker_max;
  tpool->worker_cnt = 1UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( fd_tpool_private_worker( tpool )[0] ) = worker0;
  FD_COMPILER_MFENCE();

  return tpool;
}

void *
fd_tpool_fini( fd_tpool_t * tpool ) {

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
    return NULL;
  }

  while( fd_tpool_worker_cnt( tpool )>1UL )
    if( FD_UNLIKELY( !fd_tpool_worker_pop( tpool ) ) ) {
      FD_LOG_WARNING(( "fd_tpool_worker_pop failed" ));
      return NULL;
    }

  return (void *)fd_tpool_private_worker0( tpool );
}

fd_tpool_t *
fd_tpool_worker_push( fd_tpool_t * tpool,
                      ulong        tile_idx,
                      void *       scratch,
                      ulong        scratch_sz ) {

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

  if( FD_UNLIKELY( scratch_sz ) ) {
    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, FD_SCRATCH_SMEM_ALIGN ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return NULL;
    }
  }

  fd_tpool_private_worker_t ** worker     = fd_tpool_private_worker( tpool );
  ulong                        worker_cnt = tpool->worker_cnt;

  if( FD_UNLIKELY( worker_cnt>=tpool->worker_max ) ) {
    FD_LOG_WARNING(( "too many workers" ));
    return NULL;
  }

  for( ulong worker_idx=0UL; worker_idx<worker_cnt; worker_idx++ )
    if( worker[ worker_idx ]->tile_idx==tile_idx ) {
      FD_LOG_WARNING(( "tile_idx already added to tpool" ));
      return NULL;
    }

  fd_tpool_private_worker_cfg_t cfg[1];

  cfg->tpool      = tpool;
  cfg->tile_idx   = tile_idx;
  cfg->scratch    = scratch;
  cfg->scratch_sz = scratch_sz;

  int     argc = (int)(uint)worker_cnt;
  char ** argv = (char **)fd_type_pun( cfg );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker[ worker_cnt ] ) = NULL;
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( !fd_tile_exec_new( tile_idx, fd_tpool_private_worker, argc, argv ) ) ) {
    FD_LOG_WARNING(( "fd_tile_exec_new failed (tile probably already in use)" ));
    return NULL;
  }

  while( !FD_VOLATILE_CONST( worker[ worker_cnt ] ) ) FD_SPIN_PAUSE();

  tpool->worker_cnt = worker_cnt + 1UL;
  return tpool;
}

fd_tpool_t *
fd_tpool_worker_pop( fd_tpool_t * tpool ) {

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
    return NULL;
  }

  ulong worker_cnt = tpool->worker_cnt;
  if( FD_UNLIKELY( worker_cnt<=1UL ) ) {
    FD_LOG_WARNING(( "no workers to pop" ));
    return NULL;
  }

  fd_tpool_private_worker_t * worker   = fd_tpool_private_worker( tpool )[ worker_cnt-1UL ];
  fd_tile_exec_t *            exec     = fd_tile_exec( worker->tile_idx );
  int volatile *              vstate   = (int volatile *)&(worker->state);
  int                         state;

  /* Testing for IDLE isn't strictly necessary given requirements
     to use this but can help catch user errors.  Likewise,
     FD_ATOMIC_CAS isn't strictly necessary given correct operation but
     can more robustly catch such errors. */

# if FD_HAS_ATOMIC

  FD_COMPILER_MFENCE();
  state = FD_ATOMIC_CAS( vstate, FD_TPOOL_WORKER_STATE_IDLE, FD_TPOOL_WORKER_STATE_HALT );
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( state!=FD_TPOOL_WORKER_STATE_IDLE ) ) {
    FD_LOG_WARNING(( "worker to pop is not idle (%i-%s)", state, fd_tpool_worker_state_cstr( state ) ));
    return NULL;
  }

# else

  FD_COMPILER_MFENCE();
  state = *vstate;
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( state!=FD_TPOOL_WORKER_STATE_IDLE ) ) {
    FD_LOG_WARNING(( "worker to pop is not idle (%i-%s)", state, fd_tpool_worker_state_cstr( state ) ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  *vstate = FD_TPOOL_WORKER_STATE_HALT;
  FD_COMPILER_MFENCE();

# endif

  /* Wait for the worker to shutdown */

  int          ret;
  char const * err = fd_tile_exec_delete( exec, &ret );
  if(      FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "tile err \"%s\" unexpected; attempting to continue", err ));
  else if( FD_UNLIKELY( ret ) ) FD_LOG_WARNING(( "tile ret %i unexpected; attempting to continue", ret ));

  tpool->worker_cnt = worker_cnt-1UL;
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
  FD_COMPILER_MFENCE();
  void * tpool = (void *)FD_VOLATILE_CONST( l_next[1] );
  FD_COMPILER_MFENCE();
  for(;;) {

    /* Note that we use an ATOMIC_CAS here instead of an
       ATOMIC_FETCH_AND_ADD to avoid overflow risks by having threads
       increment l0 into the tail.  ATOMIC_FETCH_AND_ADD could be used
       if there is no requirement to the effect that l1+FD_TILE_MAX does
       not overflow. */

    FD_COMPILER_MFENCE();
    ulong m0 = FD_VOLATILE_CONST( *l_next );
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

char const *
fd_tpool_worker_state_cstr( int state ) {
  switch( state ) {
  case FD_TPOOL_WORKER_STATE_BOOT: return "boot";
  case FD_TPOOL_WORKER_STATE_IDLE: return "idle";
  case FD_TPOOL_WORKER_STATE_EXEC: return "exec";
  case FD_TPOOL_WORKER_STATE_HALT: return "halt";
  default: break;
  }
  return "unknown";
}
