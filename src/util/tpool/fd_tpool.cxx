#include "fd_tpool.h"
#include "../tile/fd_tile_private.h"
#include <pthread.h>

struct fd_tpool_private_worker_cfg {
  fd_tpool_t * tpool;
  ulong        cpu_idx;
  ulong        worker_idx;
  void *       scratch;
  ulong        scratch_sz;
  void *       stack;
  ulong        stack_sz;
};

typedef struct fd_tpool_private_worker_cfg fd_tpool_private_worker_cfg_t;

/* This is not static to allow tile 0 to attach to this if desired. */

FD_TL ulong fd_tpool_private_scratch_frame[ FD_TPOOL_WORKER_SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

static void *
fd_tpool_private_worker( void * arg ) {
  fd_tpool_private_worker_cfg_t * cfg = (fd_tpool_private_worker_cfg_t *)arg;

  fd_tpool_t * tpool      = cfg->tpool;
# if !__GLIBC__
  ulong        cpu_idx    = cfg->cpu_idx;
# endif
  ulong        worker_idx = cfg->worker_idx;
  void *       scratch    = cfg->scratch;
  ulong        scratch_sz = cfg->scratch_sz;
  void *       stack      = cfg->stack;
  ulong        stack_sz   = cfg->stack_sz;

  if( FD_LIKELY( stack ) ) { /* User provided stack */
    fd_tile_private_stack0 = (ulong)stack;
    fd_tile_private_stack1 = (ulong)stack + stack_sz;
  } else { /* Pthread provided stack */
    fd_log_private_stack_discover( stack_sz, &fd_tile_private_stack0, &fd_tile_private_stack1 ); /* logs details */
    if( FD_UNLIKELY( !fd_tile_private_stack0 ) )
      FD_LOG_WARNING(( "stack diagnostics not available on this tile; attempting to continue" ));
  }

  fd_tpool_private_worker_t worker[1];
  FD_COMPILER_MFENCE();
  worker->thread               = pthread_self();
  FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_BOOT;
  FD_COMPILER_MFENCE();

# if !__GLIBC__
  if( cpu_idx<65535UL ) {
    FD_CPUSET_DECL( cpu_set );
    fd_cpuset_insert( cpu_set, cpu_idx );
    int err = fd_cpuset_setaffinity( (pid_t)0, cpu_set );
    if( FD_UNLIKELY( err ) )
      FD_LOG_WARNING(( "fd_cpuset_setaffinity_failed (%i-%s)\n\t"
                       "Unable to set the thread affinity to cpu %lu.  Attempting to\n\t"
                       "continue without explicitly specifying this tile's cpu affinity but it\n\t"
                       "is likely this thread group's performance and stability are compromised\n\t"
                       "(possibly catastrophically so).  Update --tile-cpus to specify a set of\n\t"
                       "allowed cpus that have been reserved for this thread group on this host\n\t"
                       "to eliminate this warning.", err, fd_io_strerror( err ), cpu_idx ));
  }
# endif /* !__GLIBC__ */

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
                      ulong        cpu_idx,
                      void *       scratch,
                      ulong        scratch_sz ) {

  if( FD_UNLIKELY( !tpool ) ) {
    FD_LOG_WARNING(( "NULL tpool" ));
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

  fd_tpool_private_worker_cfg_t cfg[1];

  cfg->tpool      = tpool;
  cfg->cpu_idx    = cpu_idx;
  cfg->worker_idx = worker_cnt;
  cfg->scratch    = scratch;
  cfg->scratch_sz = scratch_sz;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker[ worker_cnt ] ) = NULL;
  FD_COMPILER_MFENCE();

  int fixed   = (cpu_idx<65535UL);
  if( fixed ) FD_LOG_INFO(( "booting worker on cpu %lu",   cpu_idx ));
  else        FD_LOG_INFO(( "booting worker" ));

  pthread_attr_t attr[1];
  int err = pthread_attr_init( attr );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "pthread_attr_init failed (%i-%s).\n\t",
                                        err, fd_io_strerror( err ) ));

  /* Set affinity ahead of time.  This is a GNU-specific extension
     that is not available on musl.  On musl, we just skip this
     step as we call sched_setaffinity(2) later on regardless. */

#   if __GLIBC__
  if( fixed ) {
    FD_CPUSET_DECL( cpu_set );
    fd_cpuset_insert( cpu_set, cpu_idx );
    err = pthread_attr_setaffinity_np( attr, fd_cpuset_footprint(), (cpu_set_t const *)fd_type_pun_const( cpu_set ) );
    if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "pthread_attr_setaffinity_failed (%i-%s)\n\t"
                                              "Unable to set the thread affinity for cpu %lu.  Attempting to\n\t"
                                              "continue without explicitly specifying this cpu's thread affinity but it\n\t"
                                              "is likely this thread group's performance and stability are compromised\n\t"
                                              "(possibly catastrophically so).  Update --tile-cpus to specify a set of\n\t"
                                              "allowed cpus that have been reserved for this thread group on this host\n\t"
                                              "to eliminate this warning.",
                                              err, fd_io_strerror( err ), cpu_idx ));
  }
#   endif /* __GLIBC__ */

  /* Create an optimized stack with guard regions if the build target
     is x86 (e.g. supports huge pages necessary to optimize TLB usage)
     and the tile is assigned to a particular CPU (e.g. bind the stack
     memory to the NUMA node closest to the cpu).

     Otherwise (or if an optimized stack could not be created), create
     vanilla pthread-style stack with guard regions.  We DIY here
     because pthreads seems to be missing an API to determine the
     extents of the stacks it creates and we need to know the stack
     extents for run-time stack diagnostics.  Though we can use
     fd_log_private_stack_discover to determine stack extents after
     the thread is started, it is faster, more flexible, more reliable
     and more portable to use a user specified stack when possible.

     If neither can be done, we will let pthreads create the tile's
     stack and try to discover the stack extents after the thread is
     started. */

  int optimize = FD_HAS_X86 & fixed;

  void * stack = fd_tile_private_stack_new( optimize, cpu_idx );
  if( FD_LIKELY( stack ) ) {
    err = pthread_attr_setstack( attr, stack, FD_TILE_PRIVATE_STACK_SZ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_tile: pthread_attr_setstack failed (%i-%s)\n\t", err, fd_io_strerror( err ) ));
      fd_tile_private_stack_delete( stack );
      stack = NULL;
    }
  }
  cfg->stack = stack;
  cfg->stack_sz = FD_TILE_PRIVATE_STACK_SZ;

  if( FD_UNLIKELY( !stack ) ) FD_LOG_WARNING(( "Unable to create a stack.\n\t"
                                               "Attempting to continue with the default stack but it is likely this\n\t"
                                               "thread group's performance and stability is compromised (possibly\n\t"
                                               "catastrophically so)." ));

  pthread_t thread;
  err = pthread_create( &thread, attr, fd_tpool_private_worker, cfg );
  if( FD_UNLIKELY( err ) ) {
    if( fixed ) FD_LOG_ERR(( "pthread_create failed (%i-%s)\n\t"
                             "Unable to start up worker on cpu %lu.",
                             err, fd_io_strerror( err ), cpu_idx ));
    else        FD_LOG_ERR(( "pthread_create failed (%i-%s)\n\t"
                             "Unable to start up worker.",
                             err, fd_io_strerror( err ) ));
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

  pthread_join( worker->thread, NULL );

  tpool->worker_cnt = worker_cnt-1UL;
  return tpool;
}

FD_FN_CONST static inline ulong              /* Returns number of elements to left side */
fd_tpool_private_exec_all_split( ulong n ) { /* Assumes n>1 */
# if 0 /* Simple splitting */
  return n>>1;
# else /* NUMA aware splitting */
  /* This split has the property that the left side >= the right and one
     of the splits is the largest power of two smaller than n.  It
     results in building a balanced tree (the same as the simple split)
     but with all the leaf nodes concentrated to toward the left when n
     isn't a power of two.  This can yield a slight reduction of the
     number of messages that might have to cross a NUMA boundary in many
     common usage scenarios. */
  ulong tmp = 1UL << (fd_ulong_find_msb( n )-1);
  return fd_ulong_max( tmp, n-tmp );
# endif
}

#define FD_TPOOL_EXEC_ALL_IMPL_HDR(style)                                                                                     \
void                                                                                                                          \
fd_tpool_private_exec_all_##style##_node( void * _node_tpool,                                                                 \
                                          ulong  node_t0, ulong node_t1,                                                      \
                                          void * args,                                                                        \
                                          void * reduce,  ulong stride,                                                       \
                                          ulong  l0,      ulong l1,                                                           \
                                          ulong  _task,   ulong _tpool,                                                       \
                                          ulong  t0,      ulong t1 ) {                                                        \
  ulong node_t_cnt = node_t1-node_t0;                                                                                         \
  if( node_t_cnt>1UL ) {                                                                                                      \
    fd_tpool_t * node_tpool = (fd_tpool_t *)_node_tpool;                                                                      \
    ulong        node_ts    = node_t0 + fd_tpool_private_exec_all_split( node_t_cnt );                                        \
    fd_tpool_exec( node_tpool, node_ts, fd_tpool_private_exec_all_##style##_node,                                             \
    /**/                                      node_tpool, node_ts,node_t1, args, reduce,stride, l0,l1, _task,_tpool, t0,t1 ); \
    fd_tpool_private_exec_all_##style##_node( node_tpool, node_t0,node_ts, args, reduce,stride, l0,l1, _task,_tpool, t0,t1 ); \
    fd_tpool_wait( node_tpool, node_ts );                                                                                     \
    return;                                                                                                                   \
  }                                                                                                                           \
  fd_tpool_task_t task = (fd_tpool_task_t)_task;

#define FD_TPOOL_EXEC_ALL_IMPL_FTR \
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
