#ifndef HEADER_fd_src_util_tpool_fd_tpool_h
#define HEADER_fd_src_util_tpool_fd_tpool_h

/* tpool provides APIs to group sets of tiles together for ultra low
   overhead and high scalability launching of thread parallel jobs.
   There is a lot of nuance that most thread pool APIs and
   implementations get wrong.  And this nuance is very useful to
   understand why the APIs and implementations are the way they are.
   So, a crash course:

   High performance thread parallelism crash course ********************

   Consider the simple and highly idealized case of a job with N
   independent tasks that each take an approximately uniform time
   tau_task to execute.

   A serial implementation of this job might look like:

     for( ulong n=0; n<N; n++ ) ... do task n ...;
   
   And the overall time to do such a job is:

     T_serial ~ tau_overhead + tau_task N

   where tau_overhead represents O(1) costs like the overhead to setup
   the loop that will do the N tasks.

   In a parallel implementation, we want to uniformly divide these tasks
   over P threads to speed this up.  If we use the naive strategy that
   many codes and libraries use, we have something like (either
   explicitly or under the hood and ignoring error trapping):

     static void *
     task_block( void * _args ) {
       task_args_t * args = (task_args_t *)_args;
       ... unpack task args here, including
       ulong n0 = args->n0;
       ulong n1 = args->n1;

       for( ulong n=n0; n<n1; n++ ) ... do task n ...;

       return NULL;
     }

     ... in the main thread ...

     task_args_t * args   = (task_args_t *)malloc( P*sizeof(task_args_t) );
     pthread_t *   thread = (pthread_t *)  malloc( P*sizeof(pthread_t)   );
     for( ulong p=0; p<P; p++ ) args[p] = ... block p info ...;
     for( ulong p=1; p<P; p++ ) pthread_create( &thread[p], NULL, task_block, &args[p] );
     task_block( &args[0] );
     for( ulong p=1; p<P; p++ ) pthread_join( thread[p], NULL );
     free( thread );
     free( args );

   (Above, we used the main thread as one of the P threads in job
   execution such that it both dispatches and does a share of the work.
   This discussion still applies if we just have main do dispatch only.)

   Ugh ... this does parallelize the task over P threads but it is
   practically worthless.  The overall time to execute is:

     T_parallel_dumb ~ tau_overhead_dumb
                     + tau_partition_dumb P
                     + tau_dispatch_dumb (P-1)
                     + tau_task N / P

   tau_overhead_dumb represents that the overhead from before, but
   with more dumb.  That is, it is likely a lot larger than the serial
   version because of the allocations and need to wrap up the tasks in a
   thread dispatch function signature compatible way (pthread_create
   "start_routine" in this case).  (There are usually additional
   overheads omitted from this simplified discussion.)

   tau_partition_dumb is the time spent by the main thread partitioning
   the work for the worker threads per worker thread.  This is dumb
   because this work could be parallelized (i.e. done within the task
   itself).  A second, less obvious, dumbness is that, in complex work
   distribution scenarios, it is often very difficult for the main
   thread to determine the optimal partition a worker thread should do
   (see sgemm dispatch example below of something very hard to do
   centrally but very easy to do distributed).  This ends up a triple
   whammy of awful: the parallelization strategy is inefficient,
   computed inefficiently and computed by one thread.  Amdahl
   bottlenecks for everyone!

   tau_dispatch_dumb is the time needed to start and stop a worker
   thread to run a task.  This is dumb because things like
   pthread_create have a huge overhead and because the total overhead is
   linear in P.  (In practice, this is even dumber than it appears
   because we didn't do anything fancy with the created threads to
   mitigate thread-core affinity effects, IPC effects, kernel scheduling
   effects, NUMA effects, TLB effects, ... neglected in this idealized
   example.)

   Thus, we better have an infinite N if we are going to be able
   usefully parallelize over many threads under the dumb parallelization
   strategies.

   But, in the real world, N is not infinite and often our goal is to
   reduce the time needed to do a finite amount of work.  Throwing all
   the threads in the world at the job will not help because, while
   increasing the number of threads decreases the amount of time
   required to do the tasks hyperbolically, it _increases_ _linearly_
   the amount of time needed to setup the threads to do those tasks.

   This leads to the question: what is maximum number of threads we can
   use profitably?

   This will be the P that minimizes T_parallel_dumb.  Call this value
   P_max_useful_dumb.  Given this point is a minima of T_parallel_dumb,
   for P<P_max_useful_dumb / P>P_max_useful_dumb, using _more_ / _less_
   threads for fixed sized job is useful.

   From basic calculus, P_max_useful_dumb is where the derivative of
   T_parallel_dumb with respect to P is zero.  With:

     dT_parallel_dumb / dP ~ tau_partition_dumb
                           + tau_dispatch_dumb
                           - tau_task N / P^2

   we can solve for dT_parallel_dumb / dP = 0.  This yields:

     P_max_useful_dumb ~ sqrt( tau_task N / ( tau_partition_dumb + tau_dispatch_dumb ) )

   This does not even weak scale!  Doubling N does not double the
   P_max_useful_dumb; it only allows increases by ~sqrt(2).  Sad.

   And it is worse than that because tau_dispatch_dumb is typically
   massive and tau_task is often infinitesimal.
   
   For example, in parallelizing level 1 matrix operations (e.g. a
   vector add), N is often related to the number of scalar flops needed
   and thus tau_task is small O(1) times the marginal cost of doing a
   single flop, assuming the problem itself fits within cache.  That is,
   tau_task is measured in picoseconds (e.g. wide vector SIMD double
   pumped FMA units on a ~3 GHz core).
   
   But tau_dispatch_dumb is measured in milliseconds (e.g.
   pthread_create + pthread_join with all their glorious O/S and kernel
   scheduler overheads).
   
   This means we need huge N before it being even worthwhile to consider
   parallelization under the dumb strategy.  And once N is large enough,
   the problem transitions from being cacheable to uncachable.  And in
   that regime, memory bandwidth limits not considered here dominate
   (all those cores starved of useful work because of badly designed
   software and limited memory bandwidth).  Embarrassing.

   All too common a story: "We parallelized [important thing] with
   [rando popular but naive thread library du jour].  It got slower.
   Guess it was already as efficient as it could be."
   
   Sigh ... fortunately, the math also gives the prescription of what we
   need to do (and maybe gives a hint, contrary to belief floating
   around in blogs and what not, math is in fact critically important
   for coding).

   First, we need to parallelize the partition calculation by having
   each worker thread concurrently compute their slice of the job.  We
   can do that by passing a reference to a description of whole job
   along with just enough context to each thread that they can determine
   their slice (e.g. a thread index and number of threads).  This
   eliminates tau_partition_dumb from the denominator above but it
   requires a better thread dispatcher function signature than used
   above.

   Second, we create all the threads we are going to use up front, pin
   them to dedicated isolated cores at high kernel schedule priority
   with optimized NUMA and TLB aware stacks and scratch spaces to
   massively reduce tau_dispatch_dumb overheads (and also fix some more
   subtle performance drains in practical usage at the same time).
   These threads will spin on memory in optimized ways to make the time
   to wake up a thread on the order of the time it takes to transfer a
   cache line to a core (tens to hundreds of ns).
   
   Together, these turn the above into something like:

     static void
     task_block( void * _args,
                 ulong  p,
                 ulong  P ) {
       job_args_t * args = (job_args_t *)_args;
       ... unpack job args here, including
       ulong N = args->N;

       // Compute the block of tasks to be done by this thread
       ulong n0;
       ulong n1;
       FD_TPOOL_PARTITION( 0,N,1, p,P, n0,n1 );

       for( ulong n=n0; n<n1; n++ ) ... do task n ...;
     }

     ... in main thread ...

     job_args_t args[1] = { ... job info ... };
     for( ulong p=1; p<P; p++ ) tpool_exec( tpool,p, task_block,args, p,P );
     task_block( args, 0,P );
     for( ulong p=1; p<P; p++ ) tpool_wait( tpool,p );

   This is dramatically better in implementation as now we have:

     P_max_useful_okay ~ sqrt( tau_task N / tau_dispatch_smart )
   
   where tau_dispatch_smart << tau_dispatch_dumb.  Additionally, the
   various overheads in the main thread are much lower.
   
   While this is able to use dramatically more threads profitably for a
   fixed job size, we still aren't able to weak scale.  To do that, we
   need to parallelize the thread dispatch too.

   Third, we parallelize thread dispatch.  The obvious but wrong
   solution is to use a single common memory location that all worker
   threads in the pool will wait on to start execution and a single
   common memory location that all workers will atomically increment at
   completion so the main thread only has to spin on one memory location
   to tell if the job is complete.

   This is wrong practically because, while it superficially looks like
   O(1) operations for the dispatch and wait, this is a cache coherence
   protocol nightmare beyond compare.  There will be large constant O(N)
   messaging on the CPUs internal network-on-chip to distribute the
   information to/from all the worker threads.  Such will often not be
   parallelized under the hood particularly well or particularly
   deterministic (especially the waiting part ... the main thread still
   needs to get N updates from the workers that will be serialized with
   lots of cache line ping-pong-ing on top of atomic operations under
   the hood as they funnel back toward the main thread).

   Instead, we can recursively divide the job to unambiguously
   parallelize task dispatch.  This yields something like:

     static void
     task_node( tpool_t * tpool, // thread pool to use
                ulong     p0,    // Assumes p0>=0, caller is p0
                ulong     p1,    // Assumes p1>p0
                void *    args,
                ulong     P ) {  // Assumes P>=p1

       // At this point we are worker thread p0 and we are responsible
       // for dispatching work to workers [p0,p1) 

       ulong p_cnt = p1-p0;
       if( p_cnt>1UL ) {

         // At this point, we have more than one thread available.
         // Split the workers approximately in half and have worker
         // thread ps dispatch work to threads [ps,p1) while we
         // concurrently dispatch work to threads [p0,ps).

         ulong ps = p0 + (p_cnt>>1);
         tpool_exec( tpool,ps, task_node, tpool,ps,p1, args, P );
         task_node( tpool,p0,ps, args, P );
         tpool_wait( tpool,ps );
         return;
       }

       // At this point, there is only one thread available
       // Do our slice of the job.

       job_args_t * args = (job_args_t *)_args;
       ... unpack job args here, including
       ulong N = args->N;

       // Compute block of tasks to be done by this thread
       ulong n0;
       ulong n1;
       FD_TPOOL_PARTITION( 0,N,1, p,P, n0,n1 );

       for( ulong n=n0; n<n1; n++ ) ... do task n ...;
     }

     ... in the main thread ...

     job_args_t args[1] = { ... job info ... };
     task_node( tpool,0,P, args, P );

   This has an algorithmically different and cheaper cost model for
   thread parallelization:

     T_parallel_smart ~ tau_overhead_smart
                      + tau_dispatch_smart ceil log2(P)
                      + tau_task N / P

   With the magical power of calculus again, noting that
   log2(P)=ln(P)/ln(2) and ceil log2(P) ~ log2(P) asymptotically, we
   have:

     dT_parallel_smart / dP ~ tau_dispatch_smart / (P ln(2)) - tau_task N/P^2

   such that:

     P_max_useful_smart ~ tau_task ln(2) N / tau_dispatch_smart

   Now we can weak scale!  If we double the amount of work, we can
   double the maximum useful threads we can apply.

   Since tau_overhead_smart ~ tau_overhead_serial << tau_overhead_dumb,
   tau_dispatch_smart << tau_dispatch_dumb and N isn't stuck inside a
   sqrt anymore, we also can profitably parallelize _orders_ _of_
   _magnitude_ smaller problems than before.

   As a further bonus, the above dispatch pattern naturally supports
   much more complex parallelizations (see the sgemm example below) and
   naturally has good thread-NUMA topology oblivious and cache oblivious
   algorithmic properties (ideally the tpool threads themselves have
   good spatial locality for best results).

   Last, we can wrap all this up so that, in simple cases, all the user
   needs to do is:

     static void
     task_block( void * _args,
                 ulong  p,
                 ulong  P ) {
       job_args_t * args = (job_args_t *)_args;
       ... unpack job args here, including
       ulong N = args->N;

       // Compute block of tasks to be done by this thread
       ulong n0;
       ulong n1;
       FD_TPOOL_PARTITION( 0,N,1, p,P, n0,n1 );

       for( ulong n=n0; n<n1; n++ ) ... do task n ...;
     }

     ... in the main thread ...

     job_args_t args[1] = { ... args ... };
     tpool_exec_all( tpool,0,P, task_block,args );

   and, in the main thread, it will act like:

     job_args_t args[1] = { ... args ... };
     for( ulong p=0; p<P; p++ ) task_block( args, p,P );

   but have a performance characteristic like T_parallel_smart.

   The actual function signature used for a fd_tpool_task_t below was
   picked to be sufficient to tightly and uniformly partition an
   arbitrarily shaped layer 3 blas sgemm A^T B matrix calculation over
   lots of cores in an arbitrarily shaped NUMA topologies without a lot
   of overhead in the dispatch logic.  For example (and this also shows
   a powerful use case for scratch memory too):

     // This is called by worker thread t0 and uses tpool worker threads
     // [t0,t1) to compute:
     // 
     //   C([0,l1-l0),[0,m1-m0)) = A([m0,m1),[l0,l1))' B([m0,m1),[n0,n1))

     void
     atb_node( fd_tpool_t * tpool,       // tpool to use
               ulong t0,    ulong t1,    // Assumes t1>t0
               atb_args_t * args,        // Location of A and B matrices and their column strides
               float *      C,           // (l1-l0)*(n1-n0) col-major matrix with col stride sC
               ulong        sC,          // Assumes sC>=(l1-l0), C(i,j) at C[ i + sC*j ]
               ulong l0,    ulong l1,    // Assumes l1>=l0
               ulong m0,    ulong m1,    // Assumes m1>=m0
               ulong n0,    ulong n1 ) { // Assumes n1>=n0

       // At this point, we are worker thread t0 and we are responsible
       // for dispatching work to worker threads [t0,t1)

       ulong t_cnt = t1-t0;
       if( t_cnt>1UL ) {  // ... and optionally the task big enough to be worth parallelizing

         // We need to split this task over more than one thread.
         //
         // Split the worker threads into two approximately equal sized
         // sets (left and right) and then proportionally split the
         // longest matrix range to try to make the subtasks as square
         // as possible (and thus improve compute data ratio /
         // cacheability of subtasks).  Note that we do not just split
         // matrix ranges in half because such a split would result in
         // an increasingly bad load imbalance between the left and
         // right workers when the matrix range to split is large but
         // t_cnt is small and odd.
         // 
         // We then execute in parallel the left range on worker threads
         // [t0,th) and the right range on worker threads [th,t1).  Yes,
         // this uses recursion in the thread dispatch to get radically
         // better scalability, lower overhead and ability to map
         // arbitrary shaped problems onto arbitrarily shaped massively
         // parallel hardware with minimal load imbalance (see notes
         // above for more details about this).

         ulong t_cnt_left = t_cnt >> 1;
         ulong ts         = t0 + t_cnt_left;

         ulong l_cnt = l1-l0;
         ulong m_cnt = m1-m0;
         ulong n_cnt = n1-n0;

         if( FD_UNLIKELY( (m_cnt>l_cnt) & (m_cnt>n_cnt) ) ) { // Split m range

           // Splitting along m is more onerous than splitting along l
           // or n because the left and right subtask outputs would end
           // up clobbering each other or, if being atomically too
           // clever by half, having a non-deterministic result due to an
           // indeterminant summation order and floating point
           // non-associativity.  So we allocate a temporary matrix near
           // these cores to hold the right half partial reduction such
           // that the left and right can do their partial reductions
           // independently (and deterministically) and then do a
           // (deterministic) thread parallel reduction of the two
           // results on threads [t0,t1) afterward (a level of fine
           // grained parallelization few even think is possible on
           // commodity processors).

           ulong m_cnt_left = (m_cnt*t_cnt_left)/t_cnt; // handle overflow here
           ulong ms         = m0 + m_cnt_left;

           fd_scratch_push();

           float * CR = (float *)fd_scratch_alloc( 0UL, l_cnt*n_cnt*sizeof(float) );

           fd_tpool_exec( tpool,ts, atb_node,tpool,ts,t1, args, CR,l_cnt, l0,l1, ms,m1, n0,n1 );
           atb_node( tpool,t0,ts, args, C,sC, l0,l1, m0,ms, n0,n1 );
           fd_tpool_wait( tpool,ts );

           // Do C([0,l_cnt),[0,n_cnt)) += CR([0,l_cnt),[0,n_cnt)) on threads [t0,t1) here

           fd_scratch_pop();

         } else if( FD_UNLIKELY( n_cnt>l_cnt ) ) { // Split n range

           ulong n_cnt_left = (n_cnt*t_cnt_left)/t_cnt; // handle overflow here
           ulong ns         = n0 + n_cnt_left;

           float * CR = C + sC*n_cnt_left;

           fd_tpool_exec( tpool,ts, atb_node,tpool,ts,t1, args, CR,sC, l0,l1, m0,m1, ns,n1 );
           atb_node( tpool,t0,ts, args, C,sC, l0,l1, m0,m1, n0,ns );
           fd_tpool_wait( tpool,ts );

         } else { // Split l range

           ulong l_cnt_left = (l_cnt*t_cnt_left)/t_cnt; // handle overflow here
           ulong ls         = l0 + l_cnt_left;

           float * CR = C + l_cnt_left;

           fd_tpool_exec( tpool,ts, atb_node,tpool,ts,t1, args, CR,sC, ls,l1, m0,m1, n0,n1 );
           atb_node( tpool,t0,ts, args, C,sC, l0,ls, m0,m1, n0,n1 );
           fd_tpool_wait( tpool,ts );

         }

         return;
       }

       // At this point, we are at a leaf node
       // Do C([0,l1-l0),[0,n1-n0)) = A([m0,m1),[l0,l1))' B([m0,m1),[n0,n1)) here
     }

   End of high performance thread parallelism crash course ************/

#include "../tile/fd_tile.h"
#include "../scratch/fd_scratch.h"

/* FD_TPOOL_WORKER_STATE_* are possible states a tpool worker thread
   is in.  Users practically should never see BOOT or HALT. */

#define FD_TPOOL_WORKER_STATE_BOOT (0) /* Tile is booting */
#define FD_TPOOL_WORKER_STATE_IDLE (1) /* Tile is idle */
#define FD_TPOOL_WORKER_STATE_EXEC (2) /* Tile is executing a task */
#define FD_TPOOL_WORKER_STATE_HALT (3) /* Tile is halting */

/* FD_TPOOL_PARTITION partitions tasks indexed [task0,task1) over
   worker_cnt worker threads.  On return, tasks indexed
   [worker_task0,worker_task1) is the range of tasks to be done by
   worker worker_idx.

   The number of tasks to a worker will be as uniform as possible, with
   the constraints that the tasks will be assigned to workers in
   monotonically increasing order and, for worker_idx<worker_cnt-1, the
   number of tasks assigned will be a multiple of lane_cnt in size.
   (That is, any final incomplete SIMD block will be assigned to worker
   worker_cnt-1.)

   Assumes task1>=task0, lane_cnt>0, worker_cnt>0 and
   worker_idx<worker_cnt.  Performance will be fastest if lane_cnt
   and/or worker_cnt are an integer power-of-two (especially 1).  This
   macro is robust. */

#define FD_TPOOL_PARTITION( task0, task1, lane_cnt, worker_idx, worker_cnt, worker_task0, worker_task1 ) do {                 \
    ulong _ftp_task0            = (task0);                                                                                    \
    ulong _ftp_task1            = (task1);                                                                                    \
    ulong _ftp_lane_cnt         = (lane_cnt);                                                                                 \
    ulong _ftp_worker_idx       = (worker_idx);                                                                               \
    ulong _ftp_worker_cnt       = (worker_cnt);                                                                               \
    ulong _ftp_task_cnt         = _ftp_task1 - _ftp_task0;                                                                    \
    ulong _ftp_block_cnt        = _ftp_task_cnt  / _ftp_lane_cnt;   /* Num complete simd blocks, typically nop or fast shr */ \
    ulong _ftp_block_rem        = _ftp_task_cnt  % _ftp_lane_cnt;   /* Number of leftovers, typically nop or fast mask */     \
    ulong _ftp_worker_block_min = _ftp_block_cnt / _ftp_worker_cnt; /* Min complete simd blocks for a worker */               \
    ulong _ftp_worker_extra_cnt = _ftp_block_cnt % _ftp_worker_cnt; /* Num workers needing an extra complete simd block */    \
    ulong _ftp_worker_task0     = _ftp_task0                                                                                  \
       + _ftp_lane_cnt*(_ftp_worker_block_min*_ftp_worker_idx + fd_ulong_min(_ftp_worker_idx,_ftp_worker_extra_cnt));         \
    ulong _ftp_worker_task1     = _ftp_worker_task0                                                                           \
       + _ftp_lane_cnt*(_ftp_worker_block_min + ((ulong)(_ftp_worker_idx<_ftp_worker_extra_cnt)))                             \
       + fd_ulong_if( _ftp_worker_idx==(_ftp_worker_cnt-1UL), _ftp_block_rem, 0UL );                                          \
    (worker_task0)              = _ftp_worker_task0;                                                                          \
    (worker_task1)              = _ftp_worker_task1;                                                                          \
  } while(0)

/* A fd_tpool_task_t is the function signature used for the entry
   point of a task.  Users are free to repurpose these arguments however
   they see fit for an individual executions but the number of
   arguments, types of argument and names used below reflect the intent
   described in the above crash course.  Namely, this is adequate to map
   arbitrary level 3 BLAS dense matrix-matrix multiply with arbitrary
   shaped matrices to an arbitrary topology set of tiles ultra quickly
   and ultra tightly.  Bulk dispatchers like tpool_exec_all might apply
   some additional conventions to some of these arguments. */

typedef void
(*fd_tpool_task_t)( void * tpool,
                    ulong  t0,     ulong t1,
                    void * args,
                    void * reduce, ulong stride,
                    ulong  l0,     ulong l1,
                    ulong  m0,     ulong m1,
                    ulong  n0,     ulong n1 );

/* A fd_tpool_t is an opaque handle of a thread pool */

struct fd_tpool_private;
typedef struct fd_tpool_private fd_tpool_t;

/* Private APIs *******************************************************/

/* These are exposed here to facilitate inlining various operations in
   high performance contexts. */

struct __attribute__((aligned(128))) fd_tpool_private_worker {
  fd_tpool_task_t task;
  void *          task_tpool;
  ulong           task_t0;     ulong task_t1;
  void *          task_args;
  void *          task_reduce; ulong task_stride;
  ulong           task_l0;     ulong task_l1;
  ulong           task_m0;     ulong task_m1;
  ulong           task_n0;     ulong task_n1;
  int             state;
  uint            tile_idx;
  void *          scratch;
  ulong           scratch_sz;
};

typedef struct fd_tpool_private_worker fd_tpool_private_worker_t;

struct fd_tpool_private {

  /* This point is 128 aligned and preceded by the worker0 sentinel */

  ulong worker_max; /* Positive */
  ulong worker_cnt; /* in [1,worker_max] */

  /* worker_max element fd_tpool_private_worker_t * array here, indexed
     [0,worker_cnt).  worker[0] points to worker0 above.  Note that we
     cannot use a flex array here because strict C++17 doesn't support
     it and we use C++ in fd_tpool.cxx to handle people using C++
     libraries that throw exceptions that are uncaught ... sigh. */

};

FD_PROTOTYPES_BEGIN

/* fd_tpool_private_worker0 returns a pointer in the local address space
   to the worker0 sentinel */

FD_FN_CONST static inline fd_tpool_private_worker_t *
fd_tpool_private_worker0( fd_tpool_t const * tpool ) {
  return ((fd_tpool_private_worker_t *)tpool)-1;
}

/* fd_tpool_private_worker returns a pointer in the local address space
   of the first element of the tpool's worker array. */

FD_FN_CONST static inline fd_tpool_private_worker_t **
fd_tpool_private_worker( fd_tpool_t const * tpool ) {
  return (fd_tpool_private_worker_t **)(tpool+1);
}

FD_PROTOTYPES_END

/* End of private APIs ************************************************/

/* FD_TPOOL_{ALIGN,FOOTPRINT} return the alignment and footprint
   required for a memory region to be used as a tpool.  ALIGN will a
   integer power of two of at most 4096 and FOOTPRINT will be a multiple
   of ALIGN.  worker_max is assumed to be valid (e.g. in
   [1,FD_TILE_MAX].  These are provided to facilitate compile time
   construction and for consistency with other constructors.  (FIXME:
   consider using FD_LAYOUT here.) */

#define FD_TPOOL_ALIGN                   (128UL)
#define FD_TPOOL_FOOTPRINT( worker_max ) ( ( sizeof(fd_tpool_private_worker_t)                         /* worker0 sentinel */ \
                                           + sizeof(fd_tpool_t) +                                      /* tpool header     */ \
                                           + ((ulong)(worker_max))*sizeof(fd_tpool_private_worker_t *) /* worker array     */ \
                                           + FD_TPOOL_ALIGN-1UL ) & (~(FD_TPOOL_ALIGN-1UL)) )

/* FD_TPOOL_WORKER_SCRATCH_DEPTH is the maximum number of scratch
   frames a worker thread scratch region can have. */

#define FD_TPOOL_WORKER_SCRATCH_DEPTH (128UL)

FD_PROTOTYPES_BEGIN

/* fd_tpool_align returns FD_TPOOL_ALIGN.  fd_tpool_footprint returns
   FD_TPOOL_FOOTPRINT( worker_max ) if worker_max is in [1,FD_TILE_MAX]
   or 0 otherwise. */

FD_FN_CONST ulong fd_tpool_align( void );
FD_FN_CONST ulong fd_tpool_footprint( ulong worker_max );

/* fd_tpool_init formats a memory region mem with the appropriate
   alignment and footprint as a thread pool that can support up to
   worker_max worker threads.  worker max must be in [1,FD_TILE_MAX].
   Returns a handle for the tpool (this is not a simple cast of mem) on
   success and NULL on failure (logs details).  On a success return,
   worker 0 will already exist.  Many threads can temporarily assume the
   identity of worker 0 as the situation merits.  Worker 0 is typically
   the thread that starts dispatches to other worker threads in an
   operation and can also flexibly participates in the tpool in bulk
   operations.  This uses init/fini semantics instead of
   new/join/leave/delete semantics because thread pools aren't
   meaningfully sharable between processes / thread groups. */

fd_tpool_t *
fd_tpool_init( void * mem,
               ulong  worker_max );

/* fd_tpool_fini pops all worker threads pushed into the tpool and
   unformats the underlying memory region.  This should be called at
   most once by a thread that was not pushed into the tpool (e.g. a
   "worker 0" thread) and no other operations on the tpool should be in
   progress when this is called or done after this is called.  Returns
   the memory region used by the tpool on success (this is not a simple
   cast of mem) and NULL on failure (logs details). */

void *
fd_tpool_fini( fd_tpool_t * tpool );

/* fd_tpool_worker_push pushes tile tile_idx into the tpool.  tile_idx
   0, the calling tile, and tiles that have already been pushed into the
   tpool cannot be pushed.  Further, tile_idx should be idle and no
   other tile operations should be done it while it is a part of the
   tpool.

   If scratch_sz is non-zero, this will assume that tile tile_idx
   currently has no scratch memory attached to it and configure tile
   tile_idx to use the memory with appropriate alignment whose first byte
   in the local address space is scratch and that has scratch_sz bytes
   total for its scratch memory.  Otherwise, it will use whatever
   scratch memory has already been configured for tile_idx (or leave it
   unattached to a scratch memory).  Scratch memory used by a tile
   should not be used for any other purposes while the tile is part of
   the tpool.

   IMPORTANT SAFETY TIP! Since worker 0 identity is flexible, it is the
   caller's responsibility to attach/detach the scratch memory as
   appropriate for a "worker 0 thread" that is not pushed into the
   tpool.

   Returns tpool on success (tile tile_idx is part of the tpool and will
   be considered as executing from tile's point of view while a member
   of the tpool ... no tile operations can or should be done on it while
   it is part of the tpool) and NULL on failure (logs details).  Reasons
   for failure include NULL tpool, bad tile_idx, tile was not idle, bad
   scratch region specified, etc).

   No other operations on tpool should be in process when this is called
   or started while this is running. */

fd_tpool_t *
fd_tpool_worker_push( fd_tpool_t * tpool,
                      ulong        tile_idx,
                      void *       scratch,
                      ulong        scratch_sz );

/* fd_tpool_worker_pop pops the most recently pushed tpool worker
   thread.  If the tile is attached to some scratch memory as part of
   its push, it will be detached from it here.

   Returns tpool on success (the tile is no longer part of the tpool and
   considered idle from tile's POV and can be used for other purposes)
   and NULL on failure (logs details).  Reasons for failure include NULL
   tpool, bad tile_idx, tile was not idle, bad scratch region, etc).

   No other operations on the tpool should be in process when this is
   called or started while this is running. */

fd_tpool_t *
fd_tpool_worker_pop( fd_tpool_t * tpool );

/* Accessors.  As these are used in high performance contexts, these do
   no input argument checking.  Specifically, they assume tpool is valid
   and (if applicable) worker_idx in [0,worker_cnt).  worker 0 is
   special.  The tile_idx/scratch/scratch_sz for worker 0 are always
   returned as 0/NULL/0 here. */

FD_FN_PURE static inline ulong fd_tpool_worker_cnt( fd_tpool_t const * tpool ) { return tpool->worker_cnt; }
FD_FN_PURE static inline ulong fd_tpool_worker_max( fd_tpool_t const * tpool ) { return tpool->worker_max; }

FD_FN_PURE static inline ulong
fd_tpool_worker_tile_idx( fd_tpool_t const * tpool,
                          ulong              worker_idx ) {
  return (ulong)fd_tpool_private_worker( tpool )[ worker_idx ]->tile_idx;
}

FD_FN_PURE static inline void *
fd_tpool_worker_scratch( fd_tpool_t const * tpool,
                         ulong              worker_idx ) {
  return fd_tpool_private_worker( tpool )[ worker_idx ]->scratch;
}

FD_FN_PURE static inline ulong
fd_tpool_worker_scratch_sz( fd_tpool_t const * tpool,
                            ulong              worker_idx ) {
  return fd_tpool_private_worker( tpool )[ worker_idx ]->scratch_sz;
}

/* fd_tpool_worker_state atomically observes the state of tpool thread
   worker_idx at some point in time between when the call was made and
   the call returns.  As this is used in high performance contexts, does
   no input argument checking.  Specifically, assumes tpool is valid and
   worker_idx is in [0,worker_cnt).  Return value will be a
   FD_TPOOL_WORKER_STATE value (and, in correct usage, either IDLE or
   EXEC).  worker 0 is special.  The state here will always be EXEC. */

static inline int
fd_tpool_worker_state( fd_tpool_t const * tpool,
                       ulong              worker_idx ) {
  return FD_VOLATILE_CONST( fd_tpool_private_worker( tpool )[ worker_idx ]->state );
}

/* fd_tpool_exec calls

     task( task_tpool,
           task_t0, task_t1,
           task_args,
           task_reduce, task_stride,
           task_l0, task_l1,
           task_m0, task_m1,
           task_n0, task_n1 );

   on tpool thread worker_idx.  This will run concurrently with the
   caller.  Uncaught exceptions in task will be logged by the remote
   thread (in principle, that is assuming the uncaught exception did not
   leave the application an unstable state, thread worker_idx will still
   be usable for additional fd_tpool_exec).  As this is used in high
   performance contexts, does no input argument checking.  Specifically,
   assumes tpool is valid, worker_idx in (0,worker_cnt) (yes, open on
   both ends), caller is not tpool thread worker_idx, task is valid.
   worker_idx 0 is special and is considered to always be in the EXEC
   state so we cannot call exec on it. */

static inline void
fd_tpool_exec( fd_tpool_t *    tpool,       ulong worker_idx,
               fd_tpool_task_t task,
               void *          task_tpool,
               ulong           task_t0,     ulong task_t1,
               void *          task_args,
               void *          task_reduce, ulong task_stride,
               ulong           task_l0,     ulong task_l1,
               ulong           task_m0,     ulong task_m1,
               ulong           task_n0,     ulong task_n1 ) {
  fd_tpool_private_worker_t * worker = fd_tpool_private_worker( tpool )[ worker_idx ];
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker->task        ) = task;       
  FD_VOLATILE( worker->task_tpool  ) = task_tpool;
  FD_VOLATILE( worker->task_t0     ) = task_t0;     FD_VOLATILE( worker->task_t1     ) = task_t1;
  FD_VOLATILE( worker->task_args   ) = task_args;
  FD_VOLATILE( worker->task_reduce ) = task_reduce; FD_VOLATILE( worker->task_stride ) = task_stride;
  FD_VOLATILE( worker->task_l0     ) = task_l0;     FD_VOLATILE( worker->task_l1     ) = task_l1;
  FD_VOLATILE( worker->task_m0     ) = task_m0;     FD_VOLATILE( worker->task_m1     ) = task_m1;
  FD_VOLATILE( worker->task_n0     ) = task_n0;     FD_VOLATILE( worker->task_n1     ) = task_n1;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker->state ) = FD_TPOOL_WORKER_STATE_EXEC;
  FD_COMPILER_MFENCE();
}

/* fd_tpool_wait waits for the tpool thread worker_idx to leave the
   EXEC state.  As this is used in high performance contexts, does no
   input argument checking.  Specifically, assumes tpool is valid,
   worker_idx in (0,worker_cnt) (yes, open on both ends) and caller is
   not tpool thread worker_idx.  worker_idx 0 is considered to always be
   in an exec state so we cannot call wait on it. */

static inline void
fd_tpool_wait( fd_tpool_t const * tpool,
               ulong              worker_idx ) {
  int volatile * vstate = (int volatile *)&(fd_tpool_private_worker( tpool )[ worker_idx ]->state);
  int            state;
  for(;;) {
    state = *vstate;
    if( FD_LIKELY( state!=FD_TPOOL_WORKER_STATE_EXEC ) ) break;
    FD_SPIN_PAUSE();
  }
}

/* Assuming the tasks can be executed safely in any order and/or
   concurrently, fd_tpool_exec_all_rrobin, fd_tpool_exec_all_block and
   fd_tpool_exec_all_taskq are functionally equivalent to:

     for( ulong l=l0; l<l1; l++ )
       task( task_tpool,t0,t1, task_args,task_reduce,task_stride, task_l0,task_l1, l,l+1, t,t+1 );

   where t indicates to which tpool worker thread idx the particular
   task was assigned (and thus t is in [t0,t1), where thread t0 is the
   thread that did the dispatch).  The rrobin variant stripes individual
   tasks deterministically over worker threads (e.g. worker thread t
   does tasks (t-t0)+0*(t1-t0),(t-t0)+1*(t1-t0),(t-t0)+2*(t1-t0), ...
   The block variant blocks individual tasks over worker threads.
   
   The taskq variant requires FD_HAS_ATOMIC support and assigns tasks to
   threads dynamically.  Practically, this is only useful if there are a
   huge number of tasks to execute relative to the number of threads,
   the tasks to execute have highly non-uniform sizes, the cost to
   execute a task is much much greater than the cost of a single atomic
   memory operation, and thread-core affinity doesn't impact the time to
   execute a task ... conditions that, in total, are met far less
   frequently than most developers expect.)

   fd_tpool_exec_all_batch is functionally equivalent to:

     for( ulong t=t0; t<t1; t++ ) {
       ulong batch_task_l0;
       ulong batch_task_l1;
       FD_TPOOL_PARTITION( task_l0,task_l1,1, t-t0,t1-t0, batch_task_l0,batch_task_l1 );
       task( task_tpool,t0,t1, task_args,task_reduce,task_stride, task_l0,task_l1, batch_task_l0,batch_task_l1, t,t+1 );
     }

   The batch assigned to a thread will be the same tasks as those
   assigned to a thread by fd_tpool_exec_all_block.  The difference is
   that fd_tpool_exec_all_batch effectively merges all the calls to task
   that fd_tpool_exec_all_block would make in a block into a single call
   per thread.

   fd_tpool_exec_all_raw is functionally equivalent to:

     for( ulong t=t0; t<t1; t++ )
       task( task_tpool,t0,t1, task_args,task_reduce,task_stride, task_l0,task_l1, task_l0,task_l1, t,t+1 );

   This allows the caller to use their own partitioning strategies with
   minimal overhead.

   All these are executed thread parallel using the calling thread and
   tpool worker threads (t0,t1) (yes, open on both ends ... the caller
   masquerades as worker thread t0 if isn't actually worker thread t0 as
   far as exec_all is concerned ... see safety tip above about scratch).
   The caller should not be any of worker threads (t0,t1) and worker
   threads (t0,t1) should be idle on entry and should not be dispatched
   to while an exec_all is running.

   As such, in all of these, a task knows automatically which worker
   thread is processing this (t), the range of tasks assigned to it
   (e.g. [batch_task_l0,batch_task_l1)), the entire range of workers
   [t0,t1) in use, the entire range of tasks [task_l0,task_l1) as well
   as the original values for task_tpool, task_args, task_reduce,
   task_stride.

   As this is used in high performance contexts, this does no input
   argument checking.  Specifically, it assumes tpool is valid, task is
   valid, 0<=t0<t1<=worker_cnt, l0<=l1. */

#define FD_TPOOL_EXEC_ALL_DECL(style)                                                                          \
void                                                                                                           \
fd_tpool_private_exec_all_##style##_node( void * _node_tpool,                                                  \
                                          ulong  node_t0, ulong node_t1,                                       \
                                          void * args,                                                         \
                                          void * reduce,  ulong stride,                                        \
                                          ulong  l0,      ulong l1,                                            \
                                          ulong  _task,   ulong _tpool,                                        \
                                          ulong  t0,      ulong t1 );                                          \
                                                                                                               \
static inline void                                                                                             \
fd_tpool_exec_all_##style( fd_tpool_t *    tpool,                                                              \
                           ulong           t0,          ulong t1,                                              \
                           fd_tpool_task_t task,                                                               \
                           void *          task_tpool,                                                         \
                           void *          task_args,                                                          \
                           void *          task_reduce, ulong task_stride,                                     \
                           ulong           task_l0,     ulong task_l1 ) {                                      \
  fd_tpool_private_exec_all_##style##_node( tpool, t0,t1, task_args, task_reduce,task_stride, task_l0,task_l1, \
                                            (ulong)task,(ulong)task_tpool, t0,t1 );                            \
}

FD_TPOOL_EXEC_ALL_DECL(rrobin)
FD_TPOOL_EXEC_ALL_DECL(block)
FD_TPOOL_EXEC_ALL_DECL(batch)
FD_TPOOL_EXEC_ALL_DECL(raw)

#if FD_HAS_ATOMIC
void
fd_tpool_private_exec_all_taskq_node( void * _node_tpool,
                                      ulong  node_t0, ulong node_t1,
                                      void * args,
                                      void * reduce,  ulong stride,
                                      ulong  l0,      ulong l1,
                                      ulong  _task,   ulong _l_next,
                                      ulong  t0,      ulong t1 );

static inline void
fd_tpool_exec_all_taskq( fd_tpool_t *    tpool,
                         ulong           t0,          ulong t1,
                         fd_tpool_task_t task,
                         void *          task_tpool,
                         void *          task_args,
                         void *          task_reduce, ulong task_stride,
                         ulong           task_l0,     ulong task_l1 ) {
  ulong l_next[16] __attribute((aligned(128)));
  FD_VOLATILE( l_next[0] ) = task_l0;
  FD_VOLATILE( l_next[1] ) = (ulong)task_tpool;
  FD_COMPILER_MFENCE();
  fd_tpool_private_exec_all_taskq_node( tpool, t0,t1, task_args, task_reduce,task_stride, task_l0,task_l1,
                                        (ulong)task,(ulong)l_next, t0,t1 );
}
#endif

#undef FD_TPOOL_EXEC_ALL_DECL

/* fd_tpool_worker_state_cstr converts an FD_TPOOL_WORKER_STATE_* code
   into a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_tpool_worker_state_cstr( int state );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_tpool_fd_tpool_h */
