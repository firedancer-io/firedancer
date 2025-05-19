/* DO NOT INCLUDE DIRECTLY, USE fd_tpool.h */

/* FD_MAP_REDUCE supports writing CUDA-ish kernels.  These have faster
   dispatch than CUDA (or other threading libraries) and they don't
   require any data choreography to shuffle data between the CPU and
   GPU.  An ultra high performance deterministic parallelized tree
   dispatch is used for good scaling, cache temporal locality and cache
   spatial locality.  Example usage:

     In a header file:

       // my_hist_op uses the caller and tpool threads
       // (tpool_t0,tpool_t1) to compute:
       //
       //   long h[4];
       //   for( long j=0L; j<4L; j++ ) h[j] = 0L;
       //   for( long i=i0; i<i1; i++ ) {
       //     long j = my_map_op( x[i] );
       //     h[j]++;
       //   }
       //
       // where x is a pointer to a my_ele_t array.  Tpool threads
       // (tpool_t0,tpool_t1) are assumed to be idle and i1-i0 is
       // assumed to be in [0,LONG_MAX/FD_TILE_MAX]

       FD_MAP_REDUCE_PROTO( my_hist_op );

     In a source file that uses my_hist_op:

       long h[4]; // should have appropriate alignment

       FD_MAP_REDUCE( my_hist_op, tpool,t0,t1, i0,i1, h, x );

     In the source file that implements my_hist_op:

       FD_MAP_REDUCE_BEGIN( my_hist_op, 1L, 0UL, sizeof(long), 4L ) {

         ... At this point:

             - The long range [block_i0,block_i1) give the elements for
               this thread to process.  Other threads will process other
               approximately equally sized disjoint ranges in parallel.
               The long block_cnt gives block_i1 - block_i0.  The long
               block_thresh gives the parameter used to optimize thread
               dispatch (1L in this example).  Element ranges with more
               than this number of elements are considered worth
               processing with more than one thread if available.
               block_thresh should be at least 1 and can be a run time
               evaluated expression.  This can also be used to make sure
               different kernel dispatches consistently partition
               elements such that there is good cache reuse between
               different thread parallel kernels.

             - tpool is a handle of this thread's tpool and ulong
               range [tpool_t0,tpool_t1) give the threads available to
               process this block.  This thread should be considered
               tpool_t0 and threads (tpool_t0,tpool_t1) are idle.  Even
               if (tpool_t0,tpool_t1) is not empty, it is almost
               certainly optimal to just have this thread process all
               elements in the block single threaded.  That is, when
               processing many elements (i.e. >> block_thresh*(t1-t0)),
               (tpool_t0,tpool_t1) will be empty but, when processing a
               small numbers of elements, FD_MAP_REDUCE already
               concluded there were too few elements to dispatch to
               (tpool_t0,tpool_t1).

             - The ulong arg_cnt gives the number of arguments passed by
               the caller (2 in this example).  arg_cnt is in [0,26].

             - ulongs arg[i] for i in [1,arg_cnt) give all but the first
               user arguments passed to FD_MAP_REDUCE (cast to a ulong)
               in order.  If reduce_cnt==0 and arg_cnt>0, arg[0] gives
               the initial user argument passed to FD_MAP_REDUCE (cast
               to a ulong).

             - If reduce_cnt>0 (as it is in this example), arg[0] gives
               the unique uninitialized scratch region where this thread
               should save its local reduction.  This region will have
               an alignment of reduce_align byte where reduce_align is
               an integer power of 2.  In this example, the ulong
               reduce_align / ulong reduce_sz / long reduce_cnt were
               specified via the 0UL / sizeof(long) / 4L above.  A zero
               value for reduce_align indicates to use a HPC thread
               friendly default of 128.  Note that the combination of
               arg_cnt==0 and reduce_cnt>0 is a little silly but will
               still work.

             - The names _reduce_top, _reduce_footprint, _reduce_stack,
               _r1 are reserved.

             IMPORTANT SAFETY TIP!  REDUCE_ALIGN / REDUCE_CNT /
             REDUCE_SZ SHOULD BE ALLOCA FRIENDLY AMOUNTS (<<~1 MIB
             TYPICALLY).  DO NOT ASSUME THE REDUCTION REGION HAS A SIZE
             OF _REDUCE_FOOTPRINT (THE OUTPUT REGION PASSED BY THE USER
             MIGHT ONLY HAVE A SIZE OF REDUCE_CNT*REDUCE_SZ EVEN IF IT
             HAS THE CORRECT ALIGNMENT).

             IMPORTANT SAFETY TIP!  DO NOT RETURN FROM THIS BLOCK.  IF
             ENDING A BLOCK EARLY, USE BREAK.

             IMPORTANT SAFETY TIP!  DO NOT MODIFY BLOCK_I1 OR TPOOL_T1,
             IN THIS BLOCK.  IT WILL CONFUSE THE REDUCTION.

         long           * restrict h = (long           *)arg[0];
         my_ele_t const * restrict x = (my_ele_t const *)arg[1];

         for( long j=0L; j<4L; j++ ) h[j] = 0UL;

         for( long i=block_i0; i<block_i1; i++ ) {
           long j = my_map_op( x[i] );
           h[j]++;
         }

       } FD_MAP_END {

         ... At this point, the environment is as described above with
             the following differences:

             - There is at least one thread in the ulong range
               [tpool_t0,tpool_ts) and one thread in the ulong range
               [tpool_ts,tpool_t1).  This should be considered thread t0
               and threads (tpool_t0,tpool_t1) are idle.

             - On entry, arg[0] points to the partial reduction (cast to
               a ulong) computed for elements in the long range
               [block_i0,block_is).  This was computed by threads
               [tpool_t0,tpool_ts).  Similarly, _r1 points to the
               partial reduction (cast to a ulong) for elements in the
               long range [block_is,block_i1).  This was computed by
               threads [tpool_ts,tpool_t1).  These regions have the
               alignment and footprint specified for the FD_MAP_REDUCE.

             - On exit, the contents in _r1 should have been reduced
               into the contents of arg[0] such that arg[0] contains to
               the partial reduction of the elements in
               [block_i0,block_i1).  Threads [tpool_t0,tpool_t1) are
               available to compute this reduction.  _r1 should not be
               modified but the contents in _r1 are free to clobber.

             IMPORTANT SAFETY TIP!  While this reduction is often
             theoretically parallelizable and threads
             (tpool_t0,tpool_t1) are available here for this,
             parallelization of this is usually counterproductive if the
             amount to reduce is small, the reduction operation is cheap
             and/or the arrays to reduce have poor spatial locality due
             to the mapping phase above.

         long       * restrict h0 = (long       *)arg[0];
         long const * restrict h1 = (long const *)_r1;

         for( long j=0L; j<4L; j++ ) h0[j] += h1[j];

       } FD_REDUCE_END

  FD_MAP_REDUCE operations act as a compiler memory fence. */

#define FD_MAP_REDUCE_PROTO(op) \
void                            \
op( fd_tpool_t *  tpool,        \
    ulong         tpool_t0,     \
    ulong         arg_cnt,      \
    ulong const * arg )

/* Note: we don't use fd_alloca here because of current compiler
   limitations where gcc doesn't recognize reduce_align is a compile
   time constant (fd_alloc turns into __built_alloca_with_align under
   the hood and that builtin requires align to be compile time ... which
   is fine ... when the compiler can recognize it.  Use of dynamic
   allocation on the stack does imply this requires FD_HAS_ALLOCA. */

#define FD_MAP_REDUCE_BEGIN(op,BLOCK_THRESH,REDUCE_ALIGN,REDUCE_SZ,REDUCE_CNT)                                 \
void                                                                                                           \
op( fd_tpool_t *  tpool,                                                                                       \
    ulong         tpool_t0,                                                                                    \
    ulong         arg_cnt,  /* at least 3 */                                                                   \
    ulong const * arg ) {                                                                                      \
  FD_COMPILER_MFENCE(); /* guarantees memory fence even if tpool_cnt==1 */                                     \
  long  block_thresh      = (BLOCK_THRESH);                                                                    \
  ulong reduce_align      = (REDUCE_ALIGN); reduce_align = fd_ulong_if( !!reduce_align, reduce_align, 128UL ); \
  ulong reduce_sz         = (REDUCE_SZ);                                                                       \
  long  reduce_cnt        = (REDUCE_CNT);                                                                      \
  ulong tpool_t1          =       arg[0];                                                                      \
  long  block_i0          = (long)arg[1];                                                                      \
  long  block_i1          = (long)arg[2];                                                                      \
  long  block_cnt;                                                                                             \
  ulong _reduce_top       = 0UL;                                                                               \
  ulong _reduce_footprint = fd_ulong_align_up( reduce_sz*(ulong)reduce_cnt, reduce_align );                    \
  struct { ulong t1; long i1; } _reduce_stack[ 11 ]; /* Assumes TILE_MAX<2048 (yes strictly less) */           \
  ulong _r1 = !reduce_cnt ? 0UL :                                                                              \
    fd_ulong_align_up( (ulong)__builtin_alloca( _reduce_footprint*11UL + reduce_align-1UL ), reduce_align );   \
  for(;;) {                                                                                                    \
    ulong tpool_cnt   = tpool_t1 - tpool_t0;                                                                   \
    /**/  block_cnt   = block_i1 - block_i0;                                                                   \
    if( FD_LIKELY( (tpool_cnt<=1UL) | (block_cnt<=block_thresh) ) ) break;                                     \
    ulong tpool_left  = fd_tpool_private_split( tpool_cnt );                                                   \
    ulong tpool_right = tpool_cnt - tpool_left;                                                                \
    ulong tpool_ts    = tpool_t0 + tpool_left;                                                                 \
    long  block_is    = block_i1 - (long)((tpool_right*(ulong)block_cnt)/tpool_cnt); /* No overfl */           \
    fd_tpool_private_worker_t * worker = fd_tpool_private_worker( tpool )[ tpool_ts ];                         \
    uint  seq0        = worker->seq0 + 1U;                                                                     \
    worker->arg_cnt   = (uint)arg_cnt;                                                                         \
    worker->task      = (ulong)(op);                                                                           \
    worker->arg[0]    =        tpool_t1;                                                                       \
    worker->arg[1]    = (ulong)block_is;                                                                       \
    worker->arg[2]    = (ulong)block_i1;                                                                       \
    if( reduce_cnt ) worker->arg[3] = _r1;                                                                     \
    for( ulong idx=reduce_cnt ? 4UL : 3UL; idx<arg_cnt; idx++ ) worker->arg[idx] = arg[idx];                   \
    FD_COMPILER_MFENCE();                                                                                      \
    worker->seq0      = seq0;                                                                                  \
    FD_COMPILER_MFENCE();                                                                                      \
    if( FD_UNLIKELY( tpool->opt & FD_TPOOL_OPT_SLEEP ) ) fd_tpool_private_wake( worker );                      \
    _reduce_stack[ _reduce_top ].t1 = tpool_t1;                                                                \
    _reduce_stack[ _reduce_top ].i1 = block_i1;                                                                \
    _reduce_top++;                                                                                             \
    _r1 += _reduce_footprint;                                                                                  \
    tpool_t1 = tpool_ts;                                                                                       \
    block_i1 = block_is;                                                                                       \
  }                                                                                                            \
  arg_cnt -= 3UL;                                                                                              \
  arg     += 3UL;                                                                                              \
  do

#define FD_MAP_END                                            \
  while(0);                                                   \
  while( _reduce_top ) {                                      \
    long  block_is  = block_i1; (void)block_is;               \
    ulong tpool_ts  = tpool_t1;                               \
    /**/  _r1      -= _reduce_footprint;                      \
    /**/  _reduce_top--;                                      \
    /**/  tpool_t1  = (ulong)_reduce_stack[ _reduce_top ].t1; \
    /**/  block_i1  =        _reduce_stack[ _reduce_top ].i1; \
    /**/  block_cnt = block_i1 - block_i0;                    \
    fd_tpool_wait( tpool, tpool_ts );                         \
    do

#define FD_REDUCE_END   \
    while(0);           \
  }                     \
  FD_COMPILER_MFENCE(); \
}

/* FD_FOR_ALL is a special case of FD_MAP_REDUCE when no reduction is
   required (i.e. reduce_align=1, reduce_sz=0, reduce_cnt=0).  Example:

       // my_vec_op uses the caller and tpool threads
       // (tpool_t0,tpool_t1) to compute:
       //
       //   for( long i=i0; i<i1; i++ ) z[i] = my_scalar_op( x[i], y[i] );
       //
       // where x, y and z are pointers to non-overlapping my_ele_t
       // arrays.  Threads (tpool_t0,tpool_t1) are assumed to be idle
       // and (block_i1-block_i0) in [0,LONG_MAX / FD_TILE_MAX].

       FD_FOR_ALL_PROTO( my_vec_op );

     In a source file that uses my_vec_op:

       FD_FOR_ALL( my_vec_op, tpool, t0,t1, i0,i1, x,y,z );

     In the source file that implements my_vec_op:

       FD_FOR_ALL_BEGIN( my_vec_op, 1024L ) {

         my_ele_t const * restrict x = (my_ele_t const *)arg[0];
         my_ele_t const * restrict y = (my_ele_t const *)arg[1];
         my_ele_t       * restrict z = (my_ele_t       *)arg[2];

         for( long i=block_i0; i<block_i1; i++ ) z[i] = my_scalar_op( x[i], y[i] );

       } FD_FOR_ALL_END */

#define FD_FOR_ALL_PROTO                  FD_MAP_REDUCE_PROTO
#define FD_FOR_ALL_BEGIN(op,BLOCK_THRESH) FD_MAP_REDUCE_BEGIN((op),(BLOCK_THRESH),1UL,0UL,0L)
#define FD_FOR_ALL_END                    FD_MAP_END {} FD_REDUCE_END
#define FD_FOR_ALL                        FD_MAP_REDUCE

/* THIS CODE IS AUTOGENERATED; DO NOT INCLUDE DIRECTLY */

static inline void
fd_map_reduce_private_0( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1 ) {
  ulong arg[3]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1;
  task( tpool, t0, 3UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_0(task,tpool,t0,t1,i0,i1) fd_map_reduce_private_0( (task), (tpool), (t0), (t1), (i0), (i1) )

static inline void
fd_map_reduce_private_1( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0 ) {
  ulong arg[4]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0;
  task( tpool, t0, 4UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_1(task,tpool,t0,t1,i0,i1,a0) fd_map_reduce_private_1( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0) )

static inline void
fd_map_reduce_private_2( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1 ) {
  ulong arg[5]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1;
  task( tpool, t0, 5UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_2(task,tpool,t0,t1,i0,i1,a0,a1) fd_map_reduce_private_2( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1) )

static inline void
fd_map_reduce_private_3( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2 ) {
  ulong arg[6]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2;
  task( tpool, t0, 6UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_3(task,tpool,t0,t1,i0,i1,a0,a1,a2) fd_map_reduce_private_3( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2) )

static inline void
fd_map_reduce_private_4( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3 ) {
  ulong arg[7]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3;
  task( tpool, t0, 7UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_4(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3) fd_map_reduce_private_4( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3) )

static inline void
fd_map_reduce_private_5( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4 ) {
  ulong arg[8]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4;
  task( tpool, t0, 8UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_5(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4) fd_map_reduce_private_5( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4) )

static inline void
fd_map_reduce_private_6( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5 ) {
  ulong arg[9]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5;
  task( tpool, t0, 9UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_6(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5) fd_map_reduce_private_6( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5) )

static inline void
fd_map_reduce_private_7( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6 ) {
  ulong arg[10]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6;
  task( tpool, t0, 10UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_7(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6) fd_map_reduce_private_7( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6) )

static inline void
fd_map_reduce_private_8( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7 ) {
  ulong arg[11]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7;
  task( tpool, t0, 11UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_8(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7) fd_map_reduce_private_8( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7) )

static inline void
fd_map_reduce_private_9( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8 ) {
  ulong arg[12]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8;
  task( tpool, t0, 12UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_9(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8) fd_map_reduce_private_9( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8) )

static inline void
fd_map_reduce_private_10( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9 ) {
  ulong arg[13]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9;
  task( tpool, t0, 13UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_10(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9) fd_map_reduce_private_10( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9) )

static inline void
fd_map_reduce_private_11( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10 ) {
  ulong arg[14]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10;
  task( tpool, t0, 14UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_11(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10) fd_map_reduce_private_11( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10) )

static inline void
fd_map_reduce_private_12( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11 ) {
  ulong arg[15]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11;
  task( tpool, t0, 15UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_12(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11) fd_map_reduce_private_12( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11) )

static inline void
fd_map_reduce_private_13( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12 ) {
  ulong arg[16]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12;
  task( tpool, t0, 16UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_13(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12) fd_map_reduce_private_13( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12) )

static inline void
fd_map_reduce_private_14( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13 ) {
  ulong arg[17]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13;
  task( tpool, t0, 17UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_14(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13) fd_map_reduce_private_14( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13) )

static inline void
fd_map_reduce_private_15( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14 ) {
  ulong arg[18]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14;
  task( tpool, t0, 18UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_15(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14) fd_map_reduce_private_15( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14) )

static inline void
fd_map_reduce_private_16( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15 ) {
  ulong arg[19]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15;
  task( tpool, t0, 19UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_16(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15) fd_map_reduce_private_16( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15) )

static inline void
fd_map_reduce_private_17( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16 ) {
  ulong arg[20]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16;
  task( tpool, t0, 20UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_17(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16) fd_map_reduce_private_17( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16) )

static inline void
fd_map_reduce_private_18( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17 ) {
  ulong arg[21]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17;
  task( tpool, t0, 21UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_18(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17) fd_map_reduce_private_18( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17) )

static inline void
fd_map_reduce_private_19( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18 ) {
  ulong arg[22]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18;
  task( tpool, t0, 22UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_19(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18) fd_map_reduce_private_19( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18) )

static inline void
fd_map_reduce_private_20( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19 ) {
  ulong arg[23]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19;
  task( tpool, t0, 23UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_20(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19) fd_map_reduce_private_20( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19) )

static inline void
fd_map_reduce_private_21( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20 ) {
  ulong arg[24]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20;
  task( tpool, t0, 24UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_21(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20) fd_map_reduce_private_21( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20) )

static inline void
fd_map_reduce_private_22( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20, ulong a21 ) {
  ulong arg[25]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20; arg[24] = a21;
  task( tpool, t0, 25UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_22(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21) fd_map_reduce_private_22( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20), (ulong)(a21) )

static inline void
fd_map_reduce_private_23( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20, ulong a21, ulong a22 ) {
  ulong arg[26]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20; arg[24] = a21; arg[25] = a22;
  task( tpool, t0, 26UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_23(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22) fd_map_reduce_private_23( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20), (ulong)(a21), (ulong)(a22) )

static inline void
fd_map_reduce_private_24( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20, ulong a21, ulong a22, ulong a23 ) {
  ulong arg[27]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20; arg[24] = a21; arg[25] = a22; arg[26] = a23;
  task( tpool, t0, 27UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_24(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22,a23) fd_map_reduce_private_24( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20), (ulong)(a21), (ulong)(a22), (ulong)(a23) )

static inline void
fd_map_reduce_private_25( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20, ulong a21, ulong a22, ulong a23, ulong a24 ) {
  ulong arg[28]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20; arg[24] = a21; arg[25] = a22; arg[26] = a23; arg[27] = a24;
  task( tpool, t0, 28UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_25(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22,a23,a24) fd_map_reduce_private_25( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20), (ulong)(a21), (ulong)(a22), (ulong)(a23), (ulong)(a24) )

static inline void
fd_map_reduce_private_26( fd_tpool_task_v2_t task, fd_tpool_t * tpool, ulong t0, ulong t1, long i0, long i1, ulong a0, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6, ulong a7, ulong a8, ulong a9, ulong a10, ulong a11, ulong a12, ulong a13, ulong a14, ulong a15, ulong a16, ulong a17, ulong a18, ulong a19, ulong a20, ulong a21, ulong a22, ulong a23, ulong a24, ulong a25 ) {
  ulong arg[29]; arg[0] = t1; arg[1] = (ulong)i0; arg[2] = (ulong)i1; arg[3] = a0; arg[4] = a1; arg[5] = a2; arg[6] = a3; arg[7] = a4; arg[8] = a5; arg[9] = a6; arg[10] = a7; arg[11] = a8; arg[12] = a9; arg[13] = a10; arg[14] = a11; arg[15] = a12; arg[16] = a13; arg[17] = a14; arg[18] = a15; arg[19] = a16; arg[20] = a17; arg[21] = a18; arg[22] = a19; arg[23] = a20; arg[24] = a21; arg[25] = a22; arg[26] = a23; arg[27] = a24; arg[28] = a25;
  task( tpool, t0, 29UL, arg );
}

#define FD_MAP_REDUCE_PRIVATE_26(task,tpool,t0,t1,i0,i1,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22,a23,a24,a25) fd_map_reduce_private_26( (task), (tpool), (t0), (t1), (i0), (i1), (ulong)(a0), (ulong)(a1), (ulong)(a2), (ulong)(a3), (ulong)(a4), (ulong)(a5), (ulong)(a6), (ulong)(a7), (ulong)(a8), (ulong)(a9), (ulong)(a10), (ulong)(a11), (ulong)(a12), (ulong)(a13), (ulong)(a14), (ulong)(a15), (ulong)(a16), (ulong)(a17), (ulong)(a18), (ulong)(a19), (ulong)(a20), (ulong)(a21), (ulong)(a22), (ulong)(a23), (ulong)(a24), (ulong)(a25) )

#define FD_MAP_REDUCE_PRIVATE_F(...) too_few_arguments_passed_to_FD_MAP_REDUCE
#define FD_MAP_REDUCE(...)          FD_EXPAND_THEN_CONCAT2(FD_MAP_REDUCE_PRIVATE_,FD_VA_ARGS_SELECT(__VA_ARGS__,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,F,F,F,F,F))(__VA_ARGS__)
