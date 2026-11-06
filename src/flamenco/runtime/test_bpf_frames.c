#include "fd_bpf_frames.c"
#include <pthread.h>
#include <stdlib.h>

#define DEPTH FD_MAX_INSTRUCTION_STACK_DEPTH
#define LOCAL (2UL)
#define HELD  FD_BPF_FRAMES_HELD_CNT( LOCAL )
#define FULL  BPF_LOADER_SERIALIZATION_FOOTPRINT
#define FRAME sizeof(fd_bpf_frame_t)
#define PAGE  FD_BPF_FRAMES_ALIGN

/* Frames are only addressed, never touched beyond their pool links, so
   the memory comes from aligned_alloc and stays mostly virtual. */

static void *
pool_new( ulong frame_cnt,
          ulong joiner_cnt_max,
          ulong local_cnt ) {
  void * mem = aligned_alloc( fd_bpf_frames_shmem_align(), fd_bpf_frames_shmem_footprint( frame_cnt, joiner_cnt_max, local_cnt ) );
  FD_TEST( mem );
  FD_TEST( fd_bpf_frames_shmem_new( mem, frame_cnt, joiner_cnt_max, local_cnt )==mem );
  return mem;
}

static void
test_new( void ) {
  FD_TEST( !fd_bpf_frames_shmem_footprint( HELD,                      1UL,                       DEPTH+1UL ) );
  FD_TEST( !fd_bpf_frames_shmem_footprint( HELD-1UL,                  1UL,                       LOCAL     ) );
  FD_TEST( !fd_bpf_frames_shmem_footprint( FD_BPF_FRAMES_CNT_MAX+1UL, 1UL,                       LOCAL     ) );
  FD_TEST( !fd_bpf_frames_shmem_footprint( HELD,                      FD_BPF_FRAMES_CNT_MAX+1UL, LOCAL     ) );
  FD_TEST( !fd_bpf_frames_shmem_footprint( FD_BPF_FRAMES_CNT_MAX,     1UL,                       LOCAL     ) );
  FD_TEST( fd_bpf_frames_shmem_footprint( 0UL, 1UL, DEPTH ) );
  FD_TEST( fd_bpf_frames_shmem_footprint( HELD, 2UL, LOCAL )>=(HELD+2UL*LOCAL)*BPF_LOADER_SERIALIZATION_FOOTPRINT );
  FD_TEST( sizeof(fd_bpf_frame_t)>=BPF_LOADER_SERIALIZATION_FOOTPRINT );

  ulong  footprint = fd_bpf_frames_shmem_footprint( HELD, 1UL, LOCAL );
  void * mem       = aligned_alloc( fd_bpf_frames_shmem_align(), footprint );
  FD_TEST( mem );
  FD_TEST( !fd_bpf_frames_shmem_new( NULL,           HELD,     1UL, LOCAL ) );
  FD_TEST( !fd_bpf_frames_shmem_new( (uchar *)mem+1, HELD,     1UL, LOCAL ) );
  FD_TEST( !fd_bpf_frames_shmem_new( mem,            HELD-1UL, 1UL, LOCAL ) );

  /* Joins past joiner_cnt_max fail. */
  fd_bpf_frames_t join[1], extra[1];
  FD_TEST( fd_bpf_frames_shmem_new( mem, HELD, 1UL, LOCAL )==mem );
  FD_TEST( !fd_bpf_frames_join( NULL, mem  ) );
  FD_TEST( !fd_bpf_frames_join( join, NULL ) );
  FD_TEST( fd_bpf_frames_join( join, mem )==join );
  FD_TEST( !fd_bpf_frames_join( extra, mem ) );

  /* Every frame is handed out exactly once, aligned and in bounds,
     starting with the join's local ones. */
  uchar * frame[ HELD+LOCAL+1UL ];
  ulong   got = 0UL;
  while( (frame[ got ] = fd_bpf_frames_try_acquire( join, FULL, 1 )) ) {
    FD_TEST( fd_ulong_is_aligned( (ulong)frame[ got ], FD_BPF_FRAMES_ALIGN ) );
    FD_TEST( (ulong)frame[ got ]>=(ulong)mem && (ulong)frame[ got ]+sizeof(fd_bpf_frame_t)<=(ulong)mem+footprint );
    for( ulong j=0UL; j<got; j++ ) FD_TEST( frame[ got ]!=frame[ j ] );
    got++;
  }
  FD_TEST( got==HELD+LOCAL );
  for( ulong i=0UL; i<LOCAL; i++ ) FD_TEST( frame[ i ]==join->local+i*FRAME );
  for( ulong i=got; i; i-- ) fd_bpf_frames_release( join, frame[ i-1UL ] );
  FD_TEST( !join->local_used && !join->held_cnt );

  /* Releasing a level also frees the local levels above it. */
  frame[ 0 ] = fd_bpf_frames_try_acquire( join, 1UL, 0 );
  frame[ 1 ] = fd_bpf_frames_try_acquire( join, 1UL, 0 );
  FD_TEST( frame[ 1 ]==frame[ 0 ]+PAGE );
  fd_bpf_frames_release( join, frame[ 0 ] );
  FD_TEST( !join->local_used );

  free( mem );
}

/* A single runtime covers its whole stack without waiting, and takes
   its local frames first. */

static void
test_single( void ) {
  fd_bpf_frames_t join[1];
  void * mem = pool_new( HELD, 1UL, LOCAL );
  FD_TEST( fd_bpf_frames_join( join, mem ) );
  for( ulong iter=0UL; iter<2UL; iter++ ) {
    uchar * frame[ DEPTH ];
    for( ulong i=0UL; i<DEPTH; i++ ) {
      frame[ i ] = fd_bpf_frames_try_acquire( join, FULL, 0 );
      FD_TEST( frame[ i ] );
      for( ulong j=0UL; j<i; j++ ) FD_TEST( frame[ i ]!=frame[ j ] );
    }
    for( ulong i=0UL; i<LOCAL; i++ ) FD_TEST( frame[ i ]==join->local+i*FRAME );
    for( ulong i=DEPTH; i; i-- ) fd_bpf_frames_release( join, frame[ i-1UL ] );
  }
  free( mem );
}

/* Walks the pool rules on a minimum size pool, where every shared
   frame is held back.  Each tile has its own join. */

static void
test_pools( void ) {
  fd_bpf_frames_t t1[1], t2[1], t3[1];
  void * mem = pool_new( HELD, 3UL, LOCAL );
  FD_TEST( fd_bpf_frames_join( t1, mem ) && fd_bpf_frames_join( t2, mem ) && fd_bpf_frames_join( t3, mem ) );

  /* Every tile gets its local frames. */
  uchar * a[ DEPTH ];
  uchar * b[ DEPTH ];
  uchar * s[ DEPTH ];
  for( ulong i=0UL; i<LOCAL; i++ ) {
    FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, FULL, 0 ))==t1->local+i*FRAME );
    FD_TEST( (b[ i ] = fd_bpf_frames_try_acquire( t2, FULL, 0 ))==t2->local+i*FRAME );
    FD_TEST( (s[ i ] = fd_bpf_frames_try_acquire( t3, FULL, 0 ))==t3->local+i*FRAME );
  }

  /* Tile 1 becomes owner and gets the rest of its stack, while other
     tiles must leave both reserves. */
  for( ulong i=LOCAL; i<DEPTH; i++ ) FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, FULL, 0 )) );
  FD_TEST( t1->is_owner );
  FD_TEST( !fd_bpf_frames_try_acquire( t2, FULL, 0 ) );

  /* The priority caller still gets the rest of its stack. */
  for( ulong i=LOCAL; i<DEPTH; i++ ) FD_TEST( (s[ i ] = fd_bpf_frames_try_acquire( t3, FULL, 1 )) );
  FD_TEST( !fd_bpf_frames_try_acquire( t3, FULL, 1 ) );
  FD_TEST( !t3->is_owner );

  for( ulong i=0UL; i<DEPTH; i++ ) {
    for( ulong j=0UL; j<LOCAL; j++ ) FD_TEST( a[ i ]!=b[ j ] && s[ i ]!=b[ j ] );
    for( ulong j=0UL; j<DEPTH; j++ ) FD_TEST( a[ i ]!=s[ j ] );
  }

  /* Holding no shared frames releases ownership, then another tile can
     become owner. */
  for( ulong i=DEPTH; i>LOCAL; i-- ) fd_bpf_frames_release( t1, a[ i-1UL ] );
  FD_TEST( !t1->is_owner );
  FD_TEST( (b[ LOCAL ] = fd_bpf_frames_try_acquire( t2, FULL, 0 )) && t2->is_owner );
  FD_TEST( !fd_bpf_frames_try_acquire( t1, FULL, 0 ) );
  fd_bpf_frames_release( t2, b[ LOCAL ] );
  FD_TEST( !t2->is_owner );
  for( ulong i=DEPTH; i>LOCAL; i-- ) fd_bpf_frames_release( t3, s[ i-1UL ] );

  /* Local frames are reused. */
  fd_bpf_frames_release( t1, a[ LOCAL-1UL ] );
  FD_TEST( fd_bpf_frames_try_acquire( t1, FULL, 0 )==a[ LOCAL-1UL ] );
  for( ulong i=LOCAL; i; i-- ) {
    fd_bpf_frames_release( t1, a[ i-1UL ] );
    fd_bpf_frames_release( t2, b[ i-1UL ] );
    fd_bpf_frames_release( t3, s[ i-1UL ] );
  }
  free( mem );
}

/* With no local frames, the owner and the priority caller each still
   get a whole stack. */

static void
test_no_local( void ) {
  fd_bpf_frames_t t1[1], t2[1];
  void * mem = pool_new( FD_BPF_FRAMES_HELD_CNT( 0UL ), 2UL, 0UL );
  FD_TEST( fd_bpf_frames_join( t1, mem ) && fd_bpf_frames_join( t2, mem ) );

  uchar * a[ DEPTH ];
  uchar * b[ DEPTH ];
  for( ulong i=0UL; i<DEPTH; i++ ) FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, 1UL, 0 )) );
  FD_TEST( t1->is_owner );
  for( ulong i=0UL; i<DEPTH; i++ ) FD_TEST( (b[ i ] = fd_bpf_frames_try_acquire( t2, 1UL, 1 )) );

  for( ulong i=DEPTH; i; i-- ) {
    fd_bpf_frames_release( t1, a[ i-1UL ] );
    fd_bpf_frames_release( t2, b[ i-1UL ] );
  }
  free( mem );
}

/* Levels are carved by size from the local frames, a level that does
   not fit takes a shared frame, and a later level that fits is local
   again. */

static void
test_carve( void ) {
  fd_bpf_frames_t join[1];
  void * mem = pool_new( FD_BPF_FRAMES_HELD_CNT( 1UL ), 1UL, 1UL );
  FD_TEST( fd_bpf_frames_join( join, mem ) );
  uchar * l = join->local;

  uchar * a = fd_bpf_frames_try_acquire( join, 0UL,      0 ); FD_TEST( a==l          );
  uchar * b = fd_bpf_frames_try_acquire( join, PAGE+1UL, 0 ); FD_TEST( b==l+PAGE     );
  uchar * c = fd_bpf_frames_try_acquire( join, FULL,     0 ); FD_TEST( c && (ulong)c-(ulong)l>=FRAME && join->held_cnt==1UL );
  uchar * d = fd_bpf_frames_try_acquire( join, PAGE,     0 ); FD_TEST( d==l+3UL*PAGE );
  fd_bpf_frames_release( join, d );
  fd_bpf_frames_release( join, c );
  FD_TEST( !join->held_cnt && !join->is_owner );
  fd_bpf_frames_release( join, b );
  fd_bpf_frames_release( join, a );
  FD_TEST( !join->local_used );

  /* A stack whose first level nearly fills the local frame takes the
     most shared frames, one per later level. */
  uchar * f[ DEPTH ];
  FD_TEST( (f[ 0 ] = fd_bpf_frames_try_acquire( join, FULL-PAGE, 0 ))==l );
  for( ulong i=1UL; i<DEPTH; i++ ) FD_TEST( (f[ i ] = fd_bpf_frames_try_acquire( join, 2UL*PAGE, 0 )) );
  FD_TEST( join->held_cnt==DEPTH-1UL && join->held_cnt==join->reserve_cnt );
  for( ulong i=DEPTH; i; i-- ) fd_bpf_frames_release( join, f[ i-1UL ] );
  FD_TEST( !join->held_cnt && !join->local_used );
  free( mem );
}

/* Stress: threads join while others are already running, then run
   random nested stacks of random sizes and sometimes take an exclusive lock partway
   down, spinning for it while holding frames, and acquire as the
   priority caller while holding it, like the program cache spill lock.
   A deadlock trips the watchdog. */

#define STRESS_THREAD_CNT (12UL)
#define STRESS_LOCAL      (1UL)
#define STRESS_SHARED_CNT FD_BPF_FRAMES_HELD_CNT( STRESS_LOCAL )
#define STRESS_FRAME_CNT  (STRESS_THREAD_CNT*STRESS_LOCAL+STRESS_SHARED_CNT)
#define STRESS_ITER_CNT   (20000UL)

static void *            stress_mem;
static fd_bpf_frames_t   stress_join[ STRESS_THREAD_CNT ];
static ulong             stress_lock;
static ulong             stress_frame_holder[ STRESS_FRAME_CNT ];
static ulong             stress_done_cnt;

static ulong
stress_frame_idx( uchar * frame ) {
  ulong idx = ( (ulong)frame-(ulong)stress_mem )/sizeof(fd_bpf_frame_t);
  FD_TEST( idx<STRESS_FRAME_CNT );
  return idx;
}

static void *
stress_thread( void * arg ) {
  ulong      tid = (ulong)arg;
  fd_rng_t   _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tid, 0UL ) );

  fd_bpf_frames_t * join = &stress_join[ tid ];
  FD_TEST( fd_bpf_frames_join( join, stress_mem )==join );

  for( ulong iter=0UL; iter<STRESS_ITER_CNT; iter++ ) {
    ulong   depth    = 1UL + fd_rng_ulong_roll( rng, DEPTH );
    ulong   lock_at  = fd_rng_ulong_roll( rng, 4UL ) ? ULONG_MAX : fd_rng_ulong_roll( rng, depth );
    int     has_lock = 0;
    uchar * frame[ DEPTH ];

    int     shared[ DEPTH ];
    ulong   local_end = (ulong)join->local;
    for( ulong i=0UL; i<depth; i++ ) {
      if( i==lock_at ) {
        while( FD_ATOMIC_CAS( &stress_lock, 0UL, tid+1UL ) ) FD_SPIN_PAUSE();
        has_lock = 1;
      }
      ulong sz = fd_rng_uint_roll( rng, 2U ) ? 1UL+fd_rng_ulong_roll( rng, 4UL*PAGE ) : FULL-fd_rng_ulong_roll( rng, FULL/2UL );
      frame[ i ]  = fd_bpf_frames_acquire( join, sz, has_lock );
      shared[ i ] = (ulong)frame[ i ]-(ulong)join->local>=join->local_sz;
      if( shared[ i ] ) {
        FD_TEST( !FD_ATOMIC_CAS( &stress_frame_holder[ stress_frame_idx( frame[ i ] ) ], 0UL, tid+1UL ) );
      } else {
        FD_TEST( (ulong)frame[ i ]>=local_end && (ulong)frame[ i ]+sz<=(ulong)join->local+join->local_sz );
        local_end = (ulong)frame[ i ]+sz;
      }
      FD_TEST( join->held_cnt<=join->reserve_cnt );
    }
    for( ulong i=depth; i; i-- ) {
      if( shared[ i-1UL ] ) FD_TEST( FD_ATOMIC_CAS( &stress_frame_holder[ stress_frame_idx( frame[ i-1UL ] ) ], tid+1UL, 0UL )==tid+1UL );
      fd_bpf_frames_release( join, frame[ i-1UL ] );
      if( i-1UL==lock_at ) {
        FD_COMPILER_MFENCE();
        FD_VOLATILE( stress_lock ) = 0UL;
        has_lock = 0;
      }
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_ATOMIC_FETCH_AND_ADD( &stress_done_cnt, 1UL );
  return NULL;
}

static void
test_stress( void ) {
  stress_mem = pool_new( STRESS_SHARED_CNT, STRESS_THREAD_CNT, STRESS_LOCAL );

  pthread_t thread[ STRESS_THREAD_CNT ];
  for( ulong t=0UL; t<STRESS_THREAD_CNT; t++ ) {
    FD_TEST( !pthread_create( &thread[ t ], NULL, stress_thread, (void *)t ) );
  }

  long deadline = fd_log_wallclock() + (long)120e9;
  while( FD_VOLATILE_CONST( stress_done_cnt )<STRESS_THREAD_CNT ) {
    if( FD_UNLIKELY( fd_log_wallclock()>deadline ) ) FD_LOG_ERR(( "stress test did not finish, likely deadlocked" ));
    fd_log_sleep( (long)1e6 );
  }
  for( ulong t=0UL; t<STRESS_THREAD_CNT; t++ ) FD_TEST( !pthread_join( thread[ t ], NULL ) );

  /* Every shared frame is back and the owner role is free. */
  FD_TEST( frame_pool_free( stress_join[ 0 ].pool )==STRESS_SHARED_CNT );
  FD_TEST( !stress_join[ 0 ].shmem->has_owner );

  free( stress_mem );
}

/* Acquire+release cost per level of a 3 level stack, local and
   shared. */

static void
test_bench( ulong iter_cnt ) {
  void *          mem[2] = { pool_new( FD_BPF_FRAMES_HELD_CNT( 1UL ), 1UL, 1UL ), pool_new( FD_BPF_FRAMES_HELD_CNT( 0UL ), 1UL, 0UL ) };
  fd_bpf_frames_t join[2][1];
  for( ulong pass=0UL; pass<2UL; pass++ ) FD_TEST( fd_bpf_frames_join( join[ pass ], mem[ pass ] ) );
  for( ulong pass=0UL; pass<4UL; pass++ ) {
    long dt = -fd_log_wallclock();
    for( ulong iter=0UL; iter<iter_cnt; iter++ ) {
      fd_bpf_frames_t * j = join[ pass&1UL ];
      uchar * a = fd_bpf_frames_acquire( j, 33506UL+iter%64UL, 0 ); FD_COMPILER_FORGET( a );
      uchar * b = fd_bpf_frames_acquire( j, 3000UL,            0 ); FD_COMPILER_FORGET( b );
      uchar * c = fd_bpf_frames_acquire( j, 1000UL,            0 ); FD_COMPILER_FORGET( c );
      fd_bpf_frames_release( j, c );
      fd_bpf_frames_release( j, b );
      fd_bpf_frames_release( j, a );
    }
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%s: %.2f ns per acquire+release", (pass&1UL) ? "shared" : "local", (double)dt/(double)(3UL*iter_cnt) ));
  }
  free( mem[ 0 ] );
  free( mem[ 1 ] );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong bench_iter = fd_env_strip_cmdline_ulong( &argc, &argv, "--bench-iter", NULL, 100000UL );

  test_new();
  test_single();
  test_pools();
  test_no_local();
  test_carve();
  test_stress();
  test_bench( bench_iter );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
