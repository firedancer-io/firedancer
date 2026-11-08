#include "fd_bpf_frames.c"
#include <pthread.h>
#include <stdlib.h>

#define DEPTH FD_MAX_INSTRUCTION_STACK_DEPTH
#define LOCAL (2UL)
#define HELD  FD_BPF_FRAMES_HELD_CNT( LOCAL )

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
  while( (frame[ got ] = fd_bpf_frames_try_acquire( join, 1 )) ) {
    FD_TEST( fd_ulong_is_aligned( (ulong)frame[ got ], FD_BPF_FRAMES_ALIGN ) );
    FD_TEST( (ulong)frame[ got ]>=(ulong)mem && (ulong)frame[ got ]+sizeof(fd_bpf_frame_t)<=(ulong)mem+footprint );
    for( ulong j=0UL; j<got; j++ ) FD_TEST( frame[ got ]!=frame[ j ] );
    got++;
  }
  FD_TEST( got==HELD+LOCAL );
  for( ulong i=0UL; i<LOCAL; i++ ) FD_TEST( frame[ i ]==(uchar *)( join->local+i ) );
  for( ulong i=got; i; i-- ) fd_bpf_frames_release( join, frame[ i-1UL ] );

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
      frame[ i ] = fd_bpf_frames_try_acquire( join, 0 );
      FD_TEST( frame[ i ] );
      for( ulong j=0UL; j<i; j++ ) FD_TEST( frame[ i ]!=frame[ j ] );
    }
    for( ulong i=0UL; i<LOCAL; i++ ) FD_TEST( frame[ i ]==(uchar *)( join->local+i ) );
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
    FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, 0 ))==(uchar *)( t1->local+i ) );
    FD_TEST( (b[ i ] = fd_bpf_frames_try_acquire( t2, 0 ))==(uchar *)( t2->local+i ) );
    FD_TEST( (s[ i ] = fd_bpf_frames_try_acquire( t3, 0 ))==(uchar *)( t3->local+i ) );
  }

  /* Tile 1 becomes owner and gets the rest of its stack, while other
     tiles must leave both reserves. */
  for( ulong i=LOCAL; i<DEPTH; i++ ) FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, 0 )) );
  FD_TEST( t1->is_owner );
  FD_TEST( !fd_bpf_frames_try_acquire( t2, 0 ) );

  /* The priority caller still gets the rest of its stack. */
  for( ulong i=LOCAL; i<DEPTH; i++ ) FD_TEST( (s[ i ] = fd_bpf_frames_try_acquire( t3, 1 )) );
  FD_TEST( !fd_bpf_frames_try_acquire( t3, 1 ) );
  FD_TEST( !t3->is_owner );

  for( ulong i=0UL; i<DEPTH; i++ ) {
    for( ulong j=0UL; j<LOCAL; j++ ) FD_TEST( a[ i ]!=b[ j ] && s[ i ]!=b[ j ] );
    for( ulong j=0UL; j<DEPTH; j++ ) FD_TEST( a[ i ]!=s[ j ] );
  }

  /* Holding no shared frames releases ownership, then another tile can
     become owner. */
  for( ulong i=DEPTH; i>LOCAL; i-- ) fd_bpf_frames_release( t1, a[ i-1UL ] );
  FD_TEST( !t1->is_owner );
  FD_TEST( (b[ LOCAL ] = fd_bpf_frames_try_acquire( t2, 0 )) && t2->is_owner );
  FD_TEST( !fd_bpf_frames_try_acquire( t1, 0 ) );
  fd_bpf_frames_release( t2, b[ LOCAL ] );
  FD_TEST( !t2->is_owner );
  for( ulong i=DEPTH; i>LOCAL; i-- ) fd_bpf_frames_release( t3, s[ i-1UL ] );

  /* Local frames are reused. */
  fd_bpf_frames_release( t1, a[ LOCAL-1UL ] );
  FD_TEST( fd_bpf_frames_try_acquire( t1, 0 )==a[ LOCAL-1UL ] );
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
  for( ulong i=0UL; i<DEPTH; i++ ) FD_TEST( (a[ i ] = fd_bpf_frames_try_acquire( t1, 0 )) );
  FD_TEST( t1->is_owner );
  for( ulong i=0UL; i<DEPTH; i++ ) FD_TEST( (b[ i ] = fd_bpf_frames_try_acquire( t2, 1 )) );

  for( ulong i=DEPTH; i; i-- ) {
    fd_bpf_frames_release( t1, a[ i-1UL ] );
    fd_bpf_frames_release( t2, b[ i-1UL ] );
  }
  free( mem );
}

/* Stress: threads join while others are already running, then run
   random nested stacks and sometimes take an exclusive lock partway
   down, spinning for it while holding frames, and acquire as the
   priority caller while holding it, like the program cache spill lock.
   A deadlock trips the watchdog. */

#define STRESS_THREAD_CNT (12UL)
#define STRESS_FRAME_CNT  (STRESS_THREAD_CNT*LOCAL+HELD)
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

    for( ulong i=0UL; i<depth; i++ ) {
      if( i==lock_at ) {
        while( FD_ATOMIC_CAS( &stress_lock, 0UL, tid+1UL ) ) FD_SPIN_PAUSE();
        has_lock = 1;
      }
      frame[ i ] = fd_bpf_frames_acquire( join, has_lock );
      FD_TEST( !FD_ATOMIC_CAS( &stress_frame_holder[ stress_frame_idx( frame[ i ] ) ], 0UL, tid+1UL ) );
    }
    for( ulong i=depth; i; i-- ) {
      FD_TEST( FD_ATOMIC_CAS( &stress_frame_holder[ stress_frame_idx( frame[ i-1UL ] ) ], tid+1UL, 0UL )==tid+1UL );
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
  stress_mem = pool_new( HELD, STRESS_THREAD_CNT, LOCAL );

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
  FD_TEST( frame_pool_free( stress_join[ 0 ].pool )==HELD );
  FD_TEST( !stress_join[ 0 ].shmem->has_owner );

  free( stress_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_new();
  test_single();
  test_pools();
  test_no_local();
  test_stress();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
