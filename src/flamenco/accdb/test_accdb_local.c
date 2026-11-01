/* White-box allocator tests: include the implementation so conservation
   can cover private magazines without adding a production debug API. */
#include "fd_accdb.c"

#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#if FD_HAS_RACESAN
#include "../../util/racesan/fd_racesan_async.h"
#endif

#define JOIN_CNT (4UL)
#define LIVE_CNT (8UL)
#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

typedef struct {
  fd_accdb_shmem_t * shmem;
  fd_accdb_t * join[ JOIN_CNT ]; /* last join is background */
  int fd;
} fixture_t;

static fixture_t
fixture_new( void ) {
  fixture_t f;
  f.fd = memfd_create( "accdb_local", 0 );
  FD_TEST( f.fd>=0 );
  ulong fp = fd_accdb_shmem_footprint( 256UL, LIVE_CNT, 512UL, 32UL, 256UL<<20, 4UL, JOIN_CNT, 0UL );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_accdb_shmem_align(), fp );
  FD_TEST( mem );
  f.shmem = fd_accdb_shmem_join( fd_accdb_shmem_new( mem, 256UL, LIVE_CNT, 512UL, 32UL,
      16UL<<20, 256UL<<20, 4UL, 0, 42UL, JOIN_CNT, 0UL ) );
  FD_TEST( f.shmem );
  /* Keep both scarce classes genuinely reservation-tracked.  Shrink
     logical capacity within the existing regions before any joins. */
  for( ulong c=6UL; c<8UL; c++ ) {
    FD_TEST( f.shmem->cache_class_max[ c ]>=4UL );
    f.shmem->cache_class_max[ c ] = 4UL;
    f.shmem->cache_class_used[ c ].val = 0UL;
  }
  for( ulong j=0UL; j<JOIN_CNT; j++ ) {
    int background = j==JOIN_CNT-1UL;
    mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( LIVE_CNT, background ) );
    FD_TEST( mem );
    f.join[ j ] = fd_accdb_join( fd_accdb_new( mem, f.shmem, f.fd, 0UL, NULL, NULL, 0UL, background ) );
    FD_TEST( f.join[ j ] );
  }
  FD_TEST( f.join[ 0 ]->cache_local_cap[ 0 ]==CACHE_LOCAL_MAX );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) FD_TEST( !f.join[ 3 ]->cache_local_cap[ c ] );
  for( ulong j=0UL; j<JOIN_CNT; j++ ) {
    FD_TEST( !f.join[ j ]->cache_local_cap[ 6 ] );
    FD_TEST( !f.join[ j ]->cache_local_cap[ 7 ] );
  }
  return f;
}

static void
fixture_delete( fixture_t * f ) {
  for( ulong j=0UL; j<JOIN_CNT; j++ ) {
    fd_accdb_cache_flush( f->join[ j ] );
    free( f->join[ j ] );
  }
  free( f->shmem );
  FD_TEST( !close( f->fd ) );
}

static void
give_back( fd_accdb_t * join, ulong c, fd_accdb_cache_line_t * line ) {
  FD_TEST( line->refcnt==1U );
  line->acc_idx = UINT_MAX;
  line->key.generation = UINT_MAX;
  line->persisted = 1;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( line->refcnt ) = 0U;
  cache_free_push( join, c, line );
}

/* At a quiescent point every initialized slot must occur exactly once:
   a free list, a magazine, an active claim, or a resident account. */
static ulong
conserve( fixture_t * f, ulong c ) {
  ulong init = f->shmem->cache_class_init[ c ].val;
  FD_TEST( init<=f->shmem->cache_class_max[ c ] );
  uchar * seen = calloc( init+1UL, 1UL );
  FD_TEST( seen );
  ulong free_cnt = 0UL;
  uint idx = (uint)f->shmem->cache_free[ c ].ver_top;
  while( idx!=UINT_MAX ) {
    FD_TEST( idx<init && !seen[ idx ] );
    seen[ idx ] = 1;
    free_cnt++;
    idx = cache_line( f->join[ 0 ], c, idx )->next;
  }
  FD_TEST( free_cnt==f->shmem->cache_free_cnt[ c ].val );
  for( ulong j=0UL; j<JOIN_CNT; j++ ) {
    fd_accdb_t * join = f->join[ j ];
    FD_TEST( !join->cache_local_cnt[ c ] || join->cache_local_cookie==f->shmem->cache_reset_cookie );
    FD_TEST( join->cache_local_cnt[ c ]<=join->cache_local_cap[ c ] );
    for( ulong k=0UL; k<join->cache_local_cnt[ c ]; k++ ) {
      idx = join->cache_local_idx[ c ][ k ];
      FD_TEST( idx<init && !seen[ idx ] );
      seen[ idx ] = 1;
      free_cnt++;
    }
  }
  for( ulong i=0UL; i<init; i++ ) {
    fd_accdb_cache_line_t * line = cache_line( f->join[ 0 ], c, i );
    if( seen[ i ] ) FD_TEST( line->acc_idx==UINT_MAX && line->key.generation==UINT_MAX && line->persisted && !line->refcnt );
    else           FD_TEST( line->refcnt || (line->acc_idx!=UINT_MAX && line->key.generation!=UINT_MAX) );
  }
  free( seen );
  return free_cnt;
}

static void
test_capacity( void ) {
  FD_TEST( !cache_local_capacity( ULONG_MAX, 0UL, 192UL ) );
  FD_TEST( !cache_local_capacity( ULONG_MAX, 1UL, ULONG_MAX ) );
  FD_TEST( !cache_local_capacity( 66UL*(257UL+16UL)-1UL, 66UL, 192UL ) );
  FD_TEST( cache_local_capacity( 66UL*(257UL+16UL), 66UL, 192UL )==16UL );
  FD_TEST( !cache_local_capacity( 66UL*(960UL+16UL)-1UL, 66UL, 960UL ) );
  FD_TEST( cache_local_capacity( 64416UL, 66UL, 960UL )==16UL );
  FD_TEST( cache_local_capacity( 101988UL, 66UL, 960UL )==16UL );
  FD_TEST( !cache_local_capacity( 4934UL, 50UL, 192UL ) );
  FD_TEST( !cache_local_capacity( 967UL, 50UL, 192UL ) );

  /* Exercise construction at both sides of the admission threshold,
     including untracked-but-too-small capacity.  Regions stay unchanged. */
  fixture_t f = fixture_new();
  for( ulong j=0UL; j<JOIN_CNT; j++ ) free( f.join[ j ] );
  f.shmem->joiner_cnt = 0UL;
  f.shmem->cache_class_max[ 0 ] = JOIN_CNT*(257UL+16UL)-1UL;
  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( LIVE_CNT, 0 ) );
  fd_accdb_t * join = fd_accdb_new( mem, f.shmem, f.fd, 0UL, NULL, NULL, 0UL, 0 );
  FD_TEST( join && !join->cache_local_cap[ 0 ] );
  FD_TEST( f.shmem->cache_class_used[ 0 ].val==ULONG_MAX );
  free( mem );
  f.shmem->cache_class_max[ 0 ]++;
  mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( LIVE_CNT, 0 ) );
  join = fd_accdb_new( mem, f.shmem, f.fd, 0UL, NULL, NULL, 0UL, 0 );
  FD_TEST( join && join->cache_local_cap[ 0 ]==16U );
  fd_accdb_cache_flush( join );
  free( mem );
  free( f.shmem );
  close( f.fd );
}

static void
test_conservation( void ) {
  fixture_t f = fixture_new();
  fd_accdb_cache_line_t * held[ 80 ];
  uint evicted;
  for( ulong i=0UL; i<80UL; i++ ) {
    held[ i ] = acquire_cache_line( f.join[ 0 ], 0UL, &evicted );
    FD_TEST( evicted==UINT_MAX );
  }
  FD_TEST( !conserve( &f, 0UL ) );
  /* Different join frees the buffers; each free is locally owned by
     that join, never by the allocating worker. */
  for( ulong i=0UL; i<80UL; i++ ) give_back( f.join[ 1UL+(i&1UL) ], 0UL, held[ i ] );
  FD_TEST( conserve( &f, 0UL )==80UL );
  FD_TEST( f.join[ 1 ]->cache_local_cnt[ 0 ]==16U && f.join[ 2 ]->cache_local_cnt[ 0 ]==16U );
  FD_TEST( f.shmem->cache_free_cnt[ 0 ].val==48UL );
  ulong top = f.join[ 1 ]->cache_local_idx[ 0 ][ 15 ];
  uint seq = cache_line( f.join[ 1 ], 0UL, top )->seq;
  fd_accdb_cache_line_t * line = acquire_cache_line( f.join[ 1 ], 0UL, &evicted );
  FD_TEST( line==cache_line( f.join[ 1 ], 0UL, top ) && line->seq==seq+1U && line->refcnt==1U );
  FD_TEST( f.shmem->cache_free_cnt[ 0 ].val==48UL );
  give_back( f.join[ 1 ], 0UL, line );
  for( ulong j=0UL; j<JOIN_CNT; j++ ) fd_accdb_cache_flush( f.join[ j ] );
  FD_TEST( conserve( &f, 0UL )==80UL && f.shmem->cache_free_cnt[ 0 ].val==80UL );
  fd_accdb_cache_flush( f.join[ 1 ] ); /* idempotent */
  uchar seen[ 80 ] = {0};
  for( ulong i=0UL; i<80UL; i++ ) {
    held[ i ] = acquire_cache_line( f.join[ 0 ], 0UL, &evicted );
    ulong idx = cache_line_idx( f.join[ 0 ], 0UL, held[ i ] );
    FD_TEST( idx<80UL && !seen[ idx ] );
    seen[ idx ] = 1;
  }
  for( ulong i=0UL; i<80UL; i++ ) give_back( f.join[ 3 ], 0UL, held[ i ] );
  FD_TEST( conserve( &f, 0UL )==80UL );
  fixture_delete( &f );
}

typedef struct {
  fd_accdb_t * join;
  ulong c;
  fd_accdb_cache_line_t * result;
} alloc_ctx_t;

static void *
allocate_one( void * arg ) {
  alloc_ctx_t * ctx = arg;
  uint evicted;
  ctx->result = acquire_cache_line( ctx->join, ctx->c, &evicted );
  FD_TEST( evicted==UINT_MAX );
  return NULL;
}

static void
test_saturated_progress( void ) {
  fixture_t f = fixture_new();
  /* Exhaust the actual scarce classes.  No empty CLOCK victim is
     usable; only the late global return can let the waiter finish. */
  for( ulong c=6UL; c<8UL; c++ ) {
    ulong cap = f.shmem->cache_class_max[ c ];
    fd_accdb_cache_line_t ** held = calloc( cap, sizeof(*held) );
    FD_TEST( held );
    uint evicted;
    for( ulong i=0UL; i<cap; i++ ) held[ i ] = acquire_cache_line( f.join[ 0 ], c, &evicted );
    FD_TEST( !conserve( &f, c ) );
    ulong before = FD_VOLATILE_CONST( f.shmem->clock_hand[ c ].val );
    alloc_ctx_t ctx = { .join=f.join[ 1 ], .c=c, .result=NULL };
    pthread_t thread;
    alarm( 20U );
    FD_TEST( !pthread_create( &thread, NULL, allocate_one, &ctx ) );
    while( FD_VOLATILE_CONST( f.shmem->clock_hand[ c ].val )<before+128UL ) FD_SPIN_PAUSE();
    give_back( f.join[ 2 ], c, held[ 0 ] );
    FD_TEST( !pthread_join( thread, NULL ) );
    alarm( 0U );
    FD_TEST( ctx.result==held[ 0 ] );
    for( ulong i=0UL; i<cap; i++ ) give_back( f.join[ 2 ], c, held[ i ] );
    FD_TEST( conserve( &f, c )==cap );
    FD_TEST( f.shmem->cache_free_cnt[ c ].val==cap && !f.join[ 2 ]->cache_local_cnt[ c ] );
    FD_TEST( f.shmem->cache_class_used[ c ].val==0UL );
    free( held );
  }
  fixture_delete( &f );
}

typedef struct {
  fd_accdb_t * join;
  fd_accdb_fork_id_t fork;
} reserve_ctx_t;

static void *
reserve_one( void * arg ) {
  reserve_ctx_t * ctx = arg;
  uchar pubkey[32] = {99};
  fd_acc_t acc = fd_accdb_write_one( ctx->join, ctx->fork, pubkey );
  FD_TEST( !acc.lamports );
  acc.commit = 0;
  fd_accdb_unwrite_one( ctx->join, &acc );
  return NULL;
}

static void
test_saturated_reservations( void ) {
  fixture_t f = fixture_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( f.join[ 3 ], SENTINEL );
  uchar keys[4][32] = {{1},{2},{3},{4}};
  uchar const * pks[4] = {keys[0],keys[1],keys[2],keys[3]};
  int writable[4] = {1,1,1,1};
  fd_acc_t acc[4];
  fd_accdb_acquire( f.join[ 0 ], root, 4UL, pks, writable, acc );
  for( ulong c=6UL; c<8UL; c++ ) {
    FD_TEST( f.shmem->cache_class_used[ c ].val==4UL );
    FD_TEST( f.shmem->cache_class_init[ c ].val==4UL );
  }
  reserve_ctx_t ctx = { .join=f.join[ 1 ], .fork=root };
  pthread_t thread;
  alarm( 20U );
  FD_TEST( !pthread_create( &thread, NULL, reserve_one, &ctx ) );
  while( FD_VOLATILE_CONST( f.join[ 1 ]->metrics->acquire_failed )<32UL ) FD_SPIN_PAUSE();
  for( ulong i=0UL; i<4UL; i++ ) acc[ i ].commit = 0;
  fd_accdb_release( f.join[ 0 ], 4UL, acc );
  FD_TEST( !pthread_join( thread, NULL ) );
  alarm( 0U );
  for( ulong c=6UL; c<8UL; c++ ) {
    FD_TEST( !f.shmem->cache_class_used[ c ].val );
    FD_TEST( conserve( &f, c )==4UL );
    FD_TEST( f.shmem->cache_free_cnt[ c ].val==4UL );
  }
  fixture_delete( &f );
}

static void
test_reset( void ) {
  fixture_t f = fixture_new();
  uint evicted;
  for( ulong j=0UL; j<3UL; j++ ) {
    fd_accdb_cache_line_t * line = acquire_cache_line( f.join[ j ], 0UL, &evicted );
    give_back( f.join[ j ], 0UL, line );
  }
  ulong cookie = f.shmem->cache_reset_cookie;
  fd_accdb_reset( f.join[ 3 ] );
  int busy = 0;
  fd_accdb_background( f.join[ 3 ], &busy );
  FD_TEST( f.shmem->cache_reset_cookie==cookie+1UL );
  FD_TEST( !f.shmem->cache_class_init[ 0 ].val );
  /* Poison indices: stale flush/pop must discard without dereferencing. */
  f.join[ 1 ]->cache_local_idx[ 0 ][ 0 ] = UINT_MAX;
  fd_accdb_cache_flush( f.join[ 1 ] );
  f.join[ 2 ]->cache_local_idx[ 0 ][ 0 ] = UINT_MAX;
  fd_accdb_cache_line_t * line = acquire_cache_line( f.join[ 2 ], 0UL, &evicted );
  FD_TEST( cache_line_idx( f.join[ 2 ], 0UL, line )==0UL && line->refcnt==1U );
  /* Stale push must discard its old magazine before accepting a new
     return, otherwise slot zero could appear twice. */
  f.join[ 0 ]->cache_local_idx[ 0 ][ 0 ] = UINT_MAX;
  give_back( f.join[ 0 ], 0UL, line );
  FD_TEST( f.join[ 0 ]->cache_local_cnt[ 0 ]==1U );
  FD_TEST( conserve( &f, 0UL )==1UL );
  fd_accdb_reset( f.join[ 3 ] );
  fd_accdb_background( f.join[ 3 ], &busy );
  for( ulong j=0UL; j<JOIN_CNT; j++ ) fd_accdb_cache_flush( f.join[ j ] );
  FD_TEST( f.shmem->cache_reset_cookie==cookie+2UL && !conserve( &f, 0UL ) );
  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( LIVE_CNT, 0 ) );
  ulong epoch = ULONG_MAX;
  fd_accdb_t * ro = fd_accdb_join_readonly( mem, f.shmem, &epoch, f.fd );
  FD_TEST( ro );
  for( ulong c=0UL; c<8UL; c++ ) FD_TEST( !ro->cache_local_cap[ c ] );
  fd_accdb_cache_flush( ro );
  FD_TEST( f.shmem->cache_reset_cookie==cookie+2UL );
  free( mem );
  fixture_delete( &f );
}

static uchar const key[32] = {7};

static void
write_account( fd_accdb_t * join, fd_accdb_fork_id_t fork, ulong sz, uchar tag, int commit ) {
  fd_acc_t acc = fd_accdb_write_one( join, fork, key );
  acc.lamports = 42UL;
  acc.data_len = sz;
  memset( acc.owner, tag, 32UL );
  memset( acc.data, tag, sz );
  acc.commit = commit;
  fd_accdb_unwrite_one( join, &acc );
}

static void
check_account( fd_accdb_t * join, fd_accdb_fork_id_t fork, ulong sz, uchar tag ) {
  fd_acc_t acc = fd_accdb_read_one( join, fork, key );
  FD_TEST( acc.lamports==42UL && acc.data_len==sz );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( acc.owner[ i ]==tag );
  for( ulong i=0UL; i<sz; i++ ) FD_TEST( acc.data[ i ]==tag );
  fd_accdb_unread_one( join, &acc );
}

static void
test_native_accounts( void ) {
  fixture_t f = fixture_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( f.join[ 3 ], SENTINEL );
  write_account( f.join[ 0 ], root, 64UL, 0x11, 1 );
  fd_accdb_fork_id_t child = fd_accdb_attach_child( f.join[ 3 ], root );
  write_account( f.join[ 1 ], child, 16384UL, 0x22, 1 );
  check_account( f.join[ 0 ], root, 64UL, 0x11 );
  check_account( f.join[ 2 ], child, 16384UL, 0x22 );
  write_account( f.join[ 2 ], child, 1048577UL, 0x33, 1 );
  write_account( f.join[ 1 ], child, 512UL, 0x44, 0 );
  check_account( f.join[ 0 ], child, 1048577UL, 0x33 );
  write_account( f.join[ 1 ], child, 32UL, 0x55, 1 );
  int busy = 0;
  background_preevict( f.join[ 3 ], &busy, 1 );
  check_account( f.join[ 0 ], child, 32UL, 0x55 );
  check_account( f.join[ 2 ], root, 64UL, 0x11 );
  for( ulong c=0UL; c<8UL; c++ ) conserve( &f, c );
  FD_TEST( f.shmem->cache_class_used[ 6 ].val==0UL && f.shmem->cache_class_used[ 7 ].val==0UL );
  fixture_delete( &f );
}

#if FD_HAS_RACESAN
typedef struct {
  fd_accdb_cache_line_t * line;
  fd_accdb_cache_line_t * result;
} pin_ctx_t;

static void
late_pin( void * arg ) {
  pin_ctx_t * ctx = arg;
  ctx->result = cache_try_pin( ctx->line, key, 7U );
}

static void
async_allocate( void * arg ) {
  allocate_one( arg );
}

static void
finish_async( fd_racesan_async_t * async ) {
  for( ulong i=0UL; i<10000UL; i++ ) {
    int res = fd_racesan_async_step( async );
    if( res==FD_RACESAN_ASYNC_RET_EXIT ) return;
    FD_TEST( res==FD_RACESAN_ASYNC_RET_HOOK );
  }
  FD_TEST( 0 );
}

static void
test_local_stray_pin( void ) {
  fixture_t f = fixture_new();
  uint evicted;
  fd_accdb_cache_line_t * line = acquire_cache_line( f.join[ 0 ], 0UL, &evicted );
  give_back( f.join[ 0 ], 0UL, line );
  pin_ctx_t pin = { .line=line, .result=line };
  alloc_ctx_t alloc = { .join=f.join[ 0 ], .c=0UL, .result=NULL };
  fd_racesan_async_t p[1], a[1];
  void * ps = fd_racesan_stack_create( 1UL<<20 );
  void * as = fd_racesan_stack_create( 1UL<<20 );
  fd_racesan_async_new( p, ps, 1UL<<20, late_pin, &pin );
  fd_racesan_async_new( a, as, 1UL<<20, async_allocate, &alloc );
  FD_TEST( fd_racesan_async_step_until( p, "accdb_try_pin:post_cas", 1000UL )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( line->refcnt==1U );
  FD_TEST( fd_racesan_async_step_until( a, "accdb_freepop:refcnt_wait", 1000UL )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( !alloc.result && !f.join[ 0 ]->cache_local_cnt[ 0 ] );
  finish_async( p );
  FD_TEST( !pin.result && !line->refcnt );
  finish_async( a );
  FD_TEST( alloc.result==line && line->refcnt==1U && line->seq==1U );
  give_back( f.join[ 0 ], 0UL, line );
  FD_TEST( conserve( &f, 0UL )==1UL );
  fd_racesan_async_delete( p );
  fd_racesan_async_delete( a );
  fd_racesan_stack_destroy( ps, 1UL<<20 );
  fd_racesan_stack_destroy( as, 1UL<<20 );
  fixture_delete( &f );
}
#endif

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
#define RUN( fn ) do { FD_LOG_NOTICE(( #fn )); fn(); } while(0)
  RUN( test_capacity );
  RUN( test_conservation );
  RUN( test_saturated_progress );
  RUN( test_saturated_reservations );
  RUN( test_reset );
  RUN( test_native_accounts );
#if FD_HAS_RACESAN
  RUN( test_local_stray_pin );
#endif
#undef RUN
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
