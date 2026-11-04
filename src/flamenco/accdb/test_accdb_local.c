/* White-box allocator tests: include the implementation so conservation
   can cover private magazines without adding a production debug API. */
#include "fd_accdb.c"
#include "../../ballet/base58/fd_base58.h"

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
fixture_new_sized( ulong cache_fp, ulong minimum, ulong scarce ) {
  fixture_t f;
  f.fd = memfd_create( "accdb_local", 0 );
  FD_TEST( f.fd>=0 );
  ulong fp = fd_accdb_shmem_footprint( 256UL, LIVE_CNT, 512UL, 32UL, cache_fp, minimum, JOIN_CNT, 0UL );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_accdb_shmem_align(), fp );
  FD_TEST( mem );
  f.shmem = fd_accdb_shmem_join( fd_accdb_shmem_new( mem, 256UL, LIVE_CNT, 512UL, 32UL,
      cache_fp>(256UL<<20) ? 64UL<<20 : 16UL<<20, cache_fp, minimum, 0, 42UL, JOIN_CNT, 0UL ) );
  FD_TEST( f.shmem );
  /* Keep both scarce classes genuinely reservation-tracked.  Shrink
     logical capacity within the existing regions before any joins. */
  for( ulong c=6UL; c<8UL; c++ ) {
    FD_TEST( f.shmem->cache_class_max[ c ]>=scarce );
    f.shmem->cache_class_max[ c ] = scarce;
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

static fixture_t
fixture_new( void ) {
  return fixture_new_sized( 256UL<<20, 4UL, 4UL );
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

/* Real cache/account operations, not a model of the reservation loop.
   W32 has 32 live10MiB buffers,33 writable keys and one readonly native
   program.  A hot Buffer tag cannot imply a PD, but a nonexecutable
   Program tag can. */
static void
pd_write( fd_accdb_t * join, fd_accdb_fork_id_t fork, uchar const key_[32],
          ulong size, uint tag, int executable, int commit ) {
  fd_acc_t a = fd_accdb_write_one( join, fork, key_ );
  a.lamports = 42UL;
  a.data_len = size;
  memset( a.owner, 0x11, 32UL );
  memset( a.data, 0xA5, size );
  if( size>=4UL ) memcpy( a.data, &tag, 4UL );
  a.executable = executable;
  a.commit = commit;
  fd_accdb_unwrite_one( join, &a );
}

typedef struct {
  fd_accdb_t * join;
  fd_accdb_fork_id_t root;
  uchar const * const * keys;
  pthread_barrier_t * barrier;
  int writer;
} pd_stress_t;

static void *
pd_stress( void * arg ) {
  pd_stress_t * s = arg;
  int br = pthread_barrier_wait( s->barrier );
  FD_TEST( br==0 || br==PTHREAD_BARRIER_SERIAL_THREAD );
  for( ulong i=0UL; i<128UL; i++ ) {
    if( s->writer ) {
      /* Different accounts on the same fork: obey scheduler lock
         discipline while forcing actual class7 eviction/reuse. */
      uchar k[32] = {(uchar)(100UL+i)};
      pd_write( s->join, s->root, k, (1UL<<20)+1UL, 1U, 0, 1 );
    } else {
      int ro[34] = {0};
      fd_acc_t a[34];
      fd_accdb_acquire_a_deferred( s->join, s->root, 34UL, s->keys, ro, ro, a );
      for( ulong j=1UL; j<33UL; j++ )
        FD_TEST( a[j].lamports==42UL && a[j].data_len==10UL<<20 && fd_uint_load_4(a[j].data)==1U && a[j].data[a[j].data_len-1UL]==0xA5 );
      fd_accdb_acquire_b( s->join, s->root, 34UL, 0UL, NULL, NULL );
      fd_accdb_release_ab( s->join, 34UL, a, 0UL, NULL );
    }
  }
  return NULL;
}

static void
test_pd_reservations( void ) {
  fixture_t f = fixture_new_sized( 1536UL<<20, 128UL, 128UL );
  fd_accdb_t * db = f.join[0];
  fd_accdb_fork_id_t root = fd_accdb_attach_child( f.join[3], SENTINEL );
  uchar keys[34][32] = {{0}};
  uchar const * pks[34];
  int wr[34], deferred[34];
  for( ulong i=0UL; i<34UL; i++ ) {
    keys[i][0] = (uchar)(i+1UL); pks[i]=keys[i]; wr[i]=i<33UL; deferred[i]=i>0UL;
    pd_write( db, root, keys[i], i && i<33UL ? 10UL<<20 : 0UL, 1U, 0, 1 );
  }
  FD_TEST( !f.shmem->cache_class_used[7].val );
  fd_acc_t a[34];
  ulong copied = db->metrics->bytes_copied;
  fd_accdb_acquire_a_deferred( db, root, 34UL, pks, wr, deferred, a );
  FD_TEST( f.shmem->cache_class_used[7].val==65UL ); /* old path:99 */
  FD_TEST( db->metrics->bytes_copied==copied );
  for( ulong i=1UL; i<33UL; i++ ) {
    FD_TEST( a[i].private_deferred && a[i].data==a[i].prior_data && a[i].data_len==10UL<<20 );
    FD_TEST( fd_uint_load_4( a[i].data )==1U && a[i].data[a[i].data_len-1UL]==0xA5 );
  }
  fd_accdb_acquire_b( db, root, 34UL, 0UL, NULL, NULL );
  FD_TEST( f.shmem->cache_class_used[7].val==65UL );
  fd_accdb_release_ab( db, 34UL, a, 0UL, NULL );
  FD_TEST( !f.shmem->cache_class_used[7].val );
  /* Generic/eager API still permits arbitrary PD keys and keeps the old
     full budget.  No silent contract change for bundles or old tests. */
  fd_accdb_acquire_a( db, root, 34UL, pks, wr, a );
  FD_TEST( f.shmem->cache_class_used[7].val==99UL );
  fd_accdb_acquire_b( db, root, 34UL, 0UL, NULL, NULL );
  fd_accdb_release_ab( db, 34UL, a, 0UL, NULL );
  FD_TEST( !f.shmem->cache_class_used[7].val );
  /* Executable=false is not grounds to omit a Program placeholder.
     Also exercise a found large PD and a missing PD, with exact refunds. */
  pd_write( db, root, keys[0], 36UL, 2U, 0, 1 );
  uchar missing[32] = {200};
  uchar const * two[2] = {keys[0],keys[33]};
  int ro[2] = {0,0};
  fd_acc_t b;
  for( ulong n=0UL; n<2UL; n++ ) {
    uchar const * pd = n ? missing : keys[1];
    fd_acc_t program = fd_accdb_write_one( db, root, keys[0] );
    FD_TEST( fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111", program.owner ) );
    memcpy( program.data+4UL, pd, 32UL ); program.commit=1;
    fd_accdb_unwrite_one( db, &program );
    fd_accdb_acquire_a_deferred( db, root, 2UL, two, ro, ro, a );
    FD_TEST( !a[0].executable && fd_uint_load_4(a[0].data)==2U && f.shmem->cache_class_used[7].val==1UL );
    FD_TEST( !memcmp(a[0].data+4UL,pd,32UL) );
    fd_accdb_acquire_b( db, root, 2UL, 1UL, &pd, &b );
    FD_TEST( f.shmem->cache_class_used[7].val==!n );
    FD_TEST( n ? !b.lamports : b.lamports==42UL && b.data_len==10UL<<20 );
    fd_accdb_release_ab( db, 2UL, a, 1UL, &b );
    FD_TEST( !f.shmem->cache_class_used[7].val );
  }
  /* Force a genuine cold Buffer: no header read is available, so retain
     its placeholder until B refunds it; the subsequent hot read omits it. */
  for( ulong n=0UL; n<2UL; n++ ) {
    uchar const * k = keys[1];
    if( !n ) {
      fd_acc_t r = fd_accdb_read_one( db, root, k );
      fd_accdb_accmeta_t * meta = &db->acc_pool[cache_line(db,7UL,r._original_cache_idx)->acc_idx];
      fd_accdb_unread_one( db, &r );
      for( ulong sweep=0UL; sweep<8UL && FD_ACCDB_SIZE_CACHE_VALID(meta->executable_size); sweep++ ) {
        int busy=0; background_preevict( f.join[3], &busy, 1 );
      }
      FD_TEST( !FD_ACCDB_SIZE_CACHE_VALID(meta->executable_size) );
    }
    fd_accdb_acquire_a_deferred( db, root, 1UL, &k, ro, ro, a );
    FD_TEST( f.shmem->cache_class_used[7].val==(n ? 1UL : 2UL) );
    fd_accdb_acquire_b( db, root, 1UL, 0UL, NULL, NULL );
    FD_TEST( f.shmem->cache_class_used[7].val==1UL );
    fd_accdb_release_ab( db, 1UL, a, 0UL, NULL );
    FD_TEST( !f.shmem->cache_class_used[7].val );
  }
  /* Two valid concurrent readonly acquisitions race unrelated writers
     and actual cache eviction.  Account bytes and all reservation
     counters must survive; a pin is never retained into reservation. */
  pthread_barrier_t barrier;
  FD_TEST( !pthread_barrier_init( &barrier, NULL, 3U ) );
  pd_stress_t ctx[3]; pthread_t threads[3];
  alarm( 90U );
  for( ulong i=0UL; i<3UL; i++ ) {
    ctx[i]=(pd_stress_t){f.join[i],root,pks,&barrier,i==2UL};
    FD_TEST( !pthread_create( &threads[i], NULL, pd_stress, &ctx[i] ) );
  }
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !pthread_join( threads[i], NULL ) );
  alarm( 0U );
  FD_TEST( !pthread_barrier_destroy( &barrier ) );
  FD_TEST( f.join[2]->metrics->accounts_evicted_per_class[7]>0UL );
  for( ulong c=0UL; c<8UL; c++ ) FD_TEST( f.shmem->cache_class_used[c].val==0UL || f.shmem->cache_class_used[c].val==ULONG_MAX );
  for( ulong c=0UL; c<8UL; c++ ) conserve( &f, c );
  FD_LOG_NOTICE(( "PD reservations: W32 hot65 vs generic99; nonexecutable Program/found+missing PD/cold fallback exact refunds; concurrent256 read batches+128 unrelated writes with eviction: pass" ));
  fixture_delete( &f );
}

#if FD_HAS_RACESAN
typedef struct {
  fd_accdb_t * join;
  fd_accdb_fork_id_t root;
  ulong peak;
} pd_race_t;

static void
pd_race_read( void * arg ) {
  pd_race_t * ctx=arg;
  uchar const * pk=key; int ro=0; fd_acc_t a;
  fd_accdb_acquire_a_deferred( ctx->join, ctx->root, 1UL, &pk, &ro, &ro, &a );
  ctx->peak=ctx->join->shmem->cache_class_used[7].val;
  FD_TEST( a.lamports==42UL && a.data_len==10UL<<20 && fd_uint_load_4(a.data)==1U && a.data[a.data_len-1UL]==0xA5 );
  fd_accdb_acquire_b( ctx->join, ctx->root, 1UL, 0UL, NULL, NULL );
  fd_accdb_release_ab( ctx->join, 1UL, &a, 0UL, NULL );
}

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
test_pd_probe_eviction( void ) {
  fixture_t f=fixture_new();
  fd_accdb_fork_id_t root=fd_accdb_attach_child(f.join[3],SENTINEL);
  pd_write(f.join[0],root,key,10UL<<20,1U,0,1);
  for( ulong during=0UL; during<2UL; during++ ) {
    ulong cls,idx; FD_TEST(fd_accdb_debug_find_line(f.join[0],key,&cls,&idx) && cls==7UL);
    pd_race_t ctx={f.join[0],root,ULONG_MAX};
    fd_racesan_async_t reader[1]; void * stack=fd_racesan_stack_create(1UL<<20);
    fd_racesan_async_new(reader,stack,1UL<<20,pd_race_read,&ctx);
    char const * hook=during ? "accdb_pd:post_read" : "accdb_pd:pre_pin";
    FD_TEST(fd_racesan_async_step_until(reader,hook,10000UL)==FD_RACESAN_ASYNC_RET_HOOK);
    fd_accdb_cache_line_t * line=cache_line(f.join[0],cls,idx);
    uint ai=line->acc_idx; FD_TEST(ai!=UINT_MAX);
    fd_accdb_debug_clock_evict_line(f.join[1],cls,idx);
    /* Before pin: the real evictor wins and the stale pointer must cause
       conservative fallback.  During prefix read: the validated pin
       makes the real evictor fail, preserving the data being read. */
    FD_TEST(!!FD_ACCDB_SIZE_CACHE_VALID(f.join[0]->acc_pool[ai].executable_size)==!!during);
    finish_async(reader);
    FD_TEST(ctx.peak==(during ? 1UL : 2UL));
    FD_TEST(!f.shmem->cache_class_used[7].val);
    fd_racesan_async_delete(reader);fd_racesan_stack_destroy(stack,1UL<<20);
  }
  FD_LOG_NOTICE(( "PD probe: real eviction before pin -> conservative fallback; eviction during read blocked by pin: pass" ));
  fixture_delete(&f);
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
  RUN( test_pd_reservations );
#if FD_HAS_RACESAN
  RUN( test_local_stray_pin );
  RUN( test_pd_probe_eviction );
#endif
#undef RUN
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
