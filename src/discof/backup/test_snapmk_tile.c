/* Drives after_credit on a hand-built snapmk context with a fake stem
   (as test_replay_tile.c does) to cover the appendvec slot overflow:
   snapmk must discard the partial archive, release the snapzp tiles
   and accdb, and report FAILED to replay. */

#define FD_TILE_TEST
#include "fd_snapmk_tile.c"

#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define ZP_CNT     (2UL)
#define OUT_CNT    (ZP_CNT+1UL) /* zp links, then snapmk_out */
#define SNAPMK_OUT (ZP_CNT)
#define DEPTH      (128UL)

static fd_frag_meta_t *  test_mcaches [ OUT_CNT ];
static ulong             test_seqs    [ OUT_CNT ];
static ulong             test_depths  [ OUT_CNT ];
static ulong             test_cr_avail[ OUT_CNT ];
static ulong             test_min_cr_avail[ 1 ];
static int               test_out_reliable[ OUT_CNT ];
static fd_stem_context_t test_stem[ 1 ];
static uchar             test_backup_mem[ 1UL<<20 ] __attribute__((aligned(128)));

struct fixture {
  fd_snapmk_t * ctx;
  fd_bank_t *   bank;
  fd_wksp_t *   wksp;
  char          path[ 64 ];
  int           fd;
  ulong         sync;
};

typedef struct fixture fixture_t;

static void
setup_out_link( fixture_t * fx,
                ulong       idx,
                ulong       mtu,
                void **     out_mem,
                ulong *     out_chunk0,
                ulong *     out_wmark ) {
  void * mcache_mem = fd_wksp_alloc_laddr( fx->wksp, fd_mcache_align(), fd_mcache_footprint( DEPTH, 0UL ), 1UL );
  FD_TEST( mcache_mem );
  test_mcaches[ idx ] = fd_mcache_join( fd_mcache_new( mcache_mem, DEPTH, 0UL, 0UL ) );
  FD_TEST( test_mcaches[ idx ] );

  ulong  dcache_data_sz = fd_dcache_req_data_sz( mtu, DEPTH, 1UL, 1 );
  void * dcache_mem     = fd_wksp_alloc_laddr( fx->wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  FD_TEST( dcache_mem );
  void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( dcache );

  test_seqs        [ idx ] = 0UL;
  test_depths      [ idx ] = DEPTH;
  test_cr_avail    [ idx ] = DEPTH;
  test_out_reliable[ idx ] = 1;

  *out_mem    = fx->wksp;
  *out_chunk0 = fd_dcache_compact_chunk0( fx->wksp, dcache );
  *out_wmark  = fd_dcache_compact_wmark ( fx->wksp, dcache, mtu );
}

/* fixture_new builds the parts of a snapmk context that the states
   from START to TAR_HEADERS and from ACCDB_*_FINISH to SLEEP touch: a
   pool slot holding a locked partial file with some bytes in it, a
   bank, the shared stats, the accdb snapshot sync word, and the out
   links. */

static fixture_t *
fixture_new( fixture_t * fx,
             fd_wksp_t * wksp,
             ulong       base_slot,
             ulong       snapshot_slot ) {
  memset( fx, 0, sizeof(*fx) );
  fx->wksp = wksp;

  /* anonymous mmap: the 64 MiB of compression buffers stay untouched */
  ulong ctx_sz = fd_ulong_align_up( sizeof(fd_snapmk_t), 4096UL );
  fd_snapmk_t * ctx = mmap( NULL, ctx_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( ctx!=MAP_FAILED );
  FD_TEST( fd_ulong_is_aligned( (ulong)ctx, alignof(fd_snapmk_t) ) );
  fx->ctx = ctx;

  fx->bank = fd_wksp_alloc_laddr( wksp, alignof(fd_bank_t), sizeof(fd_bank_t), 1UL );
  FD_TEST( fx->bank );
  memset( fx->bank, 0, sizeof(fd_bank_t) );
  fx->bank->f.slot = snapshot_slot;
  ctx->bank        = fx->bank;

  /* snapshot pool slot being written: placeholder name, locked file */
  strcpy( fx->path, "/tmp/test_snapmk_tile.XXXXXX" );
  fx->fd = mkstemp( fx->path );
  FD_TEST( fx->fd>=0 );
  static uchar junk[ 8192 ];
  memset( junk, 0xEE, sizeof(junk) );
  FD_TEST( write( fx->fd, junk, sizeof(junk) )==(long)sizeof(junk) );
  struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
  FD_TEST( 0==fcntl( fx->fd, F_SETLK, &lock ) );
  fd_snap_pool_partial_name( ctx->pool[ 0 ].name, 0U );
  ctx->pool[ 0 ].full_slot = ULONG_MAX;
  ctx->pool[ 0 ].incr_slot = ULONG_MAX;
  ctx->pool_sz[ 0 ] = sizeof(junk);
  ctx->snap_idx     = 0U;
  ctx->snap_fd      = fx->fd;

  /* snapshot being produced */
  ctx->incremental = base_slot!=ULONG_MAX;
  ctx->base_slot   = base_slot;
  ctx->start_time  = fd_log_wallclock();

  /* shared state with snapzp */
  FD_TEST( fd_backup_footprint( 1UL )<=sizeof(test_backup_mem) );
  FD_TEST( fd_backup_new( test_backup_mem, 1UL ) );
  ctx->stats = fd_backup_stats( test_backup_mem );

  /* accdb snapshot sync, as left by snap_start */
  fx->sync = FD_ACCDB_SNAPSHOT_SYNC_RUNNING;
  ctx->accdb_snapshot_sync = &fx->sync;

  /* out links and stem */
  ctx->zp_cnt   = ZP_CNT;
  ctx->zp_ready = fd_ulong_mask( 0, (int)ZP_CNT-1 );
  for( ulong i=0UL; i<ZP_CNT; i++ ) {
    setup_out_link( fx, i, sizeof(fd_backup_frag_t), &ctx->zp_out[ i ].mem, &ctx->zp_out[ i ].chunk0, &ctx->zp_out[ i ].wmark );
    ctx->zp_out[ i ].chunk = ctx->zp_out[ i ].chunk0;
  }
  setup_out_link( fx, SNAPMK_OUT, sizeof(fd_snapmk_msg_t), &ctx->out.mem, &ctx->out.chunk0, &ctx->out.wmark );
  ctx->out.out_idx  = SNAPMK_OUT;
  ctx->out.chunk    = ctx->out.chunk0;
  ctx->out.seq_prod = fd_mcache_seq_laddr( test_mcaches[ SNAPMK_OUT ] );

  *test_min_cr_avail = ULONG_MAX;
  *test_stem = (fd_stem_context_t) {
    .mcaches             = test_mcaches,
    .seqs                = test_seqs,
    .depths              = test_depths,
    .cr_avail            = test_cr_avail,
    .min_cr_avail        = test_min_cr_avail,
    .cr_decrement_amount = 0UL,
    .out_reliable        = test_out_reliable
  };
  return fx;
}

static void
fixture_delete( fixture_t * fx ) {
  close( fx->fd );
  unlink( fx->path );
  fd_wksp_free_laddr( fx->bank );
  FD_TEST( 0==munmap( fx->ctx, fd_ulong_align_up( sizeof(fd_snapmk_t), 4096UL ) ) );
}

/* accdb (in production: the replay tile) acknowledges DONE by moving
   the sync word back to IDLE. */

static void *
accdb_sync_ack( void * arg ) {
  ulong * sync = arg;
  while( fd_accdb_snapshot_sync_state( sync )!=FD_ACCDB_SNAPSHOT_SYNC_DONE ) FD_SPIN_PAUSE();
  fd_accdb_snapshot_sync_advance( sync, FD_ACCDB_SNAPSHOT_SYNC_IDLE );
  return NULL;
}

/* run_until steps after_credit until the tile reaches state (or gives
   up). */

static void
run_until( fixture_t * fx,
           uint        state ) {
  for( ulong i=0UL; i<1000UL; i++ ) {
    if( fx->ctx->state==state ) return;
    int poll_in = 0; int charge_busy = 0;
    after_credit( fx->ctx, test_stem, &poll_in, &charge_busy );
  }
  FD_LOG_ERR(( "tile stuck in state %u, wanted %u", fx->ctx->state, state ));
}

static fd_frag_meta_t const *
mcache_line( ulong out_idx,
             ulong seq ) {
  return test_mcaches[ out_idx ] + fd_mcache_line_idx( seq, DEPTH );
}

/* file_is_unlocked checks from another process whether the pool file
   can be write locked (fcntl locks are per process). */

static int
file_is_unlocked( char const * path ) {
  fflush( NULL );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( pid==0 ) {
    int fd = open( path, O_RDWR );
    if( fd<0 ) _exit( 2 );
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    _exit( fcntl( fd, F_SETLK, &lock ) ? 1 : 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  return WIFEXITED( status ) && WEXITSTATUS( status )==0;
}

/* An incremental snapshot whose snapzp tiles overflowed the slot
   window is discarded once all accounts are flushed: the file is
   emptied and unlocked, the pool slot is free again, every snapzp tile
   gets DONE, accdb is released, and replay gets FAILED. */

static void
test_overflow_discards_incremental( fd_wksp_t * wksp ) {
  ulong const base = 449759793UL;
  fixture_t fx[1];
  fixture_new( fx, wksp, base, base+3UL );
  fd_snapmk_t * ctx = fx->ctx;

  __atomic_store_n( &ctx->stats->appendvec_overflow, 1UL, __ATOMIC_RELEASE );
  FD_TEST( !file_is_unlocked( fx->path ) );

  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, accdb_sync_ack, &fx->sync ) );

  ctx->state = SNAPMK_STATE_ACCDB_DELTA_FINISH;
  run_until( fx, SNAPMK_STATE_SLEEP );
  FD_TEST( !pthread_join( thread, NULL ) );

  /* archive discarded */
  struct stat st;
  FD_TEST( 0==fstat( fx->fd, &st ) );
  FD_TEST( st.st_size==0L );
  FD_TEST( file_is_unlocked( fx->path ) );
  FD_TEST( ctx->pool_sz[ 0 ]==0UL );
  FD_TEST( ctx->pool[ 0 ].full_slot==ULONG_MAX );
  FD_TEST( ctx->pool[ 0 ].incr_slot==ULONG_MAX );
  FD_TEST( ctx->snap_fd==-1 );
  FD_TEST( ctx->snap_idx==UINT_MAX );

  /* every snapzp tile was told DONE, exactly once */
  for( ulong i=0UL; i<ZP_CNT; i++ ) {
    FD_TEST( test_seqs[ i ]==1UL );
    fd_frag_meta_t const * line = mcache_line( i, 0UL );
    FD_TEST( line->seq==0UL );
    FD_TEST( fd_frag_meta_ctl_orig( line->ctl )==FD_BACKUP_ORIG_DONE );
  }

  /* accdb released */
  FD_TEST( fx->sync==FD_ACCDB_SNAPSHOT_SYNC_IDLE );

  /* replay told FAILED, exactly once, for this snapshot */
  FD_TEST( test_seqs[ SNAPMK_OUT ]==1UL );
  fd_frag_meta_t const * line = mcache_line( SNAPMK_OUT, 0UL );
  FD_TEST( line->seq==0UL );
  FD_TEST( line->sig==FD_SNAPMK_MSG_FAILED );
  FD_TEST( line->sz==sizeof(fd_snapmk_msg_failed_t) );
  fd_snapmk_msg_failed_t const * msg = fd_chunk_to_laddr_const( ctx->out.mem, line->chunk );
  FD_TEST( msg->slot==base+3UL );
  FD_TEST( msg->base_slot==base );

  fixture_delete( fx );
}

/* The START message tells each snapzp tile the base slot (ULONG_MAX
   for a full snapshot) so it can bound the appendvec slots. */

static void
test_start_carries_base_slot( fd_wksp_t * wksp ) {
  struct { ulong base_slot; ulong snapshot_slot; } const cases[] = {
    { 449759793UL, 449759993UL }, /* incremental */
    { ULONG_MAX,   100UL       }  /* full */
  };
  for( ulong c=0UL; c<sizeof(cases)/sizeof(cases[0]); c++ ) {
    fixture_t fx[1];
    fixture_new( fx, wksp, cases[ c ].base_slot, cases[ c ].snapshot_slot );
    fd_snapmk_t * ctx = fx->ctx;

    broadcast_prepare( ctx );
    ctx->state = SNAPMK_STATE_START;
    run_until( fx, SNAPMK_STATE_TAR_HEADERS );

    for( ulong i=0UL; i<ZP_CNT; i++ ) {
      FD_TEST( test_seqs[ i ]==1UL );
      fd_frag_meta_t const * line = mcache_line( i, 0UL );
      FD_TEST( fd_frag_meta_ctl_orig( line->ctl )==FD_BACKUP_ORIG_START );
      FD_TEST( line->sz==sizeof(fd_backup_start_msg_t) );
      fd_backup_start_msg_t const * msg = fd_chunk_to_laddr_const( ctx->zp_out[ i ].mem, line->chunk );
      FD_TEST( msg->slot     ==cases[ c ].snapshot_slot );
      FD_TEST( msg->base_slot==cases[ c ].base_slot     );
    }
    fixture_delete( fx );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1UL<<14, fd_shmem_cpu_idx( 0UL ), "wksp", 0UL );
  FD_TEST( wksp );

  test_overflow_discards_incremental( wksp );
  test_start_carries_base_slot( wksp );

  /* tile entry points not exercised here */
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)privileged_init;
  (void)unprivileged_init;
  (void)scratch_align;
  (void)scratch_footprint;
  (void)returnable_frag;
  (void)metrics_write;
  (void)check_credit;
  (void)recv_credit;
  (void)snapmk_run;
  (void)max_event_sz;

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
