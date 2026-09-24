/* Drives zip_flush on hand-built snapzp contexts and reads the tar
   headers back: appendvec slots must be distinct across tiles and stay
   inside the archive's window (see fd_backup_appendvec_slot). */

#define FD_TILE_TEST
#include "fd_snapzp_tile.c"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Test fixture: shared state that snapmk normally owns */

struct fixture {
  uchar               backup_mem[ 1UL<<20 ] __attribute__((aligned(128)));
  fd_backup_stats_t * stats;
  ulong volatile      file_off;
  int                 fd;
};

typedef struct fixture fixture_t;

static fixture_t *
fixture_new( fixture_t * fx ) {
  FD_TEST( fd_backup_footprint( 1UL )<=sizeof(fx->backup_mem) );
  FD_TEST( fd_backup_new( fx->backup_mem, 1UL ) );
  fx->stats    = fd_backup_stats( fx->backup_mem );
  fx->file_off = 0UL;

  char path[] = "/tmp/test_snapzp_tile.XXXXXX";
  fx->fd = mkstemp( path );
  FD_TEST( fx->fd>=0 );
  FD_TEST( 0==unlink( path ) );
  return fx;
}

/* what snapmk does before it broadcasts START */

static void
fixture_snapmk_start( fixture_t * fx ) {
  fd_backup_appendvec_reset( fx->stats );
  fx->file_off = 0UL;
  FD_TEST( 0==ftruncate( fx->fd, 0L ) );
}

/* tile_new builds the parts of a snapzp tile context that zip_flush
   touches. */

static fd_snapzp_t *
tile_new( fixture_t * fx,
          ulong       kind_id ) {
  ulong  sz  = fd_ulong_align_up( sizeof(fd_snapzp_t), 4096UL );
  void * mem = mmap( NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( mem!=MAP_FAILED );
  FD_TEST( fd_ulong_is_aligned( (ulong)mem, alignof(fd_snapzp_t) ) );
  fd_snapzp_t * ctx = mem;

  ulong  zst_sz  = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );
  void * zst_mem = aligned_alloc( 32UL, fd_ulong_align_up( zst_sz, 32UL ) );
  FD_TEST( zst_mem );
  zst_init( ctx, zst_mem );

  ctx->kind_id     = kind_id;
  ctx->stats       = fx->stats;
  ctx->file_off    = &fx->file_off;
  ctx->snap_fd_cnt = 1UL;
  ctx->snap_fd     = -1;
  return ctx;
}

/* tile_start delivers a START message.  msg_start selects the
   well-known snapshot descriptor; the test redirects to its temp
   file. */

static void
tile_start( fd_snapzp_t * ctx,
            fixture_t *   fx,
            ulong         snapshot_slot,
            ulong         base_slot ) {
  fd_backup_start_msg_t msg = {
    .slot      = snapshot_slot,
    .base_slot = base_slot,
    .snap_idx  = 0U,
    .fork_id   = 0
  };
  msg_start( ctx, &msg );
  ctx->snap_fd = fx->fd;
}

/* tile_flush buffers sz bytes of account data and flushes one frame.
   Returns the file offset the frame was (or would have been) written
   to. */

static ulong
tile_flush( fd_snapzp_t * ctx,
            fixture_t *   fx,
            ulong         sz ) {
  FD_TEST( sz<=RAW_BUF_SZ );
  ulong off = fx->file_off;
  fd_memset( ctx->raw, 0x5A, sz );
  ctx->raw_buf.pos  = 0UL;
  ctx->raw_buf.size = sz;
  zip_flush( ctx );
  return off;
}

/* frame_check reads back the tar header of the frame at off and
   verifies its name and size. */

static void
frame_check( fixture_t * fx,
             ulong       off,
             ulong       expected_slot,
             ulong       expected_sz ) {
  uchar hdr[ 10UL+sizeof(fd_tar_meta_t) ];
  FD_TEST( pread( fx->fd, hdr, sizeof(hdr), (long)off )==(long)sizeof(hdr) );

  /* Zstandard frame magic, then a raw block holding the tar header */
  FD_TEST( FD_LOAD( uint, hdr )==0xFD2FB528U );
  fd_tar_meta_t const * meta = (fd_tar_meta_t const *)( hdr+10 );
  FD_TEST( fd_tar_meta_is_reg( meta ) );
  FD_TEST( fd_tar_meta_get_size( meta )==expected_sz );

  char expected[ FD_TAR_NAME_SZ ];
  fd_backup_appendvec_name( expected, expected_slot );
  FD_TEST( !strncmp( meta->name, expected, FD_TAR_NAME_SZ ) );
}

static ulong
file_sz( fixture_t * fx ) {
  struct stat st;
  FD_TEST( 0==fstat( fx->fd, &st ) );
  return (ulong)st.st_size;
}

static int
overflowed( fixture_t * fx ) {
  return !!__atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE );
}

/* Two tiles sharing one snapshot hand out consecutive slots counting
   down from the snapshot slot, regardless of which tile flushes. */

static void
test_full_slots_shared_across_tiles( fixture_t * fx ) {
  ulong const snap = 449759793UL;
  fixture_snapmk_start( fx );
  fd_snapzp_t * t0 = tile_new( fx, 0UL );
  fd_snapzp_t * t1 = tile_new( fx, 1UL );
  tile_start( t0, fx, snap, ULONG_MAX );
  tile_start( t1, fx, snap, ULONG_MAX );

  ulong off0 = tile_flush( t0, fx, 4096UL );
  ulong off1 = tile_flush( t1, fx, 1000UL );
  ulong off2 = tile_flush( t0, fx,  512UL );
  ulong off3 = tile_flush( t1, fx, RAW_BUF_SZ );
  FD_TEST( off0<off1 && off1<off2 && off2<off3 && off3<fx->file_off );

  frame_check( fx, off0, snap,     4096UL );
  frame_check( fx, off1, snap-1UL, 1000UL );
  frame_check( fx, off2, snap-2UL,  512UL );
  frame_check( fx, off3, snap-3UL, RAW_BUF_SZ );
  FD_TEST( !overflowed( fx ) );
}

/* Incremental appendvecs stay strictly above the base slot.  Once the
   window is exhausted every tile raises the shared overflow flag and
   stops writing, so snapmk can discard the archive. */

static void
test_incremental_overflow_stops_writing( fixture_t * fx ) {
  ulong const base = 449759793UL;
  ulong const snap = base+3UL;
  fixture_snapmk_start( fx );
  fd_snapzp_t * t0 = tile_new( fx, 0UL );
  fd_snapzp_t * t1 = tile_new( fx, 1UL );
  tile_start( t0, fx, snap, base );
  tile_start( t1, fx, snap, base );

  ulong off0 = tile_flush( t0, fx, 4096UL );
  ulong off1 = tile_flush( t1, fx, 4096UL );
  ulong off2 = tile_flush( t0, fx, 4096UL );
  frame_check( fx, off0, snap,     4096UL );
  frame_check( fx, off1, snap-1UL, 4096UL );
  frame_check( fx, off2, base+1UL, 4096UL );
  FD_TEST( !overflowed( fx ) );
  ulong sz = file_sz( fx );

  /* a fourth appendvec would land on the base slot: this and every
     later frame, from either tile, is dropped */
  tile_flush( t1, fx, 4096UL );
  FD_TEST( overflowed( fx ) );
  tile_flush( t1, fx, 512UL );
  tile_flush( t0, fx, 512UL );
  FD_TEST( fx->file_off==sz );
  FD_TEST( file_sz( fx )==sz );
}

/* A full snapshot that needs more appendvecs than it has slots is a
   fatal error (only reachable with a tiny snapshot slot). */

static void
test_full_overflow_is_fatal( fixture_t * fx ) {
  fixture_snapmk_start( fx );
  fd_snapzp_t * t0 = tile_new( fx, 0UL );
  tile_start( t0, fx, 1UL, ULONG_MAX );

  fflush( NULL );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( pid==0 ) {
    tile_flush( t0, fx, 512UL ); /* slot 1 */
    tile_flush( t0, fx, 512UL ); /* slot 0 */
    tile_flush( t0, fx, 512UL ); /* no slot left: must not return */
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  /* FD_LOG_ERR exits with status 1; a crash would show as a signal */
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );

  /* the child shares the open file: the two frames before the fatal
     one were written, each padded to one 4 KiB block */
  FD_TEST( file_sz( fx )==2UL*4096UL );
  frame_check( fx, 0UL,    1UL, 512UL );
  frame_check( fx, 4096UL, 0UL, 512UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fixture_t fx[1];
  fixture_new( fx );

  test_full_slots_shared_across_tiles( fx );
  test_incremental_overflow_stops_writing( fx );
  test_full_overflow_is_fatal( fx );

  /* tile entry points not exercised here */
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)privileged_init;
  (void)unprivileged_init;
  (void)scratch_align;
  (void)scratch_footprint;
  (void)before_credit;
  (void)returnable_frag;
  (void)metrics_write;
  (void)stem_run;

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
