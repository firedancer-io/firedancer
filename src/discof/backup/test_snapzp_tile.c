/* Tests for the snapzp appendvec writer.  Every flushed compression
   frame becomes one tar entry named accounts/<slot>.0.  Agave keys
   storages by slot and rejects an archive with two appendvecs at the
   same slot, so the slots must be distinct across all snapzp tiles
   and must fit the archive's slot window (see
   fd_backup_appendvec_slot).  Drives zip_flush directly on hand-built
   tile contexts and reads the tar headers back from the output file. */

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

/* snapmk resets the shared appendvec allocator before it broadcasts
   START to the snapzp tiles. */

static void
fixture_snapmk_start( fixture_t * fx ) {
  __atomic_store_n( &fx->stats->appendvec_next,     0UL, __ATOMIC_RELAXED );
  __atomic_store_n( &fx->stats->appendvec_overflow, 0UL, __ATOMIC_RELEASE );
  fx->file_off = 0UL;
  FD_TEST( 0==ftruncate( fx->fd, 0L ) );
}

/* tile_new builds the parts of a snapzp tile context that zip_flush
   touches, mirroring unprivileged_init. */

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
  ctx->zst = ZSTD_initStaticCStream( zst_mem, zst_sz );
  FD_TEST( ctx->zst );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_BACKUP_ZSTD_LEVEL ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableInBuffer,  1 ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableOutBuffer, 1 ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_srcSizeHint, (int)RAW_BUF_SZ ) ) );
  ctx->zst_in_rec = ZSTD_CStreamInSize();
  ctx->raw        = ctx->raw_buf1;
  ctx->raw_buf    = (ZSTD_inBuffer ){ .src = ctx->raw_buf1, .size = 0UL };
  ctx->comp_buf   = (ZSTD_outBuffer){ .dst = ctx->comp_buf1+COMP_HEAD, .size = COMP_BUF_SZ-COMP_HEAD };

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
            ulong         sz,
            uchar         fill ) {
  FD_TEST( sz<=RAW_BUF_SZ );
  ulong off = fx->file_off;
  fd_memset( ctx->raw, fill, sz );
  ctx->raw_buf.pos  = 0UL;
  ctx->raw_buf.size = sz;
  zip_flush( ctx );
  return off;
}

/* frame_check reads back the tar header of the frame at off and
   verifies its name and size. */

static void
frame_check( fixture_t *  fx,
             ulong        off,
             ulong        expected_slot,
             ulong        expected_sz ) {
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

  ulong off0 = tile_flush( t0, fx, 4096UL, 0x11 );
  ulong off1 = tile_flush( t1, fx, 1000UL, 0x22 );
  ulong off2 = tile_flush( t0, fx,  512UL, 0x33 );
  ulong off3 = tile_flush( t1, fx, RAW_BUF_SZ, 0x44 );
  FD_TEST( off0<off1 && off1<off2 && off2<off3 && off3<fx->file_off );

  frame_check( fx, off0, snap,     4096UL );
  frame_check( fx, off1, snap-1UL, 1000UL );
  frame_check( fx, off2, snap-2UL,  512UL );
  frame_check( fx, off3, snap-3UL, RAW_BUF_SZ );

  FD_TEST( __atomic_load_n( &fx->stats->appendvec_next,     __ATOMIC_RELAXED )==4UL );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==0UL );
}

/* A full snapshot at a tiny slot (localnet) may use slot 0. */

static void
test_full_slot_zero( fixture_t * fx ) {
  fixture_snapmk_start( fx );
  fd_snapzp_t * t0 = tile_new( fx, 0UL );
  tile_start( t0, fx, 2UL, ULONG_MAX );

  ulong off0 = tile_flush( t0, fx, 512UL, 0x11 );
  ulong off1 = tile_flush( t0, fx, 512UL, 0x22 );
  ulong off2 = tile_flush( t0, fx, 512UL, 0x33 );
  frame_check( fx, off0, 2UL, 512UL );
  frame_check( fx, off1, 1UL, 512UL );
  frame_check( fx, off2, 0UL, 512UL );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==0UL );
}

/* Incremental appendvecs stay strictly above the base slot.  Once the
   window is exhausted the tile raises the shared overflow flag and
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

  ulong off0 = tile_flush( t0, fx, 4096UL, 0x11 );
  ulong off1 = tile_flush( t1, fx, 4096UL, 0x22 );
  ulong off2 = tile_flush( t0, fx, 4096UL, 0x33 );
  frame_check( fx, off0, snap,     4096UL );
  frame_check( fx, off1, snap-1UL, 4096UL );
  frame_check( fx, off2, base+1UL, 4096UL );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==0UL );
  ulong file_sz = fx->file_off;

  /* fourth appendvec would land on the base slot: dropped */
  tile_flush( t1, fx, 4096UL, 0x44 );
  FD_TEST( fx->file_off==file_sz );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==1UL );
  FD_TEST( t1->appendvec_overflow );
  FD_TEST( !t0->appendvec_overflow );
  struct stat st;
  FD_TEST( 0==fstat( fx->fd, &st ) );
  FD_TEST( (ulong)st.st_size==file_sz );

  /* the tile that overflowed keeps dropping */
  tile_flush( t1, fx, 512UL, 0x55 );
  FD_TEST( fx->file_off==file_sz );

  /* the other tile also has no slot left */
  tile_flush( t0, fx, 512UL, 0x66 );
  FD_TEST( fx->file_off==file_sz );
  FD_TEST( t0->appendvec_overflow );
  FD_TEST( 0==fstat( fx->fd, &st ) );
  FD_TEST( (ulong)st.st_size==file_sz );
}

/* The next START clears a tile's overflow state, and a wider window
   fits the same frames. */

static void
test_start_clears_overflow( fixture_t * fx ) {
  ulong const base = 449759793UL;
  fixture_snapmk_start( fx );
  fd_snapzp_t * t0 = tile_new( fx, 0UL );
  tile_start( t0, fx, base+1UL, base );
  tile_flush( t0, fx, 512UL, 0x11 );
  tile_flush( t0, fx, 512UL, 0x22 ); /* overflow */
  FD_TEST( t0->appendvec_overflow );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==1UL );

  fixture_snapmk_start( fx );
  tile_start( t0, fx, base+200UL, base );
  FD_TEST( !t0->appendvec_overflow );
  ulong off0 = tile_flush( t0, fx, 512UL, 0x33 );
  ulong off1 = tile_flush( t0, fx, 512UL, 0x44 );
  frame_check( fx, off0, base+200UL, 512UL );
  frame_check( fx, off1, base+199UL, 512UL );
  FD_TEST( __atomic_load_n( &fx->stats->appendvec_overflow, __ATOMIC_ACQUIRE )==0UL );
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
    tile_flush( t0, fx, 512UL, 0x11 ); /* slot 1 */
    tile_flush( t0, fx, 512UL, 0x22 ); /* slot 0 */
    tile_flush( t0, fx, 512UL, 0x33 ); /* no slot left: must not return */
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  /* FD_LOG_ERR exits with status 1; a crash would show as a signal */
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );

  /* the child shares the open file: the two frames before the fatal
     one were written, each padded to one 4 KiB block */
  struct stat st;
  FD_TEST( 0==fstat( fx->fd, &st ) );
  FD_TEST( (ulong)st.st_size==2UL*4096UL );
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
  test_full_slot_zero( fx );
  test_incremental_overflow_stops_writing( fx );
  test_start_clears_overflow( fx );
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
