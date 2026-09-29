/* Drives zip_flush on hand-built snapzp contexts and reads the tar
   entry names back: appendvec slots count down from the snapshot slot
   across tiles, stop at the lowest slot the archive may use, and the
   id takes over from there. */

#define _GNU_SOURCE
#define FD_TILE_TEST
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fd_snapzp_tile.c"

#include <sys/mman.h>

/* shared state that snapmk normally owns */
static fd_backup_stats_t stats[1];
static ulong volatile    file_off;
static ulong volatile    appendvec_slot_ticket;
static int               snap_fd;
static uchar             zst_mem[ 2 ][ 2UL<<20 ] __attribute__((aligned(32)));

static fd_snapzp_t *
tile_new( ulong kind_id ) {
  fd_snapzp_t * ctx = mmap( NULL, fd_ulong_align_up( sizeof(fd_snapzp_t), 4096UL ), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( ctx!=MAP_FAILED );

  ulong zst_sz = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );
  FD_TEST( zst_sz<=sizeof(zst_mem[ 0 ]) );
  ctx->zst = ZSTD_initStaticCStream( zst_mem[ kind_id ], zst_sz );
  FD_TEST( ctx->zst );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableInBuffer,  1 ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableOutBuffer, 1 ) ) );
  ctx->raw      = ctx->raw_buf1;
  ctx->raw_buf  = (ZSTD_inBuffer ){ .src = ctx->raw_buf1, .size = 0UL };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = ctx->comp_buf1+COMP_HEAD, .size = COMP_BUF_SZ-COMP_HEAD };

  ctx->kind_id     = kind_id;
  ctx->stats       = stats;
  ctx->file_off    = &file_off;
  ctx->appendvec_slot_ticket = &appendvec_slot_ticket;
  ctx->snap_fd_cnt = 1UL;
  return ctx;
}

/* flush_name flushes one 512 byte frame and returns the tar entry name
   the tile wrote for it (the tar header sits in plaintext right after
   the Zstandard frame header). */

static char const *
flush_name( fd_snapzp_t * ctx,
            char          name[ static FD_TAR_NAME_SZ ] ) {
  ulong off = file_off;
  ctx->raw_buf.pos  = 0UL;
  ctx->raw_buf.size = FD_TAR_BLOCK_SZ;
  zip_flush( ctx );

  uchar hdr[ COMP_HEAD ];
  FD_TEST( pread( snap_fd, hdr, sizeof(hdr), (long)off )==(long)sizeof(hdr) );
  fd_tar_meta_t const * meta = (fd_tar_meta_t const *)( hdr+COMP_HEAD-FD_TAR_BLOCK_SZ );
  fd_memcpy( name, meta->name, FD_TAR_NAME_SZ );
  return name;
}

/* check_names starts a snapshot on two tiles and flushes frames from
   them alternately, comparing each entry name to expected. */

static void
check_names( ulong               snapshot_slot,
             ulong               slot_lo,
             char const * const * expected,
             ulong               expected_cnt ) {
  fd_snapzp_t * tile[2] = { tile_new( 0UL ), tile_new( 1UL ) };

  appendvec_slot_ticket = snapshot_slot; /* what snapmk does before START */
  for( ulong i=0UL; i<2UL; i++ ) {
    msg_start( tile[ i ], &(fd_backup_start_msg_t){ .slot = snapshot_slot, .slot_lo = slot_lo } );
    tile[ i ]->snap_fd = snap_fd; /* msg_start picks the well-known descriptor */
  }

  for( ulong i=0UL; i<expected_cnt; i++ ) {
    char name[ FD_TAR_NAME_SZ ];
    FD_TEST( !strncmp( flush_name( tile[ i&1UL ], name ), expected[ i ], FD_TAR_NAME_SZ ) );
  }

  for( ulong i=0UL; i<2UL; i++ ) FD_TEST( 0==munmap( tile[ i ], fd_ulong_align_up( sizeof(fd_snapzp_t), 4096UL ) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  snap_fd = memfd_create( "test_snapzp_tile", 0U );
  FD_TEST( snap_fd>=0 );

  /* full snapshot: slots count down to 0, then the id counts up */
  char const * full[] = { "accounts/2.0", "accounts/1.0", "accounts/0.0", "accounts/0.1", "accounts/0.2" };
  check_names( 2UL, 0UL, full, 5UL );

  /* incremental on a full at slot 97: slots stay above it, then the id
     counts up */
  char const * incr[] = { "accounts/100.0", "accounts/99.0", "accounts/98.0", "accounts/98.1", "accounts/98.2" };
  check_names( 100UL, 98UL, incr, 5UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
