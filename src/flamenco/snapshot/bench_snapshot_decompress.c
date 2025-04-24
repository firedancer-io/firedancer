#include "fd_snapshot.h"
#include "fd_snapshot_istream.h"
#include "../../funk/fd_funk.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex.h>
#include <stdlib.h> /* strtoul */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ZSTD_WINDOW_SZ (33554432UL)
#define MANIFEST_DONE          (INT_MAX)

fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt =
  { .file = NULL,
    .read = NULL };

uchar buf[ 16384 ];

struct fd_snapshot_decompress_untar_ctx {
  fd_zstd_dstream_t * zstd;
  fd_io_istream_zstd_t vzstd;

  fd_tar_reader_t    tar;
  fd_io_istream_obj_t vsrc;
  fd_io_istream_file_t vfile;
  fd_tar_io_reader_t vtar;
};
typedef struct fd_snapshot_decompress_untar_ctx fd_snapshot_decompress_untar_ctx_t;

static int
fd_decompress_and_untar( fd_snapshot_decompress_untar_ctx_t * ctx ) {
    ulong buf_sz = 0UL;
    // FD_LOG_WARNING(("reading from zstd!"));
    int read_err = fd_io_istream_obj_read( &ctx->vtar.src, buf, sizeof(buf), &buf_sz );
    // FD_LOG_WARNING(("read %lu bytes", buf_sz));
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
    else {
      FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return read_err;
    }
  
    int tar_err = fd_tar_read( &ctx->vtar.reader, buf, buf_sz, MANIFEST_DONE );
    if( FD_UNLIKELY( tar_err>0 ) ) {
      FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
      return tar_err;
    }
    if( tar_err<0 ) {
      FD_LOG_NOTICE(( "Encountered end of tar stream" ));
      return -1;
    }
  
    return 0;
}


int main( int argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",     NULL, "gigantic" );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",    NULL, 50UL );
  ulong        near_cpu    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",    NULL, fd_log_cpu_id() );
  char const * snapshot = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--snapshot", NULL, NULL );

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", page_cnt, _page_sz ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );

  ulong const static_tag = 1UL;

  fd_spad_t * _spad = fd_spad_new( fd_wksp_alloc_laddr( wksp, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( 4*1024*1024 * 1024UL ), static_tag ), 4*1024*1024 * 1024UL );

  do {
    fd_spad_push( _spad );

    fd_snapshot_decompress_untar_ctx_t ctx;

    /* open the snapshot file descriptor */
    int snapshot_fd = open( snapshot, O_RDONLY );
    if( FD_UNLIKELY( snapshot_fd<0 ) ) {
        FD_LOG_ERR(( "open(%s) failed (%d-%s)", snapshot, errno, fd_io_strerror( errno ) ));
      }
    FD_LOG_NOTICE(("snapshot fd: %d", snapshot_fd));

    /* create the snapshot io stream file */
    if( FD_UNLIKELY( !fd_io_istream_file_new( &ctx.vfile, snapshot_fd ) ) ) {
      FD_LOG_ERR(( "Failed to create fd_io_istream_file_t" ));
    }

    /* Set up the vfile source */
    ctx.vsrc = fd_io_istream_file_virtual( &ctx.vfile );
    /* set up zstd dstream reader */
    ctx.zstd = fd_spad_alloc( _spad, fd_zstd_dstream_align(), fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ));
    fd_zstd_dstream_new( ctx.zstd, ZSTD_WINDOW_SZ );

    if( FD_UNLIKELY( !fd_tar_reader_new( &ctx.tar, &fd_snapshot_restore_tar_vt, NULL ) ) ) {
        FD_LOG_ERR(( "Failed to create fd_tar_reader_t" ));
      }

    /* reset dstream reader */
    fd_zstd_dstream_reset( ctx.zstd );

    /* set up zstd istream reader */
    if( FD_UNLIKELY( !fd_io_istream_zstd_new( &ctx.vzstd, ctx.zstd, ctx.vsrc ) ) ) {
        FD_LOG_ERR(( "Failed to create fd_io_istream_zstd_t" ));
      }

    if( FD_UNLIKELY( !fd_tar_io_reader_new( &ctx.vtar, &ctx.tar, fd_io_istream_zstd_virtual( &ctx.vzstd ) ) ) ) {
      FD_LOG_ERR(( "Failed to create fd_tar_io_reader_t" ));
    }

    FD_LOG_NOTICE(("starting decompress and untar benchmark"));
    long start = fd_log_wallclock();

    for(;;) {
        int err = fd_decompress_and_untar( &ctx );
        if( FD_LIKELY( !err ) ) continue;
        if( err==-1 ) break;
    }
    long end = fd_log_wallclock();
    FD_LOG_NOTICE(( "snapshot decompress and untar took %ld nanos %f seconds %f ops/sec", end-start, ((double)(end-start))/(1000000000UL), 16UL*1048576UL*3UL*1000000000UL/((double)(end-start)) ));

    fd_spad_pop( _spad );
  } while(0);

  return 0;

}