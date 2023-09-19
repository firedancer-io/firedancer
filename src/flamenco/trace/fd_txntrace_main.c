#include "fd_txntrace.h"
#include "../nanopb/pb_decode.h"
#include "../fd_flamenco.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define SCRATCH_DEPTH (64UL)

static uint fail = 0U;

static void
replay( char const * path,
        fd_wksp_t *  wksp ) {
  fail++;

  /* Read Protobuf file to scratch memory */
  int pb_fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( pb_fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%d-%s)", path, errno, fd_io_strerror( errno ) ));
    return;
  }
  uchar * buf = fd_scratch_prepare( 1UL );
  ulong maxsz = fd_scratch_free();
  long sz = read( pb_fd, buf, maxsz );
  if( FD_UNLIKELY( sz<0L ) ) {
    FD_LOG_WARNING(( "read(%s) failed (%d-%s)", path, errno, fd_io_strerror( errno ) ));
    fd_scratch_cancel();
    return;
  } else if( FD_UNLIKELY( (ulong)sz==maxsz ) ) {
    FD_LOG_WARNING(( "read(%s) failed (out of memory)", path ));
    fd_scratch_cancel();
    return;
  }
  fd_scratch_publish( buf+sz );
  close( pb_fd );

  /* Deserialize */
  pb_istream_t istream = pb_istream_from_buffer( buf, (ulong)sz );
  fd_soltrace_TxnTrace trace[1];
  if( FD_UNLIKELY( !pb_decode( &istream, fd_soltrace_TxnTrace_fields, trace ) ) ) {
    FD_LOG_WARNING(( "pb_decode(%s) failed (%s)", path, PB_GET_ERROR( &istream ) ));
    return;
  }

  /* Replay */
  fd_soltrace_TxnDiff * diff = fd_txntrace_replay( trace->input, wksp );
  fd_wksp_free_laddr( diff );

  /* Cleanup */
  pb_release( fd_soltrace_TxnTrace_fields, trace );
  fail--;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  /* Create workspace and scratch allocator */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));

  ulong fmem[ SCRATCH_DEPTH ];
  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );

  /* Ad-hoc replay each given file */

  for( int i=1; i<argc; i++ ) {
    fd_scratch_push();
    replay( argv[i], wksp );
    fd_scratch_pop();
  }

  /* Cleanup */

  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_flamenco_halt();
  fd_halt();
  return !!fail;
}
