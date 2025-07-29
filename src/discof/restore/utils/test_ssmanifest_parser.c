#include "fd_ssmanifest_parser.h"
#include "../../../flamenco//types/fd_types.h"
#include "../../../util/fd_util.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( argc!=2 ) ) {
    FD_LOG_ERR(( "Usage: %s <MANIFEST_FILE>", argv[0] ));
    return EXIT_FAILURE;
  }

  struct stat st;
  if( FD_UNLIKELY( -1==stat( argv[1], &st ) ) ) FD_LOG_ERR(( "stat() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  ulong size = (ulong)st.st_size;

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                   );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                          );
  ulong        numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  uchar * buffer = fd_wksp_alloc_laddr( wksp, 1UL, size, 1UL );
  FD_TEST( buffer );

  int fd = open( argv[1], O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ulong read_bytes = 0UL;
  while( read_bytes<size ) {
    long bytes = read( fd, buffer+read_bytes, size-read_bytes );
    if( FD_UNLIKELY( -1==bytes ) ) FD_LOG_ERR(( "read() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !bytes ) ) break;
    read_bytes += (ulong)bytes;
  }

  fd_snapshot_manifest_t * manifest = aligned_alloc( alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  FD_TEST( manifest );

  FD_LOG_NOTICE(( "Parsing %lu bytes from %s", size, argv[1] ));

  fd_bincode_decode_ctx_t ctx = { .data = buffer, .dataend = buffer+size };
  ulong total_sz = 0UL;

  long ts = -fd_log_wallclock();

  int err = fd_solana_manifest_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_solana_manifest_decode_footprint failed (%d)", err ));
  void * manifest_buf = aligned_alloc( FD_SOLANA_MANIFEST_GLOBAL_ALIGN, total_sz );
  FD_TEST( manifest_buf );
  fd_solana_manifest_global_t * manifest_global = fd_solana_manifest_decode_global( manifest_buf, &ctx );
  FD_TEST( manifest_global );
  long elapsed1 = fd_log_wallclock() + ts;
  FD_LOG_NOTICE(( "fd_types decoded %lu bytes in %ld ms", size, elapsed1/(1000L*1000L) ));

  fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint( 1UL<<24UL ) ), 1UL<<24UL, 42UL ) );
  FD_TEST( parser );

  fd_ssmanifest_parser_init( parser, manifest );

  ts = -fd_log_wallclock();

  int result = fd_ssmanifest_parser_consume( parser, buffer, size );
  if( FD_UNLIKELY( result ) ) FD_LOG_ERR(( "fd_ssmanifest_parser_consume failed (%d)", result ));

  elapsed1 = fd_log_wallclock() + ts;
  FD_LOG_NOTICE(( "fd_ssmanifest_parser decoded %lu bytes in %ld ms", size, elapsed1/(1000L*1000L) ));
}
