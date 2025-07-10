#include "../../../disco/pack/fd_pack.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "../../../disco/metrics/fd_metrics.h"

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
uchar verify_scratch[ 1024*1024*1024 ] __attribute__((aligned(128)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  char const * wksp_file = fd_env_strip_cmdline_cstr(  &argc, &argv, "--wksp-copy", NULL, NULL );
  ulong        dump_ptr  = fd_env_strip_cmdline_ulong( &argc, &argv, "--dump-ptr",  NULL, 0UL  );

  if( FD_UNLIKELY( !wksp_file | !dump_ptr ) ) FD_LOG_ERR(( "usage %s --wksp-copy /path/to/file --dump-ptr 0x4...0", argv[ 0 ] ));

  int file = open( wksp_file, O_RDWR );
  if( FD_UNLIKELY( file<0 ) ) FD_LOG_ERR(( "failed to open `%s` (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  ulong file_sz = (ulong)lseek( file, 0, SEEK_END );
#define ONE_GB (1024UL*1024UL*1024UL)
#define TWO_MB (2UL*1024UL*1024UL)
  ulong page_sz  = file_sz >= ONE_GB ? ONE_GB : TWO_MB;
  ulong map_addr = dump_ptr & ~(page_sz-1UL);

  void * mem = mmap( (void *)map_addr, page_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, file, 0UL );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "mapped to %p", mem ));
  FD_TEST( (ulong)mem == map_addr );

  fd_pack_leave( (void *)dump_ptr );

  if( FD_UNLIKELY( munmap( mem, page_sz ) ) ) FD_LOG_ERR(( "munmap `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( file ) ) ) FD_LOG_ERR(( "close `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  return 0;
}
