#include "../fd_disco.h"
#include "fd_pack.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "../../disco/metrics/fd_metrics.h"

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
uchar verify_scratch[ 1792UL*1024UL*1024UL ] __attribute__((aligned(128)));

int fd_pack_dump( fd_pack_t const * pack );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  char const * wksp_file = fd_env_strip_cmdline_cstr(  &argc, &argv, "--wksp-copy", NULL, NULL );
  ulong        dump_ptr  = fd_env_strip_cmdline_ulong( &argc, &argv, "--dump-ptr",  NULL, 0UL  );
  ulong        orig_ptr  = fd_env_strip_cmdline_ulong( &argc, &argv, "--orig-ptr",  NULL, 0UL  );

  if( FD_UNLIKELY( !wksp_file | !dump_ptr | !orig_ptr ) )
    FD_LOG_ERR(( "usage %s --wksp-copy /path/to/file --dump-ptr 0x4...0 --orig-ptr 0x4...0", argv[ 0 ] ));

  int file = open( wksp_file, O_RDWR );
  if( FD_UNLIKELY( file<0 ) ) FD_LOG_ERR(( "failed to open `%s` (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  struct stat statbuf[1] = {{ 0 }};
  FD_TEST( 0==fstat( file, statbuf ) );

  ulong page_sz  = 1024UL*1024UL*1024UL; /* one 1GB page */
  ulong map_addr = orig_ptr & ~(page_sz-1UL);

  FD_TEST( (ulong)statbuf->st_size % page_sz == 0UL );

  void * mem = mmap( (void *)map_addr, (ulong)statbuf->st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, file, 0UL );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "mapped to %p", mem ));
  FD_TEST( (ulong)mem == map_addr );

  fd_pack_t const * pack_copy     = (fd_pack_t const *)dump_ptr;
  fd_pack_t * original_pack = (fd_pack_t *)orig_ptr;
  fd_memcpy( original_pack, pack_copy, (ulong)pack_copy - (ulong)original_pack );

  fd_pack_dump( original_pack );
  fd_pack_verify( original_pack, verify_scratch );

  if( FD_UNLIKELY( munmap( mem, page_sz ) ) ) FD_LOG_ERR(( "munmap `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( file ) ) ) FD_LOG_ERR(( "close `%s` failed (%i-%s)", wksp_file, errno, fd_io_strerror( errno ) ));

  fd_halt();
  return 0;
}




