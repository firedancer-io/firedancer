//  --file d2.bin --type vote_state_versioned

#include "../fd_flamenco.h"
#include "../types/fd_types.h"
#include "../types/fd_types_yaml.h"
#include "../types/fd_types_reflect.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h> /* mkdir(2) */
#include <fcntl.h>    /* open(2) */
#include <unistd.h>   /* close(2) */

static void
usage( void ) {
  fprintf( stderr,
    "Usage: fd_solcap_dump --type <type> --file {FILE}\n"
    "\n"
    "dumps the contents of an account.\n"
    "\n"
    "Options:\n"
    "  --file         name                      filename to read\n"
    "  --type         <type>                    type of the data\n"
    "\n" );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Command line handling */

  for( int i=1; i<argc; i++ ) {
    if( 0==strcmp( argv[i], "--help" ) ) {
      usage();
      return 0;
    }
  }

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );
  char const * type       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--type",       NULL, NULL       );
  char const * file       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--file",       NULL, NULL       );

  if ((NULL == type) || (NULL == file)) {
    usage();
    return 0;
  }

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  /* Create scratch allocator */

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));
# define SCRATCH_DEPTH (4UL)
  ulong fmem[ SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );
  fd_scratch_push();

  /* Read file */

  uchar * data;
  ulong   data_sz;
  do {
    /* Open and stat file */
    int fd = open( file, O_RDONLY );
    FD_TEST( fd>=0 );
    struct stat statbuf[1];
    FD_TEST( 0==fstat( fd, statbuf ) );
    data_sz = (ulong)statbuf->st_size;

    /* Allocate scratch buffer for file */
    FD_TEST( fd_scratch_alloc_is_safe( /* align */ 1UL, data_sz ) );
    data = fd_scratch_alloc( /* align */ 1UL, data_sz );

    /* Copy file into memory */
    FD_TEST( (ssize_t)data_sz == read( fd, data, data_sz ) );
    FD_TEST( 0==close( fd ) );
  } while(0);

  /* Decode file */

  fd_bincode_decode_ctx_t decode = {
    .data    = data,
    .dataend = data + data_sz,
  };

  fd_flamenco_yaml_t * yaml =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );

  fd_types_vt_t const * f = fd_types_vt_by_name( type, strlen( type ) );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR (( "lookup for %s failed", type ));

  ulong total_sz = 0UL;
  int err = f->decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err!=0 ) ) return err;

  uchar * d = fd_scratch_alloc( f->align, total_sz );

  f->decode( d, &decode );

  f->walk( yaml, d, fd_flamenco_yaml_walk, NULL, 0U, 0U );

  fd_scratch_pop();
  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
