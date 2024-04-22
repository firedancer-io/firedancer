//  --file d2.bin --type vote_state_versioned

#define _GNU_SOURCE
#include <dlfcn.h>

#include "../fd_flamenco.h"
#include "../runtime/fd_runtime.h"
#include "../types/fd_types_yaml.h"

#include <errno.h>
#include <stdio.h>
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

ulong foo_lkasjdf( void ) {
  return fd_vote_state_versioned_footprint();
}

int fd_flamenco_type_lookup(const char *type, fd_types_funcs_t * t) {
  char fp[255];

#pragma GCC diagnostic ignored "-Wpedantic"
  sprintf(fp, "%s_footprint", type);
  t->footprint_fun = dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_align", type);
  t->align_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_new", type);
  t->new_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_decode", type);
  t->decode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_walk", type);
  t->walk_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_encode", type);
  t->encode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_destroy", type);
  t->destroy_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_size", type);
  t->size_fun =  dlsym(RTLD_DEFAULT, fp);

  if ((  t->footprint_fun == NULL) ||
      (  t->align_fun == NULL) ||
      (  t->new_fun == NULL) ||
      (  t->decode_fun == NULL) ||
      (  t->walk_fun == NULL) ||
      (  t->encode_fun == NULL) ||
      (  t->destroy_fun == NULL) ||
      (  t->size_fun == NULL))
    return -1;
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

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
    .valloc  = fd_scratch_virtual()
  };

  fd_flamenco_yaml_t * yaml =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );

  fd_types_funcs_t f;
  if (fd_flamenco_type_lookup(type, &f) != 0)
    FD_LOG_ERR (( "lookup for %s failed", type));

  char *d = fd_valloc_malloc( decode.valloc, f.align_fun(), f.footprint_fun() );
  if (NULL == d)
    FD_LOG_ERR (( "valloc_malloc failed for %s", f.footprint_fun()));

  f.new_fun(d);
  int err = f.decode_fun( d, &decode );
  if( FD_UNLIKELY( err!=0 ) ) return err;

  f.walk_fun(yaml, d, fd_flamenco_yaml_walk, NULL, 0U );

  fd_scratch_pop();
  fd_scratch_detach( NULL );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
