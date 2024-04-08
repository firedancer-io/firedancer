#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>

#include "fd_types_meta.h"
#include "../fd_flamenco.h"
#include "fd_types.h"

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

static inline void
fd_scratch_detach_null( void ) {
  fd_scratch_detach( NULL );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  fd_flamenco_boot( argc, argv );

  /* Set up scrath memory */
  static uchar scratch_mem [ 1UL<<30 ];  /* 1 GB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<30, 4UL );

  atexit( fd_halt );
  atexit( fd_flamenco_halt );
  atexit( fd_scratch_detach_null );
  return 0;
}

static int
fd_decode_fuzz_data( char  const * type_name,
                     uchar const * data,
                     ulong         size ) {

  FD_SCRATCH_SCOPE_BEGIN {

    fd_types_funcs_t type_meta;
    if( fd_flamenco_type_lookup( type_name, &type_meta ) != 0 ) {
      FD_LOG_ERR (( "Failed to lookup type %s", type_name ));
      return -1;
    }

    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = data,
      .dataend = data + size,
      .valloc  = fd_scratch_virtual()
    };
    void * decoded = fd_scratch_alloc( type_meta.align_fun(), type_meta.footprint_fun() );
    if( decoded == NULL ) {
      FD_LOG_ERR (( "Failed to alloc memory for decoded type %s", type_name ));
      return -1;
    }
    int err = type_meta.decode_fun( decoded, &decode_ctx );
    __asm__ volatile( "" : "+m,r"(err) : : "memory" ); /* prevent optimization */

  } FD_SCRATCH_SCOPE_END;

  return 0;
}

#include "fd_type_names.c"

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  uint i;
  for( i = 0; i < FD_TYPE_NAME_COUNT; i++) {
    if( fd_decode_fuzz_data( fd_type_names[i], data, size ) == -1 ) {
      return -1;
    }
  }

  return 0;
}
