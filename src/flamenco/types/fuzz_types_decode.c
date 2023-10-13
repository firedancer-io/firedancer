#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "fd_types_meta.h"
#include "../fd_flamenco.h"
#include "fd_types.h"

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

  FD_SCRATCH_SCOPED_FRAME;

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
