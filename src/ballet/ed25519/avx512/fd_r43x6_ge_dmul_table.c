#include "../../fd_ballet.h"
#include "fd_r43x6_ge.h"

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* This is the code that was used to generate the table for
     dmul_sparse. */

  char const * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL );
  int          max  = fd_env_strip_cmdline_int(  &argc, &argv, "--max",  NULL, 2047 );

  if( !path      ) FD_LOG_ERR(( "--path not specified" ));
  if( !(max & 1) ) FD_LOG_ERR(( "--max should be odd" ));

  ulong sz = ((ulong)(3*(max+1)))*sizeof(wwl_t);

  FD_LOG_NOTICE(( "Using --path %s --max %i (sz %luB)", path, max, sz ));

  FD_LOG_NOTICE(( "Computing table" ));

  wwl_t * table = (wwl_t *)fd_alloca( 128UL, sz );
  FD_R43X6_QUAD_DECL( B );  FD_R43X6_GE_ONE( B );
  fd_r43x6_ge_sparse_table( table, B03, B14, B25, max );

  FD_LOG_NOTICE(( "Saving table" ));

  FILE * file = fopen( path, "wb" );
  if( FD_UNLIKELY( !file ) ) FD_LOG_ERR(( "fopen failed" ));
  if( FD_UNLIKELY( fwrite( table, sz, 1UL, file )!=1UL ) ) FD_LOG_ERR(( "fwrite failed" ));
  if( FD_UNLIKELY( fclose( file ) ) ) FD_LOG_WARNING(( "fclose failed; attempting to continue" ));

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
