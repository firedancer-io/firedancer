#include "../../fd_ballet.h"
#include "fd_r43x6_ge.h"

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* This is the code that was used to generate the tables used by
     ge_smul_small and ge_smul_large.  Defaults are small symmetrized
     table for accelerated scalar multiplication by 256 bit ulongs.  Use
     NK==8 for the corresponding large table. */

  char const * path = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL       );
  int          NK   = fd_env_strip_cmdline_int(  &argc, &argv, "--NK",   NULL, 4          );
  int          NJ   = fd_env_strip_cmdline_int(  &argc, &argv, "--NJ",   NULL, 256/(2*NK) );
  int          W0   = fd_env_strip_cmdline_int(  &argc, &argv, "--W0",   NULL, 1          );
  int          W1   = fd_env_strip_cmdline_int(  &argc, &argv, "--W1",   NULL, 1<<(NK-1)  );

  if( !path ) FD_LOG_ERR(( "--path not specified" ));

  int   NW = W1-W0+1;
  ulong sz = ((ulong)(NJ*NW*3))*sizeof(wwl_t);

  FD_LOG_NOTICE(( "Using --path %s --NJ %i --NK %i --W0 %i --W1 %i (NW %i sz %luB)", path, NJ, NK, W0, W1, NW, sz ));

  FD_LOG_NOTICE(( "Computing table" ));

  wwl_t * table = (wwl_t *)fd_alloca( 128UL, sz );

  FD_R43X6_QUAD_DECL( Bj ); FD_R43X6_GE_ONE( Bj );

  /* At this point Bj = B */

  for( int j=0; j<NJ; j++ ) {

    /* At this point Bj = 2^(NJ*j) B */

    for( int w=W0; w<=W1; w++ ) {

      FD_R43X6_QUAD_DECL( P ); FD_R43X6_QUAD_MOV( P, Bj );
      FD_R43X6_QUAD_DECL( Q ); FD_R43X6_GE_ZERO( Q );

      /* At this point P = 2^(NJ*j) B */

      for( int k=0; k<NK; k++ ) {

        /* At this point P = 2^(NJ*j+k) B */

        int sb = (w>>k) & 1;
        if( sb ) FD_R43X6_GE_ADD( Q, Q, P );
        FD_R43X6_GE_DBL( P, P );

        /* At this point P = 2^(NJ*j+k+1) B */
      }

      /* At this point, Q = w 2^(NJ*j) B */

      /* This below could be streamlined more (e.g. mul4 to get
         qx,qy,1,qt from QT and one_QZ) but this is all done out of band
         and simpler to follow done as below. */

      fd_r43x6_t QX,QY,QZ,QT;
      FD_R43X6_QUAD_UNPACK( QX,QY,QZ,QT, Q );
      (void)QT;

      fd_r43x6_t one_QZ = fd_r43x6_invert( QZ );

      fd_r43x6_t qx   = fd_r43x6_mul( QX, one_QZ );
      fd_r43x6_t qy   = fd_r43x6_mul( QY, one_QZ );
      fd_r43x6_t qt   = fd_r43x6_mul( qx, qy );
      fd_r43x6_t qt2d = fd_r43x6_mul( fd_r43x6_2d(), qt );

      FD_R43X6_QUAD_DECL( T );
      FD_R43X6_QUAD_PACK( T, fd_r43x6_mod( fd_r43x6_sub_fast( qy, qx ) ),   /*    Y-X, reduced */
                             fd_r43x6_mod( fd_r43x6_add_fast( qy, qx ) ),   /*    Y+X, reduced */
                             fd_r43x6_mod( fd_r43x6_neg( qt2d )        ),   /* -T*2*d, reduced */
                             fd_r43x6_mod(               qt2d          ) ); /*  T*2*d, reduced */

      int idx = (j*NW + (w-W0))*3;
      table[ idx + 0 ] = T03;
      table[ idx + 1 ] = T14;
      table[ idx + 2 ] = T25;
    }

    for( int rem=2*NK; rem; rem-- ) FD_R43X6_GE_DBL( Bj, Bj );

    /* At this point Bj = 2^(NJ*(j+1)) B */

  }

  FD_LOG_NOTICE(( "Saving table" ));

  FILE * file = fopen( path, "wb" );
  if( FD_UNLIKELY( !file ) ) FD_LOG_ERR(( "fopen faield" ));
  if( FD_UNLIKELY( fwrite( table, sz, 1UL, file )!=1UL ) ) FD_LOG_ERR(( "fwrite failed" ));
  if( FD_UNLIKELY( fclose( file ) ) ) FD_LOG_WARNING(( "fclose failed; attempting to continue" ));

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
