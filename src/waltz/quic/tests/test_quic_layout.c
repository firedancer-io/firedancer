#include <stdio.h>
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../templ/fd_quic_parse_util.h"

int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  printf( "\n" );
  printf( "frame sizes:\n" );
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                        \
  printf( "%s sz: %lu\n", "fd_quic_" #NAME "_t", (ulong)sizeof( fd_quic_##NAME##_t ) );

#include "../templ/fd_quic_dft.h"
#include "../templ/fd_quic_templ.h"


#include "../templ/fd_quic_undefs.h"

  printf( "\n" );
  printf( "frame sizes:\n" );
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                        \
  printf( "%s sz: %lu\n", "fd_quic_" #NAME "_t", (ulong)sizeof( fd_quic_##NAME##_t ) );

#include "../templ/fd_quic_dft.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_undefs.h"

  return 0;
}

