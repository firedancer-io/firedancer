#include <stdio.h>
#include "../fd_quic_proto.h"
#include "../templ/fd_quic_union.h"
#include "../templ/fd_quic_parse_util.h"

/* define empty functions for handlers */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                     \
          static ulong                                      \
          fd_quic_frame_handle_##NAME(                      \
                    void *                    context,      \
                    fd_quic_##NAME##_t *      data,         \
                    uchar const *             p,            \
                    ulong                     p_sz ) {      \
            (void)context; (void)data; (void)p; (void)p_sz; \
            return 0u;                                      \
          }
#include "../templ/fd_quic_dft.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_undefs.h"

int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  ulong pkt_sz   = sizeof( fd_quic_pkt_u );
  ulong frame_sz = sizeof( fd_quic_frame_u );

  printf( "packet union size: %lu\n", pkt_sz );
  printf( "frame union size:  %lu\n", frame_sz );

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

