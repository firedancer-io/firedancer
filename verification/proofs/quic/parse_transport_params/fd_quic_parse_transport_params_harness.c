#include <tango/fd_tango_base.h>
#include <tango/quic/templ/fd_quic_transport_params.h>

void
harness( void ) {
  ulong sz;  __CPROVER_assume( sz<=256UL );
  uchar buf[ sz ];
  __CPROVER_assume( (ulong)buf <= 0xffffffffffffff );  /* 56-bit address space */

  fd_quic_transport_params_t params = {0};
  fd_quic_decode_transport_params( &params, buf, sz );
}
