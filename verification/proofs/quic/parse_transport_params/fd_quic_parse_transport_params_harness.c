#include <waltz/fd_waltz_base.h>
#include <waltz/quic/templ/fd_quic_transport_params.h>

void
harness( void ) {
  ulong sz;  __CPROVER_assume( sz<=256UL );
  uchar buf[ sz ];

  fd_quic_transport_params_t params = {0};
  fd_quic_decode_transport_params( &params, buf, sz );
}
