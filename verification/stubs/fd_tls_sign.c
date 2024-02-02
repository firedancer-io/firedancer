#include <tango/tls/fd_tls.h>

/* fd_tls_sign_fn_stub implements the fd_tls_sign_fn_t callback. */

extern void * fd_tls_sign_ctx_stub;

void
fd_tls_sign_fn_stub( void *        ctx,
                     uchar *       sig,
                     uchar const * payload ) {
  __CPROVER_assert( ctx == fd_tls_sign_ctx_stub, "invalid context" );
  __CPROVER_r_ok( payload, 130UL );
  __CPROVER_havoc_slice( sig, 64UL );
}
