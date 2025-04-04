#include "fd_grpc.h"
#include "../h2/fd_hpack_wr.h"
#include "../../app/fdctl/version.h"

static int
fd_hpack_wr_content_type_grpc( fd_h2_rbuf_t * rbuf_tx ) {
  static char const code[] =
    "\x5f" "\x16" "application/grpc+proto";
  if( FD_UNLIKELY( fd_h2_rbuf_free_sz( rbuf_tx)<sizeof(code)-1 ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, code, sizeof(code)-1 );
  return 1;
}

int
fd_grpc_h2_gen_request_hdr( fd_grpc_req_t const * req,
                            fd_h2_rbuf_t *        rbuf_tx ) {
  if( FD_UNLIKELY( !fd_hpack_wr_method_post( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_scheme( rbuf_tx, 1 ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_path( rbuf_tx, req->path, req->path_len ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_trailers( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_content_type_grpc( rbuf_tx ) ) ) return 0;
  static char const user_agent[] =
    "grpc-firedancer/" FD_EXPAND_THEN_STRINGIFY(FDCTL_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_PATCH_VERSION);
  if( FD_UNLIKELY( !fd_hpack_wr_user_agent( rbuf_tx, user_agent, sizeof(user_agent)-1 ) ) ) return 0;
  return 1;
}
