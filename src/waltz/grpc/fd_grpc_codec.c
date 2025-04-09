#include "fd_grpc_codec.h"
#include "../h2/fd_hpack.h"
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
fd_grpc_h2_gen_request_hdrs( fd_grpc_req_hdrs_t const * req,
                             fd_h2_rbuf_t *             rbuf_tx ) {
  if( FD_UNLIKELY( !fd_hpack_wr_method_post( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_scheme( rbuf_tx, 1 ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_path( rbuf_tx, req->path, req->path_len ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_trailers( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_content_type_grpc( rbuf_tx ) ) ) return 0;
  static char const user_agent[] =
    "grpc-firedancer/" FD_EXPAND_THEN_STRINGIFY(FDCTL_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_PATCH_VERSION);
  if( FD_UNLIKELY( !fd_hpack_wr_user_agent( rbuf_tx, user_agent, sizeof(user_agent)-1 ) ) ) return 0;
  if( req->bearer_auth_len ) {
    if( FD_UNLIKELY( !fd_hpack_wr_auth_bearer( rbuf_tx, req->bearer_auth, req->bearer_auth_len ) ) ) return 0;
  }
  return 1;
}

int
fd_grpc_h2_read_response_hdrs( fd_grpc_resp_hdrs_t *       resp,
                               fd_h2_hdr_matcher_t const * matcher,
                               uchar const *               payload,
                               ulong                       payload_sz ) {
  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, payload, payload_sz );
  while( !fd_hpack_rd_done( hpack_rd ) )  {
    static uchar scratch_buf[ 4096 ];
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Failed to parse response headers (%u-%s)", err, fd_h2_strerror( err ) ));
      return FD_H2_ERR_PROTOCOL;
    }

    int hdr_idx = fd_h2_hdr_match( matcher, hdr->name, hdr->name_len, hdr->hint );
    switch( hdr_idx ) {
    case FD_H2_HDR_STATUS:
      resp->is_status_ok = (0==strncmp( hdr->value, "200", hdr->value_len ));
      break;
    case FD_H2_HDR_CONTENT_TYPE:
      resp->is_grpc_proto =
        ( 0==strncmp( hdr->value, "application/grpc",       hdr->value_len ) ||
          0==strncmp( hdr->value, "application/grpc+proto", hdr->value_len ) );
      break;
    }
  }
  return FD_H2_SUCCESS;
}
