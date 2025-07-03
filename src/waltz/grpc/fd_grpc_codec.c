#include "fd_grpc_codec.h"
#include "../h2/fd_hpack.h"
#include "../h2/fd_hpack_wr.h"

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
                             fd_h2_rbuf_t *             rbuf_tx,
                             char const *               version,
                             ulong                      version_len ) {
  if( FD_UNLIKELY( !fd_hpack_wr_method_post( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_scheme( rbuf_tx, 1 ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_path( rbuf_tx, req->path, req->path_len ) ) ) return 0;
  if( req->host_len ) {
    if( FD_UNLIKELY( !fd_hpack_wr_authority( rbuf_tx, req->host, req->host_len, req->port ) ) ) return 0;
  }
  if( FD_UNLIKELY( !fd_hpack_wr_trailers( rbuf_tx ) ) ) return 0;
  if( FD_UNLIKELY( !fd_hpack_wr_content_type_grpc( rbuf_tx ) ) ) return 0;

  static char const user_agent[] = "grpc-firedancer/";
  ulong const user_agent_len = sizeof(user_agent)-1 + version_len;
  if( FD_UNLIKELY( !fd_hpack_wr_user_agent( rbuf_tx, user_agent_len ) ) ) return 0;
  fd_h2_rbuf_push( rbuf_tx, user_agent, sizeof(user_agent)-1 );
  fd_h2_rbuf_push( rbuf_tx, version,    version_len          );

  if( req->bearer_auth_len ) {
    if( FD_UNLIKELY( !fd_hpack_wr_auth_bearer( rbuf_tx, req->bearer_auth, req->bearer_auth_len ) ) ) return 0;
  }
  return 1;
}

/* fd_grpc_h2_parse_num parses a decimal number in [1,999]. */

static uint
fd_grpc_h2_parse_num( char const * num,
                      ulong        num_len ) {
  num_len = fd_ulong_min( num_len, 10 );
  char num_cstr[ 11 ];
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( num_cstr ), num, num_len ) );
  return fd_cstr_to_uint( num_cstr );
}

int
fd_grpc_h2_read_response_hdrs( fd_grpc_resp_hdrs_t *       resp,
                               fd_h2_hdr_matcher_t const * matcher,
                               uchar const *               payload,
                               ulong                       payload_sz ) {
  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, payload, payload_sz );
  while( !fd_hpack_rd_done( hpack_rd ) )  {
    static FD_TL uchar scratch_buf[ 4096 ];
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
      resp->h2_status = fd_grpc_h2_parse_num( hdr->value, hdr->value_len );
      break;
    case FD_H2_HDR_CONTENT_TYPE:
      resp->is_grpc_proto =
        ( 0==strncmp( hdr->value, "application/grpc",       hdr->value_len ) ||
          0==strncmp( hdr->value, "application/grpc+proto", hdr->value_len ) );
      break;
    case FD_GRPC_HDR_STATUS:
      resp->grpc_status = fd_grpc_h2_parse_num( hdr->value, hdr->value_len );
      break;
    case FD_GRPC_HDR_MESSAGE:
      resp->grpc_msg_len = (uint)fd_ulong_min( hdr->value_len, sizeof(resp->grpc_msg) );
      if( resp->grpc_msg_len ) {
        fd_memcpy( resp->grpc_msg, hdr->value, resp->grpc_msg_len );
      }
      break;
    }
  }
  return FD_H2_SUCCESS;
}

char const *
fd_grpc_status_cstr( uint status ) {
  switch( status ) {
  case FD_GRPC_STATUS_OK:                   return "ok";
  case FD_GRPC_STATUS_CANCELLED:            return "cancelled";
  case FD_GRPC_STATUS_UNKNOWN:              return "unknown";
  case FD_GRPC_STATUS_INVALID_ARGUMENT:     return "invalid argument";
  case FD_GRPC_STATUS_DEADLINE_EXCEEDED:    return "deadline exceeded";
  case FD_GRPC_STATUS_NOT_FOUND:            return "not found";
  case FD_GRPC_STATUS_ALREADY_EXISTS:       return "already exists";
  case FD_GRPC_STATUS_PERMISSION_DENIED:    return "permission denied";
  case FD_GRPC_STATUS_RESOURCE_EXHAUSTED:   return "resource exhausted";
  case FD_GRPC_STATUS_FAILED_PRECONDITION:  return "failed precondition";
  case FD_GRPC_STATUS_ABORTED:              return "aborted";
  case FD_GRPC_STATUS_OUT_OF_RANGE:         return "out of range";
  case FD_GRPC_STATUS_UNIMPLEMENTED:        return "unimplemented";
  case FD_GRPC_STATUS_INTERNAL:             return "internal";
  case FD_GRPC_STATUS_UNAVAILABLE:          return "unavailable";
  case FD_GRPC_STATUS_DATA_LOSS:            return "data loss";
  case FD_GRPC_STATUS_UNAUTHENTICATED:      return "unauthenticated";
  default:                                  return "unknown";
  }
}
