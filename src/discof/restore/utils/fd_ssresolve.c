#include "fd_ssresolve.h"
#include "fd_ssarchive.h"

#include "../../../waltz/http/picohttpparser.h"
#include "../../../util/log/fd_log.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define FD_SSRESOLVE_STATE_FULL_REQ  (0) /* sending request for full snapshot */
#define FD_SSRESOLVE_STATE_FULL_RESP (1) /* receiving full snapshot response */
#define FD_SSRESOLVE_STATE_INC_REQ   (2) /* sending request for incremental snapshot */
#define FD_SSRESOLVE_STATE_INC_RESP  (3) /* receiving incremental snapshot response */
#define FD_SSRESOLVE_STATE_DONE      (4) /* done */

FD_FN_CONST ulong
fd_ssresolve_align( void ) {
  return FD_SSRESOLVE_ALIGN;
}

FD_FN_CONST ulong
fd_ssresolve_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_SSRESOLVE_ALIGN, sizeof(fd_ssresolve_t) );
  return FD_LAYOUT_FINI( l, FD_SSRESOLVE_ALIGN );
}

void *
fd_ssresolve_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ssresolve_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ssresolve_t * ssresolve = FD_SCRATCH_ALLOC_APPEND( l, FD_SSRESOLVE_ALIGN, sizeof(fd_ssresolve_t) );

  fd_ssresolve_init( ssresolve );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ssresolve->magic ) = FD_SSRESOLVE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ssresolve;
}

fd_ssresolve_t *
fd_ssresolve_join( void * _ssresolve ) {
  if( FD_UNLIKELY( !_ssresolve ) ) {
    FD_LOG_WARNING(( "NULL ssresolve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_ssresolve, fd_ssresolve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ssresolve" ));
    return NULL;
  }

  fd_ssresolve_t * ssresolve = (fd_ssresolve_t *)_ssresolve;

  if( FD_UNLIKELY( ssresolve->magic!=FD_SSRESOLVE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ssresolve;
}

void
fd_ssresolve_init( fd_ssresolve_t * ssresolve ) {
  ssresolve->state = FD_SSRESOLVE_STATE_FULL_REQ;

  fd_memset( ssresolve->request, 0, sizeof(ssresolve->request) );
  fd_memset( ssresolve->response, 0, sizeof(ssresolve->response) );
  ssresolve->request_sent = 0UL;
  ssresolve->request_len  = 0UL;
  ssresolve->response_len = 0UL;
}

static void
fd_ssresolve_render_req( fd_ssresolve_t * ssresolve,
                         fd_ip4_port_t    addr ) {
  ssresolve->request_sent = 0UL;
  ssresolve->response_len = 0UL;

  FD_LOG_WARNING(("rendering request for " FD_IP4_ADDR_FMT ":%hu",
                  FD_IP4_ADDR_FMT_ARGS( addr.addr ), addr.port ));
  switch( ssresolve->state ) {
    case FD_SSRESOLVE_STATE_FULL_REQ: {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
           "GET %.*s HTTP/1.1\r\n"
           "User-Agent: Firedancer\r\n"
           "Accept: */*\r\n"
           "Accept-Encoding: identity\r\n"
           "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
           17, "/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( addr.addr ) ) );
      break;
    }
    case FD_SSRESOLVE_STATE_INC_REQ: {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
           "GET %.*s HTTP/1.1\r\n"
           "User-Agent: Firedancer\r\n"
           "Accept: */*\r\n"
           "Accept-Encoding: identity\r\n"
           "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
           29, "/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( addr.addr ) ) );
      break;
    }
  }
}

static int
fd_ssresolve_send_request( fd_ssresolve_t * ssresolve,
                           int              sockfd,
                           fd_ip4_port_t    addr ) {
  FD_TEST( ssresolve->state==FD_SSRESOLVE_STATE_FULL_REQ ||
          ssresolve->state==FD_SSRESOLVE_STATE_INC_REQ );

  fd_ssresolve_render_req( ssresolve, addr );

  long sent = send( sockfd, ssresolve->request+ssresolve->request_sent, ssresolve->request_len-ssresolve->request_sent, 0 );
  if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSRESOLVE_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==sent ) ) {
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  ssresolve->request_sent += (ulong)sent;
  if( FD_UNLIKELY( ssresolve->request_sent==ssresolve->request_len ) ) {
    if( ssresolve->state==FD_SSRESOLVE_STATE_FULL_REQ ) {
      ssresolve->state = FD_SSRESOLVE_STATE_FULL_RESP;
    } else {
      ssresolve->state = FD_SSRESOLVE_STATE_INC_RESP;
    }
    return FD_SSRESOLVE_ADVANCE_SUCCESS;
  }

  return FD_SSRESOLVE_ADVANCE_AGAIN;
}

static int
fd_ssresolve_parse_redirect( fd_ssresolve_t *        ssresolve,
                             struct phr_header *     headers,
                             ulong                   header_cnt,
                             fd_ssresolve_result_t * result ) {
  ulong        location_len = 0UL;
  char const * location     = NULL;

  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_UNLIKELY( !strncasecmp( headers[ i ].name, "location", headers[ i ].name_len ) ) ) {
      if( FD_UNLIKELY( !headers [ i ].value_len || headers[ i ].value[ 0 ]!='/' ) ) {
        FD_LOG_WARNING(( "invalid location header `%.*s`", (int)headers[ i ].value_len, headers[ i ].value ));
        return FD_SSRESOLVE_ADVANCE_ERROR;
      }

      location_len = headers[ i ].value_len;
      location = headers[ i ].value;
      break;
    }
  }

  if( FD_UNLIKELY( location_len>=PATH_MAX-1UL ) ) return FD_SSRESOLVE_ADVANCE_ERROR;

  char snapshot_name[ PATH_MAX ];
  fd_memcpy( snapshot_name, location+1UL, location_len-1UL );
  snapshot_name[ location_len-1UL ] = '\0';

  ulong full_entry_slot, incremental_entry_slot;
  uchar decoded_hash[ FD_HASH_FOOTPRINT ];
  int err = fd_ssarchive_parse_filename( snapshot_name, &full_entry_slot, &incremental_entry_slot, decoded_hash );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "unrecognized snapshot file `%s` in redirect location header", snapshot_name ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  if( incremental_entry_slot==ULONG_MAX ) {
    result->slot      = full_entry_slot;
    result->base_slot = ULONG_MAX;
  } else {
    result->slot      = incremental_entry_slot;
    result->base_slot = full_entry_slot;
  }
  fd_memcpy( result->hash.hash, decoded_hash, FD_HASH_FOOTPRINT );

  if( ssresolve->state==FD_SSRESOLVE_STATE_FULL_RESP ) {
    ssresolve->state = FD_SSRESOLVE_STATE_INC_REQ;
  } else {
    ssresolve->state = FD_SSRESOLVE_STATE_DONE;
  }

  return FD_SSRESOLVE_ADVANCE_SUCCESS;
}

static int
fd_ssresolve_read_response( fd_ssresolve_t *        ssresolve,
                            int                     sockfd,
                            fd_ssresolve_result_t * result ) {
  FD_TEST( ssresolve->state==FD_SSRESOLVE_STATE_FULL_RESP ||
           ssresolve->state==FD_SSRESOLVE_STATE_INC_RESP );
  long read = recv( sockfd, ssresolve->response+ssresolve->response_len, sizeof(ssresolve->response)-ssresolve->response_len, 0 );
  if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) return FD_SSRESOLVE_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==read ) ) {
    FD_LOG_WARNING(( "recv() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  ssresolve->response_len += (ulong)read;

  int               minor_version;
  int               status;
  const char *      message;
  ulong             message_len;
  struct phr_header headers[ 128UL ];
  ulong             header_cnt = 128UL;
  int parsed = phr_parse_response( ssresolve->response,
                                    ssresolve->response_len,
                                    &minor_version,
                                    &status,
                                    &message,
                                    &message_len,
                                    headers,
                                    &header_cnt,
                                    ssresolve->response_len - (ulong)read );
  if( FD_UNLIKELY( parsed==-1 ) ) {
    FD_LOG_WARNING(( "malformed response body" ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  } else if( parsed==-2 ) {
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  int is_redirect = (status==301) | (status==303) | (status==304) | (status==307) | (status==308);
  if( FD_UNLIKELY( is_redirect ) ) {
    return fd_ssresolve_parse_redirect( ssresolve, headers, header_cnt, result );
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "unexpected response status %d", status ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  return FD_SSRESOLVE_ADVANCE_ERROR;
}

int
fd_ssresolve_advance_poll_out( fd_ssresolve_t *        ssresolve,
                               int                     sockfd,
                               fd_ip4_port_t           addr ) {
  int res;
  switch( ssresolve->state ) {
    case FD_SSRESOLVE_STATE_FULL_REQ: {
      res = fd_ssresolve_send_request( ssresolve, sockfd, addr );
      break;
    }
    case FD_SSRESOLVE_STATE_INC_REQ: {
      res = fd_ssresolve_send_request( ssresolve, sockfd, addr );
      break;
    }
    case FD_SSRESOLVE_STATE_FULL_RESP:
    case FD_SSRESOLVE_STATE_INC_RESP:
    case FD_SSRESOLVE_STATE_DONE: {
      res = FD_SSRESOLVE_ADVANCE_PASS;
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
  }
  return res;
}

int
fd_ssresolve_advance_poll_in( fd_ssresolve_t *        ssresolve,
                              int                     sockfd,
                              fd_ssresolve_result_t * result ) {
  int res;
  switch( ssresolve->state ) {
    case FD_SSRESOLVE_STATE_FULL_RESP:
    case FD_SSRESOLVE_STATE_INC_RESP: {
      res = fd_ssresolve_read_response( ssresolve, sockfd, result );
      break;
    }
    case FD_SSRESOLVE_STATE_FULL_REQ:
    case FD_SSRESOLVE_STATE_INC_REQ:
    case FD_SSRESOLVE_STATE_DONE: {
      res = FD_SSRESOLVE_ADVANCE_PASS;
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
  }

  return res;
}

int
fd_ssresolve_is_done( fd_ssresolve_t * ssresolve ) {
  return ssresolve->state==FD_SSRESOLVE_STATE_DONE;
}
