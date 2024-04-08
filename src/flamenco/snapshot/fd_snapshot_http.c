#include "fd_snapshot_http.h"
#include "../../ballet/http/picohttpparser.h"

#include <assert.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>

/* fd_snapshot_http_set_path renders the 'GET /path' chunk of the HTTP
   request.  The chunk is right aligned and is followed immediately by
   'HTTP/1.1\r\n...' to form a contiguous message. */

int
fd_snapshot_http_set_path( fd_snapshot_http_t * this,
                           char const *         path,
                           ulong                path_len ) {

  if( FD_UNLIKELY( !path_len ) ) {
    path     = "/";
    path_len = 1UL;
  }

  if( FD_UNLIKELY( path_len > FD_SNAPSHOT_HTTP_REQ_PATH_MAX ) ) {
    FD_LOG_DEBUG(( "http: path too long (%lu chars)", path_len ));
    return 0;
  }

  ulong off = sizeof(this->path) - path_len - 4;
  char * p = this->path + off;

  fd_memcpy( p,   "GET ", 4UL      );
  fd_memcpy( p+4, path,   path_len );

  this->req_tail = (ushort)off;
  this->path_off = (ushort)off;
  return 1;
}

fd_snapshot_http_t *
fd_snapshot_http_new( void * mem,
                      uint   dst_ipv4,
                      ushort dst_port ) {

  fd_snapshot_http_t * this = (fd_snapshot_http_t *)mem;
  if( FD_UNLIKELY( !this ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( this, 0, sizeof(fd_snapshot_http_t) );
  this->next_ipv4   = dst_ipv4;
  this->next_port   = dst_port;
  this->socket_fd   = -1;
  this->state       = FD_SNAPSHOT_HTTP_STATE_INIT;
  this->req_timeout = 10e9;  /* 10s */
  this->hops        = 5;

  /* Right-aligned render the request path */

  static char const default_path[] = "/snapshot.tar.bz2";
  int path_ok = fd_snapshot_http_set_path( this, default_path, sizeof(default_path)-1 );
  assert( path_ok );

  /* Left-aligned render the headers, completing the message  */

  char * p = fd_cstr_init( this->req_hdrs );
  static char const hdr_part1[] =
    " HTTP/1.1\r\n"
    "user-agent: Firedancer\r\n"
    "accept: */*\r\n"
    "host: ";
  p = fd_cstr_append_text( p, hdr_part1, sizeof(hdr_part1)-1 );

  p = fd_cstr_append_printf( p, FD_IP4_ADDR_FMT ":%u",
                             FD_IP4_ADDR_FMT_ARGS( dst_ipv4 ), dst_port );
  static char const hdr_part2[] =
    "\r\n"
    "\r\n";
  p = fd_cstr_append_text( p, hdr_part2, sizeof(hdr_part2)-1 );
  this->req_head = (ushort)( p - this->req_buf );

  return this;
}

void *
fd_snapshot_http_delete( fd_snapshot_http_t * this ) {
  if( this->socket_fd>=0 ) {
    close( this->socket_fd );
    this->socket_fd = -1;
  }
  return (void *)this;
}

/* fd_snapshot_http_init gets called the first time an object is polled
   for snapshot data.  Creates a new outgoing TCP connection. */

static int
fd_snapshot_http_init( fd_snapshot_http_t * this ) {

  FD_LOG_INFO(( "Connecting to " FD_IP4_ADDR_FMT ":%u ...",
                FD_IP4_ADDR_FMT_ARGS( this->next_ipv4 ), this->next_port ));

  this->req_deadline = fd_log_wallclock() + this->req_timeout;

  this->socket_fd = socket( AF_INET, SOCK_STREAM, 0 );
  if( FD_UNLIKELY( this->socket_fd < 0 ) ) {
    FD_LOG_WARNING(( "socket(AF_INET, SOCK_STREAM, 0) failed (%d-%s)",
                     errno, fd_io_strerror( errno ) ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return errno;
  }

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = this->next_ipv4 },
    .sin_port   = fd_ushort_bswap( this->next_port ),
  };

  /* TODO consider using O_NONBLOCK socket so we can control the
          connect timeout interval*/

  if( 0!=connect( this->socket_fd, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) ) {
    FD_LOG_WARNING(( "connect(%d," FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                      this->socket_fd,
                      FD_IP4_ADDR_FMT_ARGS( this->next_ipv4 ), this->next_port,
                      errno, fd_io_strerror( errno ) ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return errno;
  }

  FD_LOG_INFO(( "Sending request" ));

  this->state = FD_SNAPSHOT_HTTP_STATE_REQ;
  return 0;
}

/* fd_snapshot_http_req writes out the request. */

static int
fd_snapshot_http_req( fd_snapshot_http_t * this ) {

  long now      = fd_log_wallclock();
  long deadline = this->req_deadline;

  if( FD_UNLIKELY( now > deadline ) ) {
    FD_LOG_WARNING(( "Timed out while sending request." ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return ETIMEDOUT;
  }

  int socket_fd = this->socket_fd;

  uint avail_sz = (uint)this->req_head - (uint)this->req_tail;
  assert( avail_sz < sizeof(this->req_buf) );
  long sent_sz = send( socket_fd, this->req_buf + this->req_tail, avail_sz, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( sent_sz<0L ) {
    if( FD_UNLIKELY( errno!=EWOULDBLOCK ) ) {
      FD_LOG_WARNING(( "send(%d,%p,%u) failed (%d-%s)",
                       socket_fd, (void *)(this->req_buf + this->req_tail), avail_sz,
                       errno, fd_io_strerror( errno ) ));
      this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
      return errno;
    } else {
      return 0;
    }
  }

  this->req_tail = (ushort)( this->req_tail + (uint)sent_sz );
  if( this->req_tail == this->req_head )
    this->state = FD_SNAPSHOT_HTTP_STATE_RESP;

  return 0;
}

/* fd_snapshot_http_follow_redirect winds up the state machine for a
   redirect. */

static int
fd_snapshot_http_follow_redirect( fd_snapshot_http_t *      this,
                                  struct phr_header const * headers,
                                  ulong                     header_cnt ) {

  assert( this->hops > 0 );
  this->hops--;

  /* Look for location header */

  char const * loc = NULL;
  ulong        loc_len;
  for( ulong i = 0; i<header_cnt; i++ ) {
    if( 0==strncasecmp( headers[i].name, "location", headers[i].name_len ) ) {
      loc     = headers[i].value;
      loc_len = headers[i].value_len;
      break;
    }
  }
  if( FD_UNLIKELY( !loc ) ) {
    FD_LOG_WARNING(( "Invalid redirect (no location header)" ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return EINVAL;
  }

  /* Validate character set (TODO too restrictive?) */

  if( FD_UNLIKELY( loc_len > FD_SNAPSHOT_HTTP_REQ_PATH_MAX ) ) {
    FD_LOG_WARNING(( "Redirect location too long" ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return EINVAL;
  }
  if( FD_UNLIKELY( loc_len==0 || loc[0] != '/' ) ) {
    FD_LOG_WARNING(( "Redirect is not an absolute path on the current host. Refusing to follow." ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return EPROTO;
  }
  for( ulong j=0UL; j<loc_len; j++ ) {
    int c = loc[j];
    int c_ok = ( (c>='a') & (c<='z') ) |
               ( (c>='A') & (c<='Z') ) |
               ( (c>='0') & (c<='9') ) |
               (c=='.') | (c=='/') | (c=='-') | (c=='_') |
               (c=='+') | (c=='=') | (c=='&');
    if( FD_UNLIKELY( !c_ok ) ) {
      FD_LOG_WARNING(( "Invalid char '0x%02x' in redirect location", (uint)c ));
      this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
      return EPROTO;
    }
  }

  /* Re-initialize */

  FD_LOG_NOTICE(( "Following redirect to %.*s", (int)loc_len, loc ));

  int set_path_ok = fd_snapshot_http_set_path( this, loc, loc_len );
  assert( set_path_ok );

  this->req_deadline  = fd_log_wallclock() + this->req_timeout;
  this->state     = FD_SNAPSHOT_HTTP_STATE_REQ;
  this->resp_tail = 0U;
  this->resp_head = 0U;

  return 0;
}

/* fd_snapshot_http_resp waits for response headers. */

static int
fd_snapshot_http_resp( fd_snapshot_http_t * this ) {

  long now      = fd_log_wallclock();
  long deadline = this->req_deadline;

  if( FD_UNLIKELY( now > deadline ) ) {
    FD_LOG_WARNING(( "Timed out while receiving response headers." ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return ETIMEDOUT;
  }

  /* Do blocking read of TCP data until timeout */

  int socket_fd = this->socket_fd;

  uchar * next      = this->resp_buf                + this->resp_head;
  ulong   bufsz     = FD_SNAPSHOT_HTTP_RESP_BUF_MAX - this->resp_head;
  assert( this->resp_head <= FD_SNAPSHOT_HTTP_RESP_BUF_MAX );

  long recv_sz = recv( socket_fd, next, bufsz, MSG_DONTWAIT );
  if( recv_sz<0L ) {
    if( FD_UNLIKELY( errno!=EWOULDBLOCK ) ) {
      FD_LOG_WARNING(( "recv(%d,%p,%lu) failed (%d-%s)",
                       socket_fd, (void *)next, bufsz,
                       errno, fd_io_strerror( errno ) ));
      this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
      return errno;
    } else {
      return 0;
    }
  } else if( recv_sz==0L ) {
    return 0;
  }

  /* Attempt to parse response.  (Might fail due to incomplete response) */

  ulong last_len = this->resp_head;
  this->resp_head += (uint)recv_sz;
  assert( this->resp_head <= FD_SNAPSHOT_HTTP_RESP_BUF_MAX );

  int               minor_version;
  int               status;
  char const *      msg_start;
  ulong             msg_len;
  struct phr_header headers[ FD_SNAPSHOT_HTTP_RESP_HDR_CNT ];
  ulong             header_cnt = FD_SNAPSHOT_HTTP_RESP_HDR_CNT;
  int parse_res =
    phr_parse_response( (const char *)this->resp_buf,
                        this->resp_head,
                        &minor_version,
                        &status,
                        &msg_start,
                        &msg_len,
                        headers,
                        &header_cnt,
                        last_len );

  if( FD_UNLIKELY( parse_res==-1 ) ) {
    FD_LOG_HEXDUMP_NOTICE(( "Failed HTTP response", this->resp_buf, this->resp_head ));
    FD_LOG_WARNING(( "Failed to parse HTTP response." ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return EPROTO;
  }

  if( parse_res==-2 ) return 0;  /* response headers incomplete */
  assert( parse_res>=0 );

  /* OK, we parsed the response headers.
     Remember where the leftover tail started so we can later reuse it
     during response reading. */

  this->resp_tail = (uint)parse_res;

  /* Is it a redirect?  If so, start over. */

  int is_redirect = (int)( (status==301) | (status==303) |
                           (status==304) | (status==307) );
  if( FD_UNLIKELY( (!this->hops) & (is_redirect) ) ) {
    FD_LOG_WARNING(( "Too many redirects. Aborting." ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return ELOOP;
  }

  if( is_redirect )
    return fd_snapshot_http_follow_redirect( this, headers, header_cnt );

  /* Validate response header */

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "Unexpected HTTP status %d", status ));
    this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
    return EPROTO;
  }

  /* Start downloading */

  this->state = FD_SNAPSHOT_HTTP_STATE_DL;
  return 0;
}

/* fd_snapshot_http_dl downloads bytes and returns them to the caller.
   No timeout set here. */

static int
fd_snapshot_http_dl( fd_snapshot_http_t * this,
                     void *               dst,
                     ulong                dst_max,
                     ulong *              dst_sz ) {

  /* TODO count content length and handle EOF */

  if( this->resp_head == this->resp_tail ) {
    this->resp_tail = this->resp_head = 0U;
    long recv_sz = recv( this->socket_fd, this->resp_buf, FD_SNAPSHOT_HTTP_RESP_BUF_MAX, MSG_DONTWAIT );
    if( recv_sz<0L ) {
      if( FD_UNLIKELY( errno!=EWOULDBLOCK ) ) {
        FD_LOG_WARNING(( "recv(%d,%p,%lu) failed while downloading response body (%d-%s)",
                        this->socket_fd, (void *)this->resp_buf, FD_SNAPSHOT_HTTP_RESP_BUF_MAX,
                        errno, fd_io_strerror( errno ) ));
        this->state = FD_SNAPSHOT_HTTP_STATE_FAIL;
        return errno;
      } else {
        return 0;
      }
    }
    this->resp_head = (uint)recv_sz;
  }

  uint avail_sz = this->resp_head - this->resp_tail;
  ulong write_sz = fd_ulong_min( avail_sz, dst_max );
  fd_memcpy( dst, this->resp_buf + this->resp_tail, write_sz );
  *dst_sz = write_sz;
  this->resp_tail += (uint)write_sz;
  return 0;
}

/* fd_snapshot_http_req gets called when we are ready to send our HTTP
   request for the snapshot to the server. */

int
fd_io_istream_snapshot_http_read( void *  _this,
                                  void *  dst,
                                  ulong   dst_max,
                                  ulong * dst_sz ) {

  fd_snapshot_http_t * this = (fd_snapshot_http_t *)_this;

  int err = 0;
  switch( this->state ) {
  case FD_SNAPSHOT_HTTP_STATE_INIT:
    err = fd_snapshot_http_init( this );
    break;
  case FD_SNAPSHOT_HTTP_STATE_REQ:
    err = fd_snapshot_http_req( this );
    break;
  case FD_SNAPSHOT_HTTP_STATE_RESP:
    err = fd_snapshot_http_resp( this );
    break;
  case FD_SNAPSHOT_HTTP_STATE_DL:
    return fd_snapshot_http_dl( this, dst, dst_max, dst_sz );
  }

  /* Not yet ready to read at this point. */

  *dst_sz = 0UL;
  return err;
}

fd_io_istream_vt_t const fd_io_istream_snapshot_http_vt = {
  .read = fd_io_istream_snapshot_http_read,
};
