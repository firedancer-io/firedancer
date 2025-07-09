#define _GNU_SOURCE
#include "fd_snapshot_httpdl.h"
#include "../../../waltz/http/picohttpparser.h"
#include "../../../flamenco/snapshot/fd_snapshot_base.h"
#include "fd_snapshot_archive.h"
#include "fd_snapshot_istream.h"
#include "fd_snapshot_peers_manager.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>

static char const default_full_path[] = "/snapshot.tar.bz2";
static char const default_incremental_path[] = "/incremental-snapshot.tar.bz2";

static void
fd_snapshot_httpdl_render_headers( fd_snapshot_httpdl_t * self ) {
  char * p = fd_cstr_init( self->req_hdrs );
  static char const hdr_part1[] =
    " HTTP/1.1\r\n"
    "user-agent: Firedancer\r\n"
    "accept: */*\r\n"
    "accept-encoding: identity\r\n"
    "host: ";

  p = fd_cstr_append_text( p, hdr_part1, sizeof(hdr_part1)-1 );

  /* Get the ip dst as a string */
  char ip_dst_str[ 20UL ];
  fd_memset( ip_dst_str, 0, sizeof(ip_dst_str) );
  sprintf( ip_dst_str, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( self->ipv4 ) );

  p = fd_cstr_append_text( p, ip_dst_str, strlen(ip_dst_str) );

  static char const hdr_part2[] =
    "\r\n"
    "\r\n";
  p = fd_cstr_append_text( p, hdr_part2, sizeof(hdr_part2)-1 );

  self->req_head = (ulong)( p - self->req_buf );
}

static void
fd_snapshot_httpdl_set_path( fd_snapshot_httpdl_t * self,
                             char const *            path,
                             ulong                   path_len ) {
  if( FD_UNLIKELY( !path_len ) ) {
    path     = "/";
    path_len = 1UL;
  }

  if( FD_UNLIKELY( path_len > FD_SNAPSHOT_HTTPDL_REQ_PATH_MAX ) ) {
    FD_LOG_CRIT(( "fd_snapshot_httpdl: path too long (%lu chars)", path_len ));
  }

  ulong off = sizeof(self->path) - path_len - 4;
  char * p = self->path + off;

  fd_memcpy( p,   "GET ", 4UL      );
  fd_memcpy( p+4, path,   path_len );

  self->req_tail = off;
  self->path_off = off;
}

static void
fd_snapshot_httpdl_cleanup_fds( fd_snapshot_httpdl_t * self ) {
  if( self->current_snapshot_fd!=-1 ) {
    if( FD_UNLIKELY( close( self->current_snapshot_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    self->current_snapshot_fd = -1;
  }

  if( self->current_snapshot_fd!=-1 ) {
    if( FD_UNLIKELY( close( self->current_snapshot_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    self->current_snapshot_fd = -1;
  }

  if( self->socket_fd!=-1 ) {
    if( FD_UNLIKELY( close( self->socket_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    self->socket_fd = -1;
  }
}

static void
fd_snapshot_httpdl_reset( fd_snapshot_httpdl_t * self ) {
  self->state         = FD_SNAPSHOT_HTTPDL_STATE_INIT;
  self->hops          = FD_SNAPSHOT_HTTPDL_DEFAULT_HOPS;
  self->req_deadline  = 0L;

  self->req_tail      = 0UL;
  self->req_head      = 0UL;
  self->resp_tail     = 0UL;
  self->resp_head     = 0UL;
  self->dl_total      = 0UL;
  self->last_dl_total = 0UL;
  self->last_nanos    = 0UL;
  self->write_total   = 0UL;
  self->content_len   = 0UL;

  fd_memset( self->req_buf, 0, sizeof(self->req_buf) );
  fd_memset( self->resp_buf, 0, sizeof(self->resp_buf) );

  fd_snapshot_httpdl_cleanup_fds( self );
}

static int
fd_snapshot_httpdl_render_request( fd_snapshot_httpdl_t * self ) {
  fd_snapshot_httpdl_reset( self );

  if( self->snapshot_type == FD_SNAPSHOT_TYPE_FULL ) {
    fd_snapshot_httpdl_set_path( self, default_full_path, sizeof(default_full_path)-1UL );
  } else if( self->snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
    fd_snapshot_httpdl_set_path( self, default_incremental_path, sizeof(default_incremental_path)-1UL );
  } else {
    FD_LOG_WARNING(( "Unknown snapshot type %d", self->snapshot_type ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EINVAL;
  }

  fd_snapshot_httpdl_render_headers( self );

  return 0;
}

static int
fd_snapshot_httpdl_init_peer( fd_snapshot_httpdl_t * self ) {
  self->current_peer = fd_snapshot_peers_manager_get_next_peer( self->peers_manager );

  if( !self->current_peer ) {
    FD_LOG_WARNING(( "No peers to connect to." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EINVAL;
  }

  self->ipv4 = self->current_peer->dest.addr;
  self->port = self->current_peer->dest.port;

  FD_LOG_INFO(( "Selected peer " FD_IP4_ADDR_FMT ":%u ...", FD_IP4_ADDR_FMT_ARGS( self->ipv4 ), self->port ));

  return fd_snapshot_httpdl_render_request( self );
}

static int
fd_snapshot_httpdl_init_connection( fd_snapshot_httpdl_t * self ) {

  if( !self->current_peer ) {
    int res = fd_snapshot_httpdl_init_peer( self );
    if( FD_UNLIKELY( res ) ) {
      return res;
    }
  }

  self->req_deadline = fd_log_wallclock() + (long)FD_SNAPSHOT_HTTPDL_REQUEST_TIMEOUT;

  /* Create socket */
  self->socket_fd = socket( AF_INET, SOCK_STREAM, 0 );
  if( FD_UNLIKELY( self->socket_fd < 0) ) {
    FD_LOG_WARNING(( "socket(AF_INET, SOCK_STREAM, 0) failed (%d-%s)",
                 errno, fd_io_strerror( errno ) ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return errno;
  }

  int optval = 1;
  if( FD_UNLIKELY( setsockopt( self->socket_fd,
                               SOL_TCP,
                               TCP_NODELAY,
                               &optval,
                               sizeof(int) )<0 ) ) {
    FD_LOG_WARNING(( "setsockopt failed (%d-%s)",
                     errno, fd_io_strerror( errno ) ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return errno;
  }

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = self->ipv4 },
    .sin_port   = fd_ushort_bswap( self->port ),
  };

  /* TODO consider using O_NONBLOCK socket so we can control the
     connect timeout interval */
  if( FD_UNLIKELY( connect( self->socket_fd,
                            fd_type_pun_const( &addr ),
                            sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_WARNING(( "connect(%d," FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                      self->socket_fd,
                      FD_IP4_ADDR_FMT_ARGS( self->ipv4 ), self->port,
                      errno, fd_io_strerror( errno ) ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return errno;
  }

  FD_LOG_INFO(( "Sending request" ));
  self->state = FD_SNAPSHOT_HTTPDL_STATE_REQ;
  return 0;
}

/* fd_snapshot_httpdl_req writes out the request. */

static int
fd_snapshot_httpdl_req( fd_snapshot_httpdl_t * self ) {
  long now      = fd_log_wallclock();
  long deadline = self->req_deadline;

  if( FD_UNLIKELY( now > deadline ) ) {
    FD_LOG_WARNING(( "Timed out while sending request." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return ETIMEDOUT;
  }

  ulong avail_sz = self->req_head - self->req_tail;
  assert( avail_sz < sizeof(self->req_buf) );
  long sent_sz = send( self->socket_fd, self->req_buf + self->req_tail, avail_sz, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( sent_sz<0L ) {
    if( FD_UNLIKELY( errno!=EWOULDBLOCK ) ) {
      FD_LOG_WARNING(( "send(%d,%p,%u) failed (%d-%s)",
                       self->socket_fd, (void *)(self->req_buf + self->req_tail), (uint)avail_sz,
                       errno, fd_io_strerror( errno ) ));
      self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
      return errno;
    } else {
      return 0;
    }
  }

  self->req_tail = self->req_tail + (ulong)sent_sz;
  if( self->req_tail == self->req_head ) {
    self->state = FD_SNAPSHOT_HTTPDL_STATE_RESP;
  }

  return 0;
}

static void
fd_snapshot_httpdl_parse_location_header( struct phr_header const * headers,
                                          ulong                     header_cnt,
                                          char const **             loc,
                                          ulong *                   loc_len ) {
  for( ulong i = 0; i<header_cnt; i++ ) {
    if( 0==strncasecmp( headers[i].name, "location", headers[i].name_len ) ) {
      *loc     = headers[i].value;
      *loc_len = headers[i].value_len;
      break;
    }
  }
}

static int
fd_snapshot_httpdl_init_full_snapshot_file( fd_snapshot_httpdl_t * self,
                                            char const *           filename,
                                            ulong                  filename_len ) {
  if( FD_UNLIKELY( filename_len > PATH_MAX ) ) {
    FD_LOG_WARNING(( "Snapshot filename too long (%lu chars)", filename_len ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  char snapshot_filename[ PATH_MAX ];
  fd_memcpy( snapshot_filename, filename, filename_len );
  snapshot_filename[ filename_len ] = '\0';

  int res = fd_snapshot_archive_parse_full_snapshot_file( self->snapshot_archive_path,
                                                          snapshot_filename,
                                                          self->full_snapshot_entry );
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_WARNING(( "Cannot parse full snapshot name %s", snapshot_filename ));
  }

  /* append tag */
  char const tag[] = "-partial";
  ulong tag_len = sizeof(tag) - 1UL;
  ulong snapshot_filename_len = strlen( self->full_snapshot_entry->filename );
  if( FD_UNLIKELY( snapshot_filename_len + tag_len + 1UL > PATH_MAX ) ) {
    FD_LOG_WARNING(( "Snapshot filename too long (%lu chars)", snapshot_filename_len + tag_len + 1UL ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  fd_memcpy( self->snapshot_filename_temp, self->full_snapshot_entry->filename, PATH_MAX );
  fd_memcpy( self->snapshot_filename_temp + snapshot_filename_len, tag, tag_len );
  self->snapshot_filename_temp[ snapshot_filename_len + tag_len ] = '\0';

  fd_memcpy( self->snapshot_filename, self->full_snapshot_entry->filename, PATH_MAX );

  /* open full snapshot save file */
  self->current_snapshot_fd = open( self->snapshot_filename_temp, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( self->current_snapshot_fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%d-%s)", self->snapshot_filename_temp, errno, fd_io_strerror( errno ) ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EACCES;
  }

  self->base_slot = self->full_snapshot_entry->slot;
  return 0;
}

static int
fd_snapshot_httpdl_init_incremental_snapshot_file( fd_snapshot_httpdl_t * self,
                                                   char const *           filename,
                                                   ulong                  filename_len ) {
  if( FD_UNLIKELY( filename_len > PATH_MAX ) ) {
    FD_LOG_WARNING(( "Snapshot filename too long (%lu chars)", filename_len ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  char snapshot_filename[ PATH_MAX ];
  fd_memcpy( snapshot_filename, filename, filename_len );
  snapshot_filename[ filename_len ] = '\0';

  int res = fd_snapshot_archive_parse_incremental_snapshot_file( self->snapshot_archive_path,
                                                                 snapshot_filename,
                                                                 self->incremental_snapshot_entry );
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_WARNING(( "Cannot parse incremental snapshot name %s", snapshot_filename ));
  }

  /* append tag */
  char const tag[] = "-partial";
  ulong tag_len = sizeof(tag) - 1UL;
  ulong snapshot_filename_len = strlen( self->incremental_snapshot_entry->inner.filename );
  if( FD_UNLIKELY( snapshot_filename_len + tag_len + 1UL > PATH_MAX ) ) {
    FD_LOG_WARNING(( "Snapshot filename too long (%lu chars)", snapshot_filename_len + tag_len + 1UL ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  /* create the temp filename, which includes a -partial at the end of the snapshot filename */
  fd_memcpy( self->snapshot_filename_temp, self->incremental_snapshot_entry->inner.filename, PATH_MAX );
  fd_memcpy( self->snapshot_filename_temp + snapshot_filename_len, tag, tag_len );
  self->snapshot_filename_temp[ snapshot_filename_len + tag_len ] = '\0';

  /* store the actual filename, later the temp filename will be renamed to the actual filename */
  fd_memcpy( self->snapshot_filename, self->incremental_snapshot_entry->inner.filename, PATH_MAX );

  /* open incremental snapshot save file */
  self->current_snapshot_fd = open( self->snapshot_filename_temp, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( self->current_snapshot_fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%d-%s)", self->snapshot_filename_temp, errno, fd_io_strerror( errno ) ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EACCES;
  }

  if( self->incremental_snapshot_entry->base_slot != self->base_slot ) {
    FD_LOG_WARNING(( "Incremental snapshot does not build off previously loaded full snapshot. "
                     "This likely indicates that the full snapsnot is stale and that the incremental snapshot is based on a newer slot."
                     "Re-loading full snapshot." ));
    self->metrics.status = FD_SNAPSHOT_READER_RESET;
    return EINVAL;
  }

  return 0;
}

static void
fd_snapshot_httpdl_reset_req( fd_snapshot_httpdl_t * self ) {
  self->req_deadline  = fd_log_wallclock() + (long)FD_SNAPSHOT_HTTPDL_REQUEST_TIMEOUT;
  self->state     = FD_SNAPSHOT_HTTPDL_STATE_REQ;
  self->resp_tail = 0UL;
  self->resp_head = 0UL;
}

static int
fd_snapshot_httpdl_parse_snapshot_name( fd_snapshot_httpdl_t * self,
                                        char const *           path,
                                        ulong                  path_len ) {
  int err;
  if( self->snapshot_type == FD_SNAPSHOT_TYPE_FULL ) {
    err = fd_snapshot_httpdl_init_full_snapshot_file( self, path, path_len );
  } else if( self->snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
    err = fd_snapshot_httpdl_init_incremental_snapshot_file( self, path, path_len );
  } else {
    FD_LOG_WARNING(( "Unknown snapshot type %d", self->snapshot_type ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    err = EINVAL;
  }

  return err;
}

/* fd_snapshot_http_follow_redirect winds up the state machine for a
   redirect. */
static int
fd_snapshot_httpdl_follow_redirect( fd_snapshot_httpdl_t *    self,
                                    struct phr_header const * headers,
                                    ulong                     header_cnt ) {
  assert( self->hops > 0 );
  self->hops--;

  /* Look for location header */
  char const * loc = NULL;
  ulong        loc_len = 0UL;
  fd_snapshot_httpdl_parse_location_header( headers,
                                            header_cnt,
                                            &loc,
                                            &loc_len );

  if( FD_UNLIKELY( !loc ) ) {
    FD_LOG_WARNING(( "Invalid redirect (no location header)" ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EINVAL;
  }

  if( FD_UNLIKELY( loc_len > FD_SNAPSHOT_HTTPDL_REQ_PATH_MAX ) ) {
    FD_LOG_WARNING(( "Redirect location too long" ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EINVAL;
  }

  if( FD_UNLIKELY( loc_len==0 || loc[0] != '/' ) ) {
    FD_LOG_WARNING(( "Redirect is not an absolute path on the current host. Refusing to follow." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  /* Validate character set (TODO too restrictive?) */
  for( ulong j=0UL; j<loc_len; j++ ) {
    int c = loc[j];
    int c_ok = ( (c>='a') & (c<='z') ) |
               ( (c>='A') & (c<='Z') ) |
               ( (c>='0') & (c<='9') ) |
               (c=='.') | (c=='/') | (c=='-') | (c=='_') |
               (c=='+') | (c=='=') | (c=='&') | (c=='~') |
               (c=='%') | (c=='#');
    if( FD_UNLIKELY( !c_ok ) ) {
      FD_LOG_WARNING(( "Invalid char '0x%02x' in redirect location", (uint)c ));
      self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
      return EPROTO;
    }
  }

  /* Re-initialize */

  FD_LOG_INFO(( "Following redirect to %.*s", (int)loc_len, loc ));

  int err = fd_snapshot_httpdl_parse_snapshot_name(self, loc, loc_len );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_snapshot_httpdl_set_path( self, loc, loc_len );
  fd_snapshot_httpdl_reset_req( self );

  return 0;
}

static int
fd_snapshot_httpdl_resp( fd_snapshot_httpdl_t * self ) {
  long now      = fd_log_wallclock();
  long deadline = self->req_deadline;

  if( FD_UNLIKELY( now > deadline ) ) {
    FD_LOG_WARNING(( "Timed out while receiving response headers." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return ETIMEDOUT;
  }

  /* Do blocking read of TCP data until timeout */
  uchar * next      = self->resp_buf                + self->resp_head;
  ulong   bufsz     = FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX - self->resp_head;
  assert( self->resp_head <= FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX );

  long recv_sz = recv( self->socket_fd, next, bufsz, MSG_DONTWAIT );
  if( recv_sz<0L ) {
    if( FD_UNLIKELY( errno!=EWOULDBLOCK ) ) {
      FD_LOG_WARNING(( "recv(%d,%p,%lu) failed (%d-%s)",
                       self->socket_fd, (void *)next, bufsz,
                       errno, fd_io_strerror( errno ) ));
      self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
      return errno;
    } else {
      return 0;
    }
  } else if( recv_sz==0L ) {
    return 0;
  }

  /* Attempt to parse response.  (Might fail due to incomplete response) */
  ulong last_len = self->resp_head;
  self->resp_head += (uint)recv_sz;
  assert( self->resp_head <= FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX );

  int               minor_version;
  int               status;
  char const *      msg_start;
  ulong             msg_len;
  struct phr_header headers[ FD_SNAPSHOT_HTTPDL_RESP_HDR_CNT ];
  ulong             header_cnt = FD_SNAPSHOT_HTTPDL_RESP_HDR_CNT;
  int parse_res =
    phr_parse_response( (const char *)self->resp_buf,
                        self->resp_head,
                        &minor_version,
                        &status,
                        &msg_start,
                        &msg_len,
                        headers,
                        &header_cnt,
                        last_len );
  if( FD_UNLIKELY( parse_res==-1 ) ) {
    FD_LOG_HEXDUMP_NOTICE(( "Failed HTTP response", self->resp_buf, self->resp_head ));
    FD_LOG_WARNING(( "Failed to parse HTTP response." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  if( parse_res==-2 ) return 0;  /* response headers incomplete */
  assert( parse_res>=0 );

  /* OK, we parsed the response headers.
     Remember where the leftover tail started so we can later reuse it
     during response reading. */

  self->resp_tail = (ulong)parse_res;

  /* Is it a redirect?  If so, start over. */

  int is_redirect = (int)( (status==301) | (status==303) |
                           (status==304) | (status==307) |
                           (status==308) );
  if( FD_UNLIKELY( (!self->hops) & (is_redirect) ) ) {
    FD_LOG_WARNING(( "Too many redirects. Aborting." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return ELOOP;
  }

  if( is_redirect ) {
    FD_LOG_INFO(( "Redirecting due to code %d", status ));
    return fd_snapshot_httpdl_follow_redirect( self, headers, header_cnt );
  }

  /* Validate response header */

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "Unexpected HTTP status %d", status ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  /* Find content-length */

  self->content_len = ULONG_MAX;
  const ulong target_len = sizeof("content-length")-1;
  for( ulong i = 0; i < header_cnt; ++i ) {
    if( headers[i].name_len==target_len && strncasecmp( headers[i].name, "content-length", target_len ) == 0 ) {
      self->content_len         = strtoul( headers[i].value, NULL, 10 );
      self->metrics.bytes_total = self->content_len;
      break;
    }
  }
  if( self->content_len == ULONG_MAX ) {
    FD_LOG_WARNING(( "Missing content-length" ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    return EPROTO;
  }

  /* Start downloading */
  if( FD_UNLIKELY( self->current_snapshot_fd==-1 ) ) {
    /* We didn't follow a redirect. Parse the snapshot file name here */
    ulong off = (ulong)self->path_off + 4;
    int err = fd_snapshot_httpdl_parse_snapshot_name( self,
                                            self->path + off,
                                            sizeof(self->path) - off );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

  }

  /* assert that file len is less than content len */
  struct stat sb;
  if ( FD_LIKELY( fstat( self->current_snapshot_fd, &sb )==0 ) ) {
    ulong file_len = (ulong)sb.st_size;
    FD_TEST( file_len < self->content_len );
  } else {
    FD_LOG_ERR(("fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  self->state = FD_SNAPSHOT_HTTPDL_STATE_DL;
  return 0;
}

static int
fd_snapshot_httldl_write_snapshot_file( fd_snapshot_httpdl_t * self,
                                        ulong                  write_sz ) {
  FD_TEST( self->current_snapshot_fd != -1 );

  /* write out to snapshot file */
  ulong src_sz;
  int err = fd_io_write( self->current_snapshot_fd,
                         self->resp_buf + self->resp_tail,
                         write_sz,
                         write_sz,
                         &src_sz );
  if( FD_UNLIKELY( err!=0 ) ) {
    FD_LOG_WARNING(( "fd_io_write() failed (%d-%s) requested %lu bytes and wrote %lu bytes", err, fd_io_strerror( err ), write_sz, src_sz ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    fd_snapshot_httpdl_cleanup_fds( self );
    return err;
  }

  return 0;
}

static int
fd_snapshot_httpdl_retry( fd_snapshot_httpdl_t * self ) {
  /* mark current peer invalid because download speed was too slow */
  fd_snapshot_peers_manager_set_current_peer_invalid( self->peers_manager );

  self->current_peer = fd_snapshot_peers_manager_get_next_peer( self->peers_manager );

  if( !self->current_peer ) {
    FD_LOG_WARNING(( "Exhausted all peers to download from. Failing." ));
    self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
    fd_snapshot_httpdl_cleanup_fds( self );
    return -1;
  }

  self->ipv4 = self->current_peer->dest.addr;
  self->port = self->current_peer->dest.port;

  FD_LOG_NOTICE(( "Retrying download of %s from peer "FD_IP4_ADDR_FMT": %u",
                  self->snapshot_filename,
                  FD_IP4_ADDR_FMT_ARGS( self->ipv4 ),
                  self->port ));

  return fd_snapshot_httpdl_render_request( self );
}

static int
fd_snapshot_httpdl_write( fd_snapshot_httpdl_t * self,
                          void *               dst,
                          ulong                dst_max,
                          ulong *              sz ) {
  ulong avail_sz = self->resp_head - self->resp_tail;
  if( FD_UNLIKELY( self->dl_total==0UL ) ) {
    self->dl_total = avail_sz;
  }

  /* write out to in memory buffer */
  ulong write_sz = fd_ulong_min( avail_sz, dst_max );
  fd_memcpy( dst, self->resp_buf + self->resp_tail, write_sz );
  *sz = write_sz;

  /* save snapshot contents to file */
  int err = fd_snapshot_httldl_write_snapshot_file( self, write_sz );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  self->resp_tail          += (uint)write_sz;
  self->write_total        += write_sz;
  self->metrics.bytes_read  = self->dl_total;

  /* check if done downloading and writing */
  if( self->content_len == self->write_total ) {
    FD_LOG_NOTICE(( "Wrote out all %lu MB", self->write_total>>20 ));

    self->state = FD_SNAPSHOT_HTTPDL_STATE_DONE;
    fd_snapshot_httpdl_cleanup_fds( self );
    self->metrics.status = FD_SNAPSHOT_READER_DONE;

    /* rename to remove partial tag */
    rename( self->snapshot_filename_temp, self->snapshot_filename );
  }

  return 0;
}

static int
fd_snapshot_httpdl_dl( fd_snapshot_httpdl_t * self,
                       void *               dst,
                       ulong                dst_max,
                       ulong *              sz ) {
  if( self->content_len==self->dl_total &&
      self->write_total<self->content_len ) {
    /* Reaching here means we have some unflushed downloaded bytes. */
    int err = fd_snapshot_httpdl_write( self, dst, dst_max, sz );
    if( FD_UNLIKELY( err ) ) return err;
    else                     return 0;
  }

  if( self->resp_head == self->resp_tail ) {
    /* Empty resp buffer means we can recv more bytes */
    self->resp_tail = self->resp_head = 0UL;
    long recv_sz = recv( self->socket_fd, self->resp_buf,
                         fd_ulong_min( self->content_len - self->dl_total, FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX ),
                         MSG_DONTWAIT );
    if( recv_sz<0L ) {
      if( FD_UNLIKELY( errno!=EWOULDBLOCK && errno!=EAGAIN ) ) {
        FD_LOG_WARNING(( "recv(%d,%p,%lu) failed while downloading response body (%d-%s)",
                        self->socket_fd, (void *)self->resp_buf, FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX,
                        errno, fd_io_strerror( errno ) ));
        self->state          = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
        fd_snapshot_httpdl_cleanup_fds( self );
        return errno;
      } else {
        return 0;
      }
    }
    if( !recv_sz ) { /* Connection closed */
      FD_LOG_WARNING(( "Connection closed at %lu MB", self->dl_total>>20 ));
      self->state = FD_SNAPSHOT_HTTPDL_STATE_FAIL;
      fd_snapshot_httpdl_cleanup_fds( self );
      return -1;
    }
    self->resp_head = (ulong)recv_sz;
    self->dl_total += (ulong)recv_sz;

    /* check download speed and retry if needed */
    if( self->dl_total - self->last_dl_total >= FD_SNAPSHOT_HTTPDL_DL_PERIOD ) {
      if( self->last_nanos > 0 ) {
        ulong dl_delta    = self->dl_total - self->last_dl_total;
        ulong nanos_delta = (ulong)(fd_log_wallclock() - self->last_nanos);
        ulong mibps       = (dl_delta*1000UL)/nanos_delta;

        if( FD_UNLIKELY( self->dl_total < FD_SNAPSHOT_HTTPDL_SPEED_CHECK_PERIOD &&
                         mibps < self->minimum_download_speed_mib ) ) {
          FD_LOG_WARNING(( "Download speed %lu MB/s is below minimum %lu MB/s",
                          mibps, self->minimum_download_speed_mib ));
          self->metrics.status = FD_SNAPSHOT_READER_RETRY;
          return fd_snapshot_httpdl_retry( self );
        }
      }

      self->last_dl_total = self->dl_total;
      self->last_nanos    = fd_log_wallclock();
    }

    if( self->content_len <= self->dl_total ) {
      FD_LOG_NOTICE(( "Download complete at %lu MB", self->dl_total>>20 ));
      if( FD_UNLIKELY( self->content_len < self->dl_total ) ) {
        FD_LOG_WARNING(( "server transmitted more than Content-Length %lu bytes vs %lu bytes", self->content_len, self->dl_total ));
      }
    }
  }

  int err = fd_snapshot_httpdl_write( self, dst, dst_max, sz );
  if( FD_UNLIKELY( err ) ) return err;
  else                     return 0;
}

/* fd_snapshot_http_read reads bytes from a pre-existing snapshot file
   and returns them to the caller. */

fd_snapshot_reader_metrics_t
fd_snapshot_httpdl_read( void *  _self,
                         uchar * dst,
                         ulong   dst_max,
                         ulong * sz ) {
   fd_snapshot_httpdl_t * self = (fd_snapshot_httpdl_t *)_self;

  int err = 0;
  switch( self->state ) {
  case FD_SNAPSHOT_HTTPDL_STATE_INIT: {
    err = fd_snapshot_httpdl_init_connection( self );
    self->metrics.status = FD_SNAPSHOT_READER_INIT;
    break;
  }
  case FD_SNAPSHOT_HTTPDL_STATE_REQ:
    FD_LOG_NOTICE(( "Retrieving snapshot from http://" FD_IP4_ADDR_FMT ":%u",
                    FD_IP4_ADDR_FMT_ARGS( self->ipv4 ), self->port ));
    err = fd_snapshot_httpdl_req( self );
    break;
  case FD_SNAPSHOT_HTTPDL_STATE_RESP:
    err = fd_snapshot_httpdl_resp( self );
    self->metrics.status = FD_SNAPSHOT_READER_READ;
    break;
  case FD_SNAPSHOT_HTTPDL_STATE_DL: {
    err = fd_snapshot_httpdl_dl( self, dst, dst_max, sz );
    break;
  }
  case FD_SNAPSHOT_HTTPDL_STATE_DONE:
    break;
  }

  if( err ) {
    self->metrics.status = FD_SNAPSHOT_READER_FAIL;
    self->metrics.err    = err;
  }

  return self->metrics;
}

fd_snapshot_httpdl_t *
fd_snapshot_httpdl_new( void *                                    mem,
                        fd_snapshot_peers_manager_t *             peers_manager,
                        char                                      snapshot_archive_path[ PATH_MAX],
                        fd_snapshot_archive_entry_t *             full_snapshot_entry,
                        fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                        int                                       should_download_full,
                        int                                       should_download_incremental,
                        ulong                                     minimum_download_speed_mib ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_httpdl_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  fd_snapshot_httpdl_t * self = fd_type_pun( mem );
  fd_memset( self, 0, sizeof(fd_snapshot_httpdl_t) );

  /* Assign peers by reference from peers manager */
  self->peers_manager = peers_manager;

  /* set up http state */
  self->socket_fd = -1;
  self->state = FD_SNAPSHOT_HTTPDL_STATE_INIT;
  self->hops  = FD_SNAPSHOT_HTTPDL_DEFAULT_HOPS;

  /* copy in snapshot archive path
     TODO: we could just use the pointer to the snapshot_archive_path that lives in the snaprd tile */
  fd_memcpy( self->snapshot_archive_path, snapshot_archive_path, PATH_MAX );
  self->current_snapshot_fd = -1;

  self->full_snapshot_entry        = full_snapshot_entry;
  self->incremental_snapshot_entry = incremental_snapshot_entry;
  self->minimum_download_speed_mib = minimum_download_speed_mib;

  if( should_download_full ) {
    self->snapshot_type = FD_SNAPSHOT_TYPE_FULL;
  } else if( should_download_incremental) {
    self->snapshot_type = FD_SNAPSHOT_TYPE_INCREMENTAL;
    self->base_slot = full_snapshot_entry->slot;
    fd_snapshot_httpdl_set_source_incremental( self );
  } else {
    FD_LOG_ERR(( "No snapshots to download" ));
  }

  return self;
}

void
fd_snapshot_httpdl_set_source_incremental( fd_snapshot_httpdl_t * self ) {
  self->snapshot_type = FD_SNAPSHOT_TYPE_INCREMENTAL;

  fd_snapshot_httpdl_render_request( self );
}

void *
fd_snapshot_httpdl_delete( fd_snapshot_httpdl_t * self ) {
  if( FD_UNLIKELY ( !self ) ) {
    return NULL;
  }

  fd_snapshot_httpdl_cleanup_fds( self );
  return (void *)self;
}

fd_snapshot_istream_vt_t const fd_snapshot_istream_httpdl_vt =
  { .read = fd_snapshot_httpdl_read };
