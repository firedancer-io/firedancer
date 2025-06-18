#include "fd_snapshot_httpdl.h"
#include <asm-generic/errno.h>

static char const default_path[] = "/snapshot.tar.bz2";

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

  p = fd_cstr_append_text( p, dst_str, strlen(dst_str) );

  static char const hdr_part2[] =
    "\r\n"
    "\r\n";
  p = fd_cstr_append_text( p, hdr_part2, sizeof(hdr_part2)-1 );

  self->req_head = (ushort)( p - self->req_buf );
}

fd_snapshot_httpdl_t *
fd_snapshot_httpdl_new( void *              mem,
                        ulong               peers_cnt,
                        fd_ip4_port_t const peers[ FD_SNAPSHOT_HTTP_MAX_NODES ],
                        char const *        snapshot_archive_path ) {
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

  /* copy peers into http peers */
  self->peers_cnt = peers_cnt;
  fd_memcpy( self->peers, peers, sizeof(fd_ip4_port_t) * peers_cnt );

  /* set up first peer to contact */
  self->ipv4 = self->peers[0].addr;
  self->port = self->peers[0].port;

  /* set up http state */
  self->socket_fd = -1;
  self->state = FD_SNAPSHOT_HTTP_STATE_INIT;
  self->hops = FD_SNAPSHOT_HTTP_DEFAULT_HOPS;

  /* copy in snapshot archive path */
  fd_memcpy( self->snapshot_archive_path, snapshot_archive_path, PATH_MAX );
  self->full_snapshot_fd        = -1;
  self->incremental_snapshot_fd = -1;

  /* set initial get request to point to full snapshot path */
  fd_snapshot_http_set_path( self, default_path, sizeof(default_path) );

  fd_snapshot_httpdl_render_headers( self );
  return self;
}

void
fd_snapshot_httpdl_set_path( fd_snapshot_httpdl_t * self,
                             char const *            path,
                             ulong                   path_len ) {
  if( FD_UNLIKELY( !path_len ) ) {
    path     = "/";
    path_len = 1UL;
  }

  if( FD_UNLIKELY( path_len > FD_SNAPSHOT_HTTP_REQ_PATH_MAX ) ) {
    FD_LOG_CRIT(( "fd_snapshot_httpdl: path too long (%lu chars)", path_len ));
  }

  ulong off = sizeof(self->path) - path_len - 4;
  char * p = self->path + off;

  fd_memcpy( p,   "GET ", 4UL      );
  fd_memcpy( p+4, path,   path_len );

  self->req_tail = (ushort)off;
  self->path_off = (ushort)off;
}

void *
fd_snapshot_httpdl_delete( fd_snapshot_httpdl_t * self ) {
  if( FD_UNLIKELY ( !self ) ) {
    return NULL;
  }

  fd_snapshot_httpdl_cleanup_fds( self );
  return (void *)self;
}