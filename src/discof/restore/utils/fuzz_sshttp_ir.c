#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_sshttp_private.h"

typedef struct {
  uchar const * cur;
  uchar const * end;
} fd_sshttp_ir_stream_t;

typedef struct {
  int          listen_fd;
  int          conn_fd;
  fd_ip4_port_t addr;
} fd_sshttp_ir_server_t;

typedef struct {
  long  now;
  ulong advance_cnt;
} fd_sshttp_ir_exec_t;

static fd_sshttp_t * http_mem;

extern _Bool fd_sshttp_fuzz;

static inline uchar
ir_u8( fd_sshttp_ir_stream_t * ir ) {
  return FD_LIKELY( ir->cur<ir->end ) ? *ir->cur++ : (uchar)0;
}

static inline ulong
ir_take( fd_sshttp_ir_stream_t * ir,
         uchar *                out,
         ulong                  out_max ) {
  ulong rem = (ulong)( ir->end - ir->cur );
  ulong n   = fd_ulong_min( rem, fd_ulong_min( out_max, (ulong)ir_u8( ir ) ) );
  if( FD_LIKELY( n ) ) {
    fd_memcpy( out, ir->cur, n );
    ir->cur += n;
  }
  return n;
}

static inline long
ir_delta_nanos( fd_sshttp_ir_stream_t * ir ) {
  /* 1ms-1024ms */
  ulong q = (ulong)ir_u8( ir ) + 1UL;
  return (long)( q * 1000UL * 1000UL );
}

static void
ir_close( int * fd ) {
  if( FD_LIKELY( *fd!=-1 ) ) {
    close( *fd );
    *fd = -1;
  }
}

static int
ir_set_nonblock( int fd ) {
  int flags = fcntl( fd, F_GETFL, 0 );
  if( FD_UNLIKELY( flags==-1 ) ) return -1;
  return fcntl( fd, F_SETFL, flags|O_NONBLOCK );
}

static void
ir_server_fini( fd_sshttp_ir_server_t * srv ) {
  ir_close( &srv->conn_fd   );
  ir_close( &srv->listen_fd );
}

static int
ir_server_init( fd_sshttp_ir_server_t * srv ) {
  ir_server_fini( srv );

  int listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( listen_fd==-1 ) ) return -1;

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval) ) ) ) {
    close( listen_fd );
    return -1;
  }

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = 0,
    .sin_addr   = { .s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) }
  };

  if( FD_UNLIKELY( -1==bind( listen_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
    close( listen_fd );
    return -1;
  }

  if( FD_UNLIKELY( -1==listen( listen_fd, 16 ) ) ) {
    close( listen_fd );
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if( FD_UNLIKELY( -1==getsockname( listen_fd, fd_type_pun( &addr ), &addr_len ) ) ) {
    close( listen_fd );
    return -1;
  }

  srv->listen_fd = listen_fd;
  srv->conn_fd   = -1;
  srv->addr      = (fd_ip4_port_t){
    .addr = FD_IP4_ADDR( 127, 0, 0, 1 ),
    .port = addr.sin_port
  };

  return 0;
}

static int
ir_server_accept( fd_sshttp_ir_server_t * srv ) {
  if( FD_LIKELY( srv->conn_fd!=-1 ) ) return 1;
  if( FD_UNLIKELY( srv->listen_fd==-1 ) ) return 0;

  int conn = accept( srv->listen_fd, NULL, NULL );
  if( FD_UNLIKELY( conn==-1 ) ) {
    if( FD_LIKELY( (errno==EAGAIN) | (errno==EWOULDBLOCK) | (errno==EINTR) ) ) return 0;
    return -1;
  }

  if( FD_UNLIKELY( -1==ir_set_nonblock( conn ) ) ) {
    close( conn );
    return -1;
  }

  srv->conn_fd = conn;
  return 1;
}

static void
ir_server_close_conn( fd_sshttp_ir_server_t * srv ) {
  ir_close( &srv->conn_fd );
}

static void
ir_server_shutdown_wr( fd_sshttp_ir_server_t * srv ) {
  if( FD_LIKELY( srv->conn_fd!=-1 ) ) {
    shutdown( srv->conn_fd, SHUT_WR );
  }
}

static void
ir_server_drain_req( fd_sshttp_ir_server_t * srv ) {
  if( FD_UNLIKELY( srv->conn_fd==-1 ) ) return;

  uchar tmp[ 1024 ];
  while(1) {
    long n = recv( srv->conn_fd, tmp, sizeof(tmp), MSG_DONTWAIT|MSG_NOSIGNAL );
    if( FD_UNLIKELY( n<=0L ) ) {
      if( FD_UNLIKELY( n==0L ) ) {
        ir_server_close_conn( srv );
        return;
      }
      if( FD_LIKELY( (errno==EAGAIN) | (errno==EWOULDBLOCK) | (errno==EINTR) ) ) return;
      ir_server_close_conn( srv );
      return;
    }
  }
}

static void
ir_server_send( fd_sshttp_ir_server_t * srv,
                void const *            data,
                ulong                   data_sz ) {
  if( FD_UNLIKELY( (srv->conn_fd==-1) | !data_sz ) ) return;

  uchar const * buf = (uchar const *)data;
  ulong off = 0UL;
  for( ulong i=0UL; i<16UL && off<data_sz; i++ ) {
    long n = send( srv->conn_fd, buf+off, data_sz-off, MSG_NOSIGNAL );
    if( FD_LIKELY( n>0L ) ) {
      off += (ulong)n;
      continue;
    }
    if( FD_UNLIKELY( n==0L ) ) break;
    if( FD_LIKELY( (errno==EAGAIN) | (errno==EWOULDBLOCK) | (errno==EINTR) ) ) continue;
    ir_server_close_conn( srv );
    break;
  }
}

static void
ir_server_send_200( fd_sshttp_ir_server_t *  srv,
                    fd_sshttp_ir_stream_t *  ir ) {
  uchar body[ 512 ];
  ulong body_sz = ir_take( ir, body, sizeof(body) );

  char  hdr[ 256 ];
  ulong hdr_sz = 0UL;
  FD_TEST( fd_cstr_printf_check( hdr, sizeof(hdr), &hdr_sz,
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Length: %lu\r\n"
                                 "\r\n",
                                 body_sz ) );

  ir_server_send( srv, hdr,  hdr_sz  );
  ir_server_send( srv, body, body_sz );
}

static void
ir_server_send_200_no_content_len( fd_sshttp_ir_server_t * srv ) {
  static char const resp[] = "HTTP/1.1 200 OK\r\n\r\n";
  ir_server_send( srv, resp, sizeof(resp)-1UL );
}

static void
ir_server_send_304( fd_sshttp_ir_server_t * srv ) {
  static char const resp[] = "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n";
  ir_server_send( srv, resp, sizeof(resp)-1UL );
}

static void
ir_server_send_302_snapshot_redirect( fd_sshttp_ir_server_t * srv ) {
  static char const location[] = "/snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst";

  char  hdr[ 512 ];
  ulong hdr_sz = 0UL;
  FD_TEST( fd_cstr_printf_check( hdr, sizeof(hdr), &hdr_sz,
                                 "HTTP/1.1 302 Found\r\n"
                                 "Location: %s\r\n"
                                 "Content-Length: 0\r\n"
                                 "\r\n",
                                 location ) );

  ir_server_send( srv, hdr, hdr_sz );
}

static int
ir_http_advance( fd_sshttp_t *         http,
                 fd_sshttp_ir_exec_t * exec,
                 ulong                 cap ) {
  uchar data_buf[ 4096 ];
  cap = fd_ulong_min( cap, sizeof(data_buf) );
  if( FD_UNLIKELY( !cap ) ) cap = 1UL;

  ulong data_len = cap;
  int   downloading = 0;
  int   prev_state  = http->state;

  int res = fd_sshttp_advance( http, &data_len, data_buf, &downloading, exec->now );
  exec->advance_cnt++;

  FD_TEST( res>=FD_SSHTTP_ADVANCE_ERROR && res<=FD_SSHTTP_ADVANCE_DONE );
  if( FD_UNLIKELY( res==FD_SSHTTP_ADVANCE_DATA ) ) {
    FD_TEST( data_len>0UL && data_len<=cap );
  }
  if( FD_UNLIKELY( downloading ) ) {
    FD_TEST( prev_state==FD_SSHTTP_STATE_DL );
  }
  FD_TEST( (http->content_read<=http->content_len) | (http->content_len==ULONG_MAX) );

  return res;
}

static void
ir_drive_until_conn_or_terminal( fd_sshttp_t *           http,
                                 fd_sshttp_ir_server_t * srv,
                                 fd_sshttp_ir_exec_t *   exec,
                                 ulong                   max_steps ) {
  for( ulong i=0UL; i<max_steps; i++ ) {
    if( FD_UNLIKELY( ir_server_accept( srv )==1 ) ) return;

    exec->now += (long)(20UL*1000UL*1000UL);
    int res = ir_http_advance( http, exec, 512UL );
    if( FD_UNLIKELY( (res==FD_SSHTTP_ADVANCE_DONE) | (res==FD_SSHTTP_ADVANCE_ERROR) | (http->state==FD_SSHTTP_STATE_INIT) ) ) return;
  }
}

static int
ir_drive_until_state_or_terminal( fd_sshttp_t *           http,
                                  fd_sshttp_ir_server_t * srv,
                                  fd_sshttp_ir_exec_t *   exec,
                                  int                     target_state,
                                  ulong                   max_steps ) {
  for( ulong i=0UL; i<max_steps; i++ ) {
    ir_server_drain_req( srv );
    if( FD_UNLIKELY( http->state==target_state ) ) return 1;

    exec->now += (long)(20UL*1000UL*1000UL);
    int res = ir_http_advance( http, exec, 1024UL );
    if( FD_UNLIKELY( (res==FD_SSHTTP_ADVANCE_DONE) | (res==FD_SSHTTP_ADVANCE_ERROR) | (http->state==FD_SSHTTP_STATE_INIT) ) ) return 0;
  }

  return http->state==target_state;
}

static void
ir_scenario_redirect_budget( fd_sshttp_t *           http,
                             fd_sshttp_ir_server_t * srv,
                             fd_sshttp_ir_exec_t *   exec,
                             fd_sshttp_ir_stream_t * ir ) {
  ulong redirect_cnt = 1UL+((ulong)ir_u8( ir )&7UL);

  if( FD_UNLIKELY( -1==srv->listen_fd ) ) {
    if( FD_UNLIKELY( ir_server_init( srv ) ) ) return;
  }
  ir_server_close_conn( srv );

  if( FD_UNLIKELY( http->state!=FD_SSHTTP_STATE_INIT ) ) fd_sshttp_cancel( http );

  static char const hostname[] = "localhost";
  static char const path[]     = "/snapshot.tar.bz2";

  fd_sshttp_init( http,
                  srv->addr,
                  hostname,
                  0,
                  path,
                  sizeof(path)-1UL,
                  exec->now );

  for( ulong i=0UL; i<redirect_cnt; i++ ) {
    ir_drive_until_conn_or_terminal( http, srv, exec, 128UL );
    if( FD_UNLIKELY( srv->conn_fd==-1 ) ) break;
    if( FD_UNLIKELY( !ir_drive_until_state_or_terminal( http, srv, exec, FD_SSHTTP_STATE_RESP, 128UL ) ) ) break;

    int prev_hops = http->hops;
    ir_server_send_302_snapshot_redirect( srv );
    ir_server_close_conn( srv );

    int saw_reissue      = 0;
    int redirect_applied = 0;
    int terminal         = 0;

    for( ulong j=0UL; j<256UL; j++ ) {
      if( FD_UNLIKELY( ir_server_accept( srv )==1 ) ) saw_reissue = 1;
      if( FD_UNLIKELY( http->hops<prev_hops ) ) {
        redirect_applied = 1;
        break;
      }

      exec->now += (long)(20UL*1000UL*1000UL);
      int res = ir_http_advance( http, exec, 1024UL );

      if( FD_UNLIKELY( (res==FD_SSHTTP_ADVANCE_DONE) | (res==FD_SSHTTP_ADVANCE_ERROR) | (http->state==FD_SSHTTP_STATE_INIT) ) ) {
        terminal = 1;
        break;
      }
    }

    if( FD_UNLIKELY( terminal | !saw_reissue | !redirect_applied ) ) break;
    FD_TEST( http->hops<prev_hops );
    FD_TEST( http->hops>=0 );
  }

  if( FD_UNLIKELY( redirect_cnt>4UL ) ) {
    int terminated = 0;
    for( ulong i=0UL; i<256UL; i++ ) {
      exec->now += (long)(20UL*1000UL*1000UL);
      int res = ir_http_advance( http, exec, 1024UL );
      if( FD_UNLIKELY( (res==FD_SSHTTP_ADVANCE_DONE) | (res==FD_SSHTTP_ADVANCE_ERROR) | (http->state==FD_SSHTTP_STATE_INIT) ) ) {
        terminated = 1;
        break;
      }
      ir_server_accept( srv );
      ir_server_drain_req( srv );
    }
    FD_TEST( terminated );
  }
}

static void
ir_scenario_truncated_body( fd_sshttp_t *           http,
                            fd_sshttp_ir_server_t * srv,
                            fd_sshttp_ir_exec_t *   exec ) {
  if( FD_UNLIKELY( -1==srv->listen_fd ) ) {
    if( FD_UNLIKELY( ir_server_init( srv ) ) ) return;
  }
  ir_server_close_conn( srv );

  if( FD_UNLIKELY( http->state!=FD_SSHTTP_STATE_INIT ) ) fd_sshttp_cancel( http );

  static char const hostname[] = "localhost";
  static char const path[]     = "/snapshot.tar.bz2";

  fd_sshttp_init( http,
                  srv->addr,
                  hostname,
                  0,
                  path,
                  sizeof(path)-1UL,
                  exec->now );

  ir_drive_until_conn_or_terminal( http, srv, exec, 128UL );
  if( FD_UNLIKELY( srv->conn_fd==-1 ) ) return;
  if( FD_UNLIKELY( !ir_drive_until_state_or_terminal( http, srv, exec, FD_SSHTTP_STATE_RESP, 128UL ) ) ) return;

  static char const resp[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 64\r\n"
    "\r\n"
    "abc";

  ir_server_send( srv, resp, sizeof(resp)-1UL );
  ir_server_close_conn( srv );

  int terminated = 0;
  for( ulong i=0UL; i<512UL; i++ ) {
    exec->now += (long)(20UL*1000UL*1000UL); /* 20ms */
    int res = ir_http_advance( http, exec, 1024UL );
    if( FD_UNLIKELY( (res==FD_SSHTTP_ADVANCE_DONE) | (res==FD_SSHTTP_ADVANCE_ERROR) | (http->state==FD_SSHTTP_STATE_INIT) ) ) {
      terminated = 1;
      break;
    }
  }

  FD_TEST( terminated );
}

int
LLVMFuzzerInitialize( int *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set( 3 );

  ulong align     = fd_sshttp_align();
  ulong footprint = fd_sshttp_footprint();
  http_mem = aligned_alloc( align, footprint );
  FD_TEST( http_mem );

  fd_sshttp_fuzz = 0;

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( http_mem ) );
  FD_TEST( http );

  fd_sshttp_ir_stream_t ir = {
    .cur = data,
    .end = data + data_sz
  };

  fd_sshttp_ir_server_t srv = {
    .listen_fd = -1,
    .conn_fd   = -1,
    .addr      = { .addr = 0U, .port = 0U }
  };

  fd_sshttp_ir_exec_t exec = {
    .now         = 0L,
    .advance_cnt = 0UL
  };

  char  hostname[ 256 ];
  char  path[ 512 ];
  uchar raw[ 1024 ];

  fd_cstr_fini( hostname );
  fd_cstr_fini( path );

  for( ulong step=0UL; step<1024UL; step++ ) {
    if( FD_UNLIKELY( ir.cur>=ir.end ) ) break;

    int acc_res = ir_server_accept( &srv );
    if( FD_UNLIKELY( acc_res==-1 ) ) break;
    ir_server_drain_req( &srv );

    uchar op = (uchar)(ir_u8( &ir ) & 0x0fU);

    switch( op ) {
      case 0x0: {
        /* NOP */
        break;
      }

      case 0x1: {
        (void)ir_server_init( &srv );
        break;
      }

      case 0x2: {
        if( FD_UNLIKELY( srv.listen_fd==-1 ) ) {
          if( FD_UNLIKELY( ir_server_init( &srv ) ) ) break;
        }

        if( FD_UNLIKELY( http->state!=FD_SSHTTP_STATE_INIT ) ) fd_sshttp_cancel( http );

        ulong host_n = 1UL + ((ulong)ir_u8( &ir ) & 31UL);
        host_n = fd_ulong_min( host_n, sizeof(hostname)-1UL );
        for( ulong i=0UL; i<host_n; i++ ) hostname[ i ] = (char)('a' + (ir_u8( &ir ) % 26U));
        hostname[ host_n ] = '\0';

        ulong path_n = 1UL + ((ulong)ir_u8( &ir ) & 127UL);
        path_n = fd_ulong_min( path_n, sizeof(path)-1UL );
        path[ 0 ] = '/';
        for( ulong i=1UL; i<path_n; i++ ) {
          uchar ch = ir_u8( &ir );
          path[ i ] = (char)( ( ch%3U==0U ) ? ('a' + (ch%26U)) : (( ch%3U==1U ) ? ('0' + (ch%10U)) : '-') );
        }

        fd_sshttp_init( http,
                        srv.addr,
                        hostname,
                        0,
                        path,
                        path_n,
                        exec.now );
        break;
      }

      case 0x3: {
        if( FD_UNLIKELY( http->state!=FD_SSHTTP_STATE_INIT ) ) fd_sshttp_cancel( http );

        fd_ip4_port_t bad = {
          .addr = FD_IP4_ADDR( 255, 255, 255, 255 ),
          .port = fd_ushort_bswap( 80 )
        };

        static char const hostname_bad[] = "bad.host";
        static char const path_bad[]     = "/snapshot.tar.bz2";

        fd_sshttp_init( http,
                        bad,
                        hostname_bad,
                        0,
                        path_bad,
                        sizeof(path_bad)-1UL,
                        exec.now );
        break;
      }

      case 0x4: {
        exec.now += ir_delta_nanos( &ir );
        ulong cap = 1UL + ((ulong)ir_u8( &ir ) & 0xffUL);
        (void)ir_http_advance( http, &exec, cap );
        break;
      }

      case 0x5: {
        ulong n = ir_take( &ir, raw, sizeof(raw) );
        ir_server_send( &srv, raw, n );
        break;
      }

      case 0x6: {
        ir_server_send_200( &srv, &ir );
        break;
      }

      case 0x7: {
        ir_server_send_302_snapshot_redirect( &srv );
        break;
      }

      case 0x8: {
        ir_server_send_304( &srv );
        break;
      }

      case 0x9: {
        ir_server_send_200_no_content_len( &srv );
        break;
      }

      case 0xa: {
        ir_server_shutdown_wr( &srv );
        break;
      }

      case 0xb: {
        ir_server_close_conn( &srv );
        break;
      }

      case 0xc: {
        fd_sshttp_cancel( http );
        break;
      }

      case 0xd: {
        ir_scenario_redirect_budget( http, &srv, &exec, &ir );
        break;
      }

      case 0xe: {
        ir_scenario_truncated_body( http, &srv, &exec );
        break;
      }

      case 0xf: {
        step = 1024UL;
        break;
      }

      default: break;
    }
  }

  fd_sshttp_cancel( http );

#if FD_HAS_OPENSSL
  if( FD_LIKELY( !!http->ssl_ctx ) ) {
    SSL_CTX_free( http->ssl_ctx );
    http->ssl_ctx = NULL;
  }
#endif

  ir_server_fini( &srv );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
