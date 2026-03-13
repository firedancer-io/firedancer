#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../disco/topo/fd_topo.h"
#include "fd_genesis_client_private.h"

#define GENESIS_REQ_SZ      (1024UL)
#define FUZZ_MAX_PEERS      (4UL)
#define FUZZ_MAX_STEPS      (96UL)
#define FUZZ_MAX_RESP_BYTES (8192UL)
#define FUZZ_SCENARIOS      (12UL)
#define FUZZ_MUT_MIN_INPUT  (96UL)
#define NSEC_PER_SEC        (1000000000L)

static fd_genesis_client_t * client_mem      = NULL;

typedef struct {
  uint state;
} fd_fuzz_mut_rng_t;

typedef struct {
  uchar const * data;
  ulong         sz;
  ulong         off;
} fd_fuzz_stream_t;

typedef struct {
  int   fd;
  uchar response[ FUZZ_MAX_RESP_BYTES ];
  ulong response_sz;
  ulong response_off;
  int   close_after_send;
  int   hard_close_after_send;
} fd_fuzz_peer_chan_t;

static inline uchar
fuzz_u8( fd_fuzz_stream_t * stream,
         uchar              fallback ) {
  if( FD_LIKELY( stream->off<stream->sz ) ) return stream->data[ stream->off++ ];
  return fallback;
}

static inline ulong
fuzz_range( fd_fuzz_stream_t * stream,
            ulong              max_exclusive,
            uchar              fallback ) {
  if( FD_UNLIKELY( !max_exclusive ) ) return 0UL;
  return (ulong)fuzz_u8( stream, fallback ) % max_exclusive;
}

static inline uint
fuzz_mut_rand( fd_fuzz_mut_rng_t * rng ) {
  uint x = rng->state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  rng->state = x;
  return x;
}

static inline ulong
fuzz_mut_roll( fd_fuzz_mut_rng_t * rng,
               ulong               max_exclusive ) {
  if( FD_UNLIKELY( !max_exclusive ) ) return 0UL;
  return (ulong)fuzz_mut_rand( rng ) % max_exclusive;
}

static inline uchar
fuzz_mut_u8( fd_fuzz_mut_rng_t * rng ) {
  return (uchar)fuzz_mut_rand( rng );
}

static inline void
fuzz_mut_ensure( uchar *            data,
                 ulong *            data_sz,
                 ulong              want_sz,
                 ulong              max_sz,
                 fd_fuzz_mut_rng_t * rng ) {
  want_sz = fd_ulong_min( want_sz, max_sz );
  while( *data_sz < want_sz ) data[ (*data_sz)++ ] = fuzz_mut_u8( rng );
}

static inline void
set_nonblocking( int fd ) {
  int flags = fcntl( fd, F_GETFL, 0 );
  if( FD_LIKELY( flags!=-1 ) ) (void)fcntl( fd, F_SETFL, flags | O_NONBLOCK );
}

static void
drain_fd( int fd ) {
  uchar scratch[ 1024UL ];
  for( int i=0; i<8; i++ ) {
    long n = recv( fd, scratch, sizeof(scratch), MSG_DONTWAIT|MSG_NOSIGNAL );
    if( FD_LIKELY( n>0 ) ) continue;
    if( FD_UNLIKELY( n<0 && errno==EINTR ) ) continue;
    break;
  }
}

static ulong
synth_response( fd_fuzz_stream_t * stream,
                uchar              mode,
                uchar *            out,
                ulong              out_cap,
                int *              close_after_send,
                int *              hard_close_after_send ) {
  *close_after_send      = 0;
  *hard_close_after_send = 0;

  uchar body[ 256UL ];
  ulong body_sz = 16UL + fuzz_range( stream, 112UL, 0x2A );
  for( ulong i=0UL; i<body_sz; i++ ) body[i] = fuzz_u8( stream, (uchar)('A'+(i%26UL)) );

  switch( mode ) {
    case 0: { /* valid HTTP/200 with complete body */
      int hdr = snprintf( (char *)out, out_cap,
                          "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nServer: fuzz\r\n\r\n",
                          body_sz );
      if( FD_UNLIKELY( hdr<0 ) ) return 0UL;
      ulong off = (ulong)hdr;
      if( FD_UNLIKELY( off>=out_cap ) ) return 0UL;
      ulong copy_sz = fd_ulong_min( body_sz, out_cap-off );
      memcpy( out+off, body, copy_sz );
      return off+copy_sz;
    }
    case 1: { /* incomplete header => phr_parse_response returns -2 */
      int hdr = snprintf( (char *)out, out_cap,
                          "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n",
                          body_sz );
      if( FD_UNLIKELY( hdr<0 ) ) return 0UL;
      *close_after_send = 1;
      return fd_ulong_min( (ulong)hdr, out_cap );
    }
    case 2: { /* malformed response line => parse error */
      char const * malformed = "HTP/1.1 ???\r\n\r\n";
      ulong sz = fd_ulong_min( strlen( malformed ), out_cap );
      memcpy( out, malformed, sz );
      *close_after_send = 1;
      return sz;
    }
    case 3: { /* non-200 status */
      char const * resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nnope";
      ulong sz = fd_ulong_min( strlen( resp ), out_cap );
      memcpy( out, resp, sz );
      *close_after_send = 1;
      return sz;
    }
    case 4: { /* missing content-length */
      char const * resp = "HTTP/1.1 200 OK\r\nDate: fuzz\r\n\r\nABCD";
      ulong sz = fd_ulong_min( strlen( resp ), out_cap );
      memcpy( out, resp, sz );
      *close_after_send = 1;
      return sz;
    }
    case 5: { /* invalid content-length */
      char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: xyz\r\n\r\nABCD";
      ulong sz = fd_ulong_min( strlen( resp ), out_cap );
      memcpy( out, resp, sz );
      *close_after_send = 1;
      return sz;
    }
    case 6: { /* content-length overflows UINT_MAX */
      char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 4294967296\r\n\r\nABCD";
      ulong sz = fd_ulong_min( strlen( resp ), out_cap );
      memcpy( out, resp, sz );
      *close_after_send = 1;
      return sz;
    }
    case 7: { /* declared body exceeds peer->response capacity */
      char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 10485761\r\n\r\n";
      ulong sz = fd_ulong_min( strlen( resp ), out_cap );
      memcpy( out, resp, sz );
      *close_after_send = 1;
      return sz;
    }
    default: { /* partial body => content_length+len>response_bytes_read */
      ulong declared_body_sz = body_sz + 32UL;
      ulong sent_body_sz     = body_sz / 2UL;
      int hdr = snprintf( (char *)out, out_cap,
                          "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                          declared_body_sz );
      if( FD_UNLIKELY( hdr<0 ) ) return 0UL;
      ulong off = (ulong)hdr;
      if( FD_UNLIKELY( off>=out_cap ) ) return 0UL;
      ulong copy_sz = fd_ulong_min( sent_body_sz, out_cap-off );
      memcpy( out+off, body, copy_sz );
      *close_after_send      = 1;
      *hard_close_after_send = (int)(fuzz_u8( stream, 0x5A ) & 1U);
      return off+copy_sz;
    }
  }
}

static void
send_peer_chunk( fd_fuzz_peer_chan_t * peer,
                 ulong                 chunk_max ) {
  if( FD_UNLIKELY( peer->fd==-1 || peer->response_off>=peer->response_sz ) ) return;

  ulong chunk_sz = fd_ulong_min( chunk_max, peer->response_sz-peer->response_off );
  long n = send( peer->fd, peer->response + peer->response_off, chunk_sz, MSG_NOSIGNAL );
  if( FD_LIKELY( n>0 ) ) peer->response_off += (ulong)n;
  else if( FD_UNLIKELY( n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR ) ) {
    close( peer->fd );
    peer->fd = -1;
    return;
  }

  if( FD_UNLIKELY( peer->fd!=-1 && peer->response_off>=peer->response_sz && peer->close_after_send ) ) {
    (void)shutdown( peer->fd, SHUT_WR );
    if( peer->hard_close_after_send ) {
      close( peer->fd );
      peer->fd = -1;
    }
  }
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(3);

  ulong align     = fd_genesis_client_align();
  ulong footprint = fd_genesis_client_footprint();
  client_mem = aligned_alloc( align, footprint );
  FD_TEST( client_mem );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_fuzz_stream_t stream = {
    .data = data,
    .sz   = data_sz,
    .off  = 0UL
  };

  fd_genesis_client_t * client = fd_genesis_client_join( fd_genesis_client_new( client_mem ) );
  FD_TEST( client );

  ulong peer_cnt = 1UL + fuzz_range( &stream, FUZZ_MAX_PEERS, 0x01 );
  uchar scenario = (uchar)fuzz_range( &stream, FUZZ_SCENARIOS, 0x00 );

  fd_fuzz_peer_chan_t chans[ FUZZ_MAX_PEERS ];
  for( ulong i=0UL; i<FUZZ_MAX_PEERS; i++ ) {
    chans[i].fd                    = -1;
    chans[i].response_sz           = 0UL;
    chans[i].response_off          = 0UL;
    chans[i].close_after_send      = 0;
    chans[i].hard_close_after_send = 0;
  }

  for( ulong i=0UL; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) client->pollfds[i].fd = -1;

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int sockfds[2];
    FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sockfds ) );
    set_nonblocking( sockfds[0] );
    set_nonblocking( sockfds[1] );

    client->pollfds[i] = (struct pollfd){
      .fd      = sockfds[0],
      .events  = POLLIN | POLLOUT,
      .revents = 0
    };

    chans[i].fd = sockfds[1];

    uchar mode = (uchar)fuzz_range( &stream, 9UL, (uchar)(0xA0U+i) );
    if( i==0UL && scenario<9U ) mode = scenario;
    chans[i].response_sz = synth_response( &stream, mode, chans[i].response, sizeof(chans[i].response),
                                           &chans[i].close_after_send, &chans[i].hard_close_after_send );

    client->peers[i].addr.addr = 0x7F000001U + (uint)i;
    client->peers[i].addr.port = fd_ushort_bswap( (ushort)(8899U+i) );
    client->peers[i].response_bytes_read = 0UL;

    ulong write_mode = fuzz_range( &stream, 3UL, (uchar)i );
    if( scenario<8U || write_mode==1UL ) {
      client->peers[i].writing = 0;
      client->peers[i].request_bytes_sent = GENESIS_REQ_SZ;
    } else if( write_mode==2UL ) {
      client->peers[i].writing = 1;
      client->peers[i].request_bytes_sent = GENESIS_REQ_SZ - 1UL;
    } else {
      client->peers[i].writing = 1;
      client->peers[i].request_bytes_sent = 0UL;
    }
  }

  client->peer_cnt           = peer_cnt;
  client->remaining_peer_cnt = peer_cnt;
  client->start_time_nanos   = fd_log_wallclock();

  if( scenario==9U ) {
    client->remaining_peer_cnt = 0UL;
  } else if( scenario==10U ) {
    client->start_time_nanos = fd_log_wallclock() - (21L*NSEC_PER_SEC);
  } else if( scenario==11U ) {
    for( ulong i=0UL; i<peer_cnt; i++ ) {
      if( chans[i].fd!=-1 ) {
        close( chans[i].fd );
        chans[i].fd = -1;
      }
    }
  }

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    if( (fuzz_u8( &stream, (uchar)i ) & 1U) && chans[i].fd!=-1 ) {
      ulong chunk_max = 1UL + fuzz_range( &stream, 256UL, 0x40 );
      send_peer_chunk( &chans[i], chunk_max );
    }
  }

  ulong step_budget = 16UL + fuzz_range( &stream, FUZZ_MAX_STEPS-15UL, 0x20 );
  for( ulong step=0UL; step<step_budget; step++ ) {
    FD_FUZZ_MUST_BE_COVERED;

    ulong idx = fuzz_range( &stream, peer_cnt, (uchar)step );
    fd_fuzz_peer_chan_t * chan = &chans[ idx ];
    uchar action = fuzz_u8( &stream, (uchar)(step*13UL) );

    switch( action & 7U ) {
      case 0:
        send_peer_chunk( chan, 1UL + fuzz_range( &stream, 512UL, 0x80 ) );
        break;
      case 1:
        if( chan->response_off<chan->response_sz ) send_peer_chunk( chan, chan->response_sz-chan->response_off );
        break;
      case 2:
        if( chan->fd!=-1 ) (void)shutdown( chan->fd, SHUT_WR );
        break;
      case 3:
        if( chan->fd!=-1 ) {
          close( chan->fd );
          chan->fd = -1;
        }
        break;
      case 4:
        if( chan->fd!=-1 ) drain_fd( chan->fd );
        break;
      case 5:
        client->start_time_nanos = fd_log_wallclock() - (21L*NSEC_PER_SEC);
        break;
      case 6:
        client->peers[ idx ].writing = 0;
        client->peers[ idx ].request_bytes_sent = GENESIS_REQ_SZ;
        break;
      default:
        if( action & 0x40U ) client->remaining_peer_cnt = 0UL;
        break;
    }

    ulong prev_sent[ FUZZ_MAX_PEERS ] = {0};
    for( ulong i=0UL; i<peer_cnt; i++ ) prev_sent[i] = client->peers[i].request_bytes_sent;

    fd_ip4_port_t out_peer = {0};
    uchar * out_buffer = NULL;
    ulong out_buffer_sz = 0UL;
    int charge_busy = 0;

    int result = fd_genesis_client_poll( client, &out_peer, &out_buffer, &out_buffer_sz, &charge_busy );

    for( ulong i=0UL; i<peer_cnt; i++ ) {
      if( FD_UNLIKELY( prev_sent[i]!=client->peers[i].request_bytes_sent && chans[i].fd!=-1 ) ) {
        drain_fd( chans[i].fd );
      }
    }

    if( result==0 && out_buffer && out_buffer_sz>0UL ) {
      uchar x = 0;
      for( ulong j=0UL; j<out_buffer_sz; j++ ) x ^= out_buffer[j];
      FD_COMPILER_FORGET( x );
      if( action & 0x80U ) break;
    } else if( result==-1 ) {
      break;
    }
  }

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    if( chans[i].fd!=-1 ) close( chans[i].fd );
    if( client->pollfds[i].fd!=-1 ) {
      close( client->pollfds[i].fd );
      client->pollfds[i].fd = -1;
    }
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   data_sz,
                         ulong   max_sz,
                         uint    seed ) {
  if( FD_UNLIKELY( !max_sz ) ) return 0UL;

  fd_fuzz_mut_rng_t rng = {
    .state = seed ? seed : 0x9E3779B9U
  };

  if( FD_LIKELY( data_sz ) ) data_sz = LLVMFuzzerMutate( data, data_sz, max_sz );
  else {
    data[0] = fuzz_mut_u8( &rng );
    data_sz = 1UL;
  }

  if( FD_UNLIKELY( !data_sz ) ) {
    data[0] = fuzz_mut_u8( &rng );
    data_sz = 1UL;
  }

  ulong min_sz = FUZZ_MUT_MIN_INPUT + fuzz_mut_roll( &rng, 128UL );
  fuzz_mut_ensure( data, &data_sz, min_sz, max_sz, &rng );

  if( FD_LIKELY( max_sz>=1UL ) ) data[0] = (uchar)fuzz_mut_roll( &rng, FUZZ_MAX_PEERS );
  ulong peer_cnt = 1UL + (max_sz>=1UL ? ((ulong)data[0] % FUZZ_MAX_PEERS) : 0UL);

  ulong scenario = fuzz_mut_roll( &rng, 4UL )
                 ? fuzz_mut_roll( &rng, 9UL )
                 : (9UL + fuzz_mut_roll( &rng, FUZZ_SCENARIOS-9UL ));
  if( FD_LIKELY( max_sz>=2UL ) ) data[1] = (uchar)scenario;

  ulong cursor = fd_ulong_min( data_sz, 2UL );
  static char const alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\r\n:;,-_/= ";
  ulong alphabet_len = sizeof(alphabet) - 1UL;

  for( ulong i=0UL; i<peer_cnt && cursor<max_sz; i++ ) {
    fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
    ulong mode = fuzz_mut_roll( &rng, 9UL );
    data[ cursor++ ] = (uchar)mode;

    fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
    ulong body_sz = 16UL + fuzz_mut_roll( &rng, 112UL );
    data[ cursor++ ] = (uchar)(body_sz - 16UL);

    fuzz_mut_ensure( data, &data_sz, cursor+body_sz, max_sz, &rng );
    int chaos = (int)(0UL==fuzz_mut_roll( &rng, 16UL ));
    for( ulong j=0UL; j<body_sz && cursor+j<data_sz; j++ ) {
      data[ cursor+j ] = chaos ? fuzz_mut_u8( &rng )
                               : (uchar)alphabet[ fuzz_mut_roll( &rng, alphabet_len ) ];
    }
    cursor = fd_ulong_min( max_sz, cursor + body_sz );

    if( mode>=8UL ) {
      fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
      data[ cursor++ ] = fuzz_mut_u8( &rng );
    }

    fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
    data[ cursor++ ] = (uchar)fuzz_mut_roll( &rng, 3UL );
  }

  for( ulong i=0UL; i<peer_cnt && cursor<max_sz; i++ ) {
    fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
    uchar send_now = (uchar)(fuzz_mut_roll( &rng, 4UL ) ? 1U : 0U);
    data[ cursor++ ] = send_now;
    if( send_now ) {
      fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
      data[ cursor++ ] = fuzz_mut_u8( &rng );
    }
  }

  fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
  ulong step_budget = 16UL + fuzz_mut_roll( &rng, FUZZ_MAX_STEPS-15UL );
  data[ cursor++ ] = (uchar)(step_budget - 16UL);

  ulong steps_to_emit = fd_ulong_min( step_budget, 40UL + fuzz_mut_roll( &rng, 24UL ) );
  for( ulong step=0UL; step<steps_to_emit && cursor<max_sz; step++ ) {
    fuzz_mut_ensure( data, &data_sz, cursor+2UL, max_sz, &rng );
    if( FD_UNLIKELY( cursor>=data_sz ) ) break;
    data[ cursor++ ] = (uchar)fuzz_mut_roll( &rng, peer_cnt );
    uchar action = (uchar)fuzz_mut_roll( &rng, 8UL );
    if( (action==7U) && (0UL==fuzz_mut_roll( &rng, 2UL )) ) action |= 0x40U;
    if( 0UL==fuzz_mut_roll( &rng, 9UL ) ) action |= 0x80U;
    data[ cursor++ ] = action;
    if( (action & 7U)==0U ) {
      fuzz_mut_ensure( data, &data_sz, cursor+1UL, max_sz, &rng );
      data[ cursor++ ] = fuzz_mut_u8( &rng );
    }
  }

  ulong flip_cnt = 1UL + fuzz_mut_roll( &rng, 8UL );
  for( ulong i=0UL; i<flip_cnt && data_sz; i++ ) {
    ulong idx = fuzz_mut_roll( &rng, data_sz );
    data[idx] ^= (uchar)(1U << fuzz_mut_roll( &rng, 8UL ));
  }

  if( 0UL==fuzz_mut_roll( &rng, 6UL ) ) {
    ulong append = fd_ulong_min( max_sz-data_sz, 1UL + fuzz_mut_roll( &rng, 96UL ) );
    for( ulong i=0UL; i<append; i++ ) data[ data_sz++ ] = fuzz_mut_u8( &rng );
  }

  return data_sz;
}
