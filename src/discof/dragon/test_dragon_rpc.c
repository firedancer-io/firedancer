/* test_dragon_rpc drives the Dragon's Mouth service over the gRPC
   server's direct transport: no sockets, no tile, and a clock the test
   moves by hand. */

#include "fd_dragon_rpc.h"
#include "fd_geyser_core.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"
#include "proto/geyser.pb.h"
#include "proto/health.pb.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../waltz/grpc/fd_grpc_server_private.h"
#include "../../waltz/h2/fd_hpack_wr.h"
#include "../../flamenco/runtime/fd_system_ids.h"

/* Protobuf writers ***************************************************/

static ulong
pb_varint( uchar * p,
           ulong   v ) {
  ulong o = 0UL;
  while( v>=0x80UL ) { p[ o++ ] = (uchar)( ( v & 0x7FUL ) | 0x80UL ); v >>= 7; }
  p[ o++ ] = (uchar)v;
  return o;
}

static ulong
pb_varint_field( uchar * p,
                 uint    field,
                 ulong   v ) {
  ulong o = 0UL;
  p[ o++ ] = (uchar)( ( field<<3 ) | 0U );
  o += pb_varint( p+o, v );
  return o;
}

static ulong
pb_bytes_field( uchar *       p,
                uint          field,
                void const *  data,
                ulong         data_sz ) {
  ulong o = 0UL;
  p[ o++ ] = (uchar)( ( field<<3 ) | 2U );
  o += pb_varint( p+o, data_sz );
  if( data_sz ) fd_memcpy( p+o, data, data_sz );
  return o+data_sz;
}

/* pb_map_entry writes one map<string,X> entry with an empty value into
   the map field of a SubscribeRequest. */

static ulong
pb_map_entry( uchar *      p,
              uint         field,
              char const * name,
              ulong        name_len ) {
  uchar entry[ 8192 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, name, name_len );
  return pb_bytes_field( p, field, entry, entry_sz );
}

/* Client side ********************************************************/

#define TC_STREAM_MAX 32

struct tc_stream {
  uint  id;
  int   used;
  int   hdr_block_cnt;
  int   end_stream;
  char  status[ 16 ];
  char  content_type[ 64 ];
  char  grpc_status[ 16 ];
  char  grpc_message[ 512 ];
  ulong data_sz;
  /* The DATA bytes of the stream.  The buffer is one slice of the
     shared pool unless a test hands the stream a larger one, which is
     what an update of several megabytes needs. */
  uchar * data;
  ulong   data_cap;
};

#define TC_STREAM_DATA_CAP (64UL<<10)

typedef struct tc_stream tc_stream_t;

struct tc {
  fd_grpc_server_t *      server;
  fd_grpc_server_conn_t * conn;
  fd_dragon_rpc_t *       rpc;
  long                    now;
  tc_stream_t             stream[ TC_STREAM_MAX ];
  int                     settings_cnt;
  uchar                   res[ 1UL<<20 ];
  ulong                   res_sz;
  uchar                   req[ 1UL<<20 ];
  ulong                   req_sz;
};

typedef struct tc tc_t;

static tc_t g_tc[1];

/* The DATA bytes of every stream, one slice each. */

static uchar tc_stream_data[ TC_STREAM_MAX*TC_STREAM_DATA_CAP ];

static tc_stream_t *
tc_stream( tc_t * tc,
           uint   id ) {
  for( ulong i=0UL; i<TC_STREAM_MAX; i++ ) {
    if( tc->stream[i].used && tc->stream[i].id==id ) return tc->stream+i;
  }
  for( ulong i=0UL; i<TC_STREAM_MAX; i++ ) {
    if( !tc->stream[i].used ) {
      tc_stream_t * s = tc->stream+i;
      s->used     = 1;
      s->id       = id;
      s->data     = tc_stream_data + i*TC_STREAM_DATA_CAP;
      s->data_cap = TC_STREAM_DATA_CAP;
      return s;
    }
  }
  FD_LOG_ERR(( "out of test stream slots" ));
}

static void
tc_frame( tc_t *       tc,
          uint         type,
          uint         flags,
          uint         stream_id,
          void const * payload,
          ulong        payload_sz ) {
  FD_TEST( tc->req_sz + 9UL + payload_sz <= sizeof(tc->req) );
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( type, payload_sz ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  fd_memcpy( tc->req+tc->req_sz, &hdr, 9UL );
  tc->req_sz += 9UL;
  if( payload_sz ) {
    fd_memcpy( tc->req+tc->req_sz, payload, payload_sz );
    tc->req_sz += payload_sz;
  }
}

static ulong
hdr_lit( uchar *      p,
         char const * name,
         ulong        name_len,
         char const * value,
         ulong        value_len ) {
  ulong o = 0UL;
  p[ o++ ] = 0x00;
  FD_TEST( name_len<127UL && value_len<127UL );
  p[ o++ ] = (uchar)name_len;
  fd_memcpy( p+o, name, name_len ); o += name_len;
  p[ o++ ] = (uchar)value_len;
  fd_memcpy( p+o, value, value_len ); o += value_len;
  return o;
}

#define HDR_LIT(p,name,value) hdr_lit( (p), (name), sizeof(name)-1UL, (value), strlen( value ) )

struct req_opt {
  char const * path;
  char const * x_token;
  char const * accept_encoding;
  int          end_stream;
};

typedef struct req_opt req_opt_t;

static void
tc_request( tc_t *            tc,
            uint              stream_id,
            req_opt_t const * opt ) {
  uchar block[ 1024 ];
  ulong o = 0UL;

  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 ); /* :method: POST */
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 ); /* :scheme: http */
  o += HDR_LIT( block+o, ":path", opt->path );
  o += HDR_LIT( block+o, ":authority", "localhost" );
  o += HDR_LIT( block+o, "content-type", "application/grpc" );
  o += HDR_LIT( block+o, "te", "trailers" );
  if( opt->x_token         ) o += HDR_LIT( block+o, "x-token",              opt->x_token         );
  if( opt->accept_encoding ) o += HDR_LIT( block+o, "grpc-accept-encoding", opt->accept_encoding );

  uint flags = FD_H2_FLAG_END_HEADERS;
  if( opt->end_stream ) flags |= FD_H2_FLAG_END_STREAM;
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS, flags, stream_id, block, o );
}

static void
tc_msg( tc_t *       tc,
        uint         stream_id,
        void const * msg,
        ulong        msg_sz,
        int          end_stream ) {
  static uchar buf[ 1UL<<18 ];
  FD_TEST( msg_sz+5UL<=sizeof(buf) );
  buf[0] = 0;
  uint be = fd_uint_bswap( (uint)msg_sz );
  fd_memcpy( buf+1, &be, 4UL );
  if( msg_sz ) fd_memcpy( buf+5, msg, msg_sz );
  tc_frame( tc, FD_H2_FRAME_TYPE_DATA, end_stream ? FD_H2_FLAG_END_STREAM : 0U,
            stream_id, buf, msg_sz+5UL );
}

static void
tc_settings( tc_t * tc,
             ushort id,
             uint   value ) {
  uchar payload[ 6 ];
  ushort id_be = fd_ushort_bswap( id );
  uint   va_be = fd_uint_bswap( value );
  fd_memcpy( payload,   &id_be, 2UL );
  fd_memcpy( payload+2, &va_be, 4UL );
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, payload, 6UL );
}

static void
tc_window_update( tc_t * tc,
                  uint   stream_id,
                  uint   increment ) {
  uint be = fd_uint_bswap( increment );
  tc_frame( tc, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, stream_id, &be, 4UL );
}

static void
tc_parse_hdrs( tc_stream_t * s,
               uchar const * block,
               ulong         block_sz ) {
  static uchar scratch_buf[ 16384 ];
  fd_hpack_rd_t rd[1];
  FD_TEST( fd_hpack_rd_init( rd, block, block_sz ) );
  while( !fd_hpack_rd_done( rd ) ) {
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    FD_TEST( !fd_hpack_rd_next( rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) ) );
    char * dst    = NULL;
    ulong  dst_sz = 0UL;
    if     ( hdr->name_len== 7UL && fd_memeq( hdr->name, ":status",      7UL ) ) { dst = s->status;       dst_sz = sizeof(s->status      ); }
    else if( hdr->name_len==12UL && fd_memeq( hdr->name, "content-type",12UL ) ) { dst = s->content_type; dst_sz = sizeof(s->content_type); }
    else if( hdr->name_len==11UL && fd_memeq( hdr->name, "grpc-status", 11UL ) ) { dst = s->grpc_status;  dst_sz = sizeof(s->grpc_status ); }
    else if( hdr->name_len==12UL && fd_memeq( hdr->name, "grpc-message",12UL ) ) { dst = s->grpc_message; dst_sz = sizeof(s->grpc_message); }
    if( dst ) {
      ulong len = fd_ulong_min( hdr->value_len, dst_sz-1UL );
      fd_memcpy( dst, hdr->value, len );
      dst[ len ] = '\0';
    }
  }
  s->hdr_block_cnt++;
}

static void
tc_parse( tc_t * tc ) {
  ulong off = 0UL;
  while( tc->res_sz-off >= 9UL ) {
    fd_h2_frame_hdr_t hdr;
    fd_memcpy( &hdr, tc->res+off, 9UL );
    ulong payload_sz = fd_h2_frame_length( hdr.typlen );
    uint  type       = fd_h2_frame_type  ( hdr.typlen );
    uint  stream_id  = fd_h2_frame_stream_id( hdr.r_stream_id );
    if( tc->res_sz-off < 9UL+payload_sz ) break;
    uchar const * payload = tc->res+off+9UL;
    off += 9UL+payload_sz;

    switch( type ) {
    case FD_H2_FRAME_TYPE_SETTINGS:
      if( !( hdr.flags & FD_H2_FLAG_ACK ) ) tc->settings_cnt++;
      break;
    case FD_H2_FRAME_TYPE_HEADERS: {
      tc_stream_t * s = tc_stream( tc, stream_id );
      tc_parse_hdrs( s, payload, payload_sz );
      if( hdr.flags & FD_H2_FLAG_END_STREAM ) s->end_stream = 1;
      break;
    }
    case FD_H2_FRAME_TYPE_DATA: {
      tc_stream_t * s = tc_stream( tc, stream_id );
      FD_TEST( s->data_sz+payload_sz<=s->data_cap );
      fd_memcpy( s->data+s->data_sz, payload, payload_sz );
      s->data_sz += payload_sz;
      if( hdr.flags & FD_H2_FLAG_END_STREAM ) s->end_stream = 1;
      break;
    }
    default:
      break;
    }
  }
  if( off ) {
    memmove( tc->res, tc->res+off, tc->res_sz-off );
    tc->res_sz -= off;
  }
}

static void
tc_drain( tc_t * tc ) {
  for(;;) {
    if( FD_UNLIKELY( !fd_grpc_server_conn_is_open( tc->conn ) ) ) break;
    ulong n = fd_grpc_server_conn_pop_tx( tc->conn, tc->res+tc->res_sz, sizeof(tc->res)-tc->res_sz );
    if( !n ) break;
    tc->res_sz += n;
  }
  tc_parse( tc );
}

/* tc_service runs the service layers the tile would run every loop */

static void
tc_service( tc_t * tc ) {
  fd_dragon_rpc_service( tc->rpc, tc->now );
  fd_grpc_server_service( tc->server, tc->now );
  tc_drain( tc );
}

static void
tc_flush( tc_t * tc ) {
  ulong off = 0UL;
  while( off<tc->req_sz ) {
    ulong n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
    tc_drain( tc );
    if( !n ) {
      if( FD_UNLIKELY( !fd_grpc_server_conn_is_open( tc->conn ) ) ) break;
      tc_service( tc );
      n = fd_grpc_server_conn_push_rx( tc->conn, tc->req+off, tc->req_sz-off, tc->now );
      tc_drain( tc );
      if( !n ) break;
    }
    off += n;
  }
  tc->req_sz = 0UL;
  tc_service( tc );
}

static void
tc_open( tc_t *             tc,
         fd_grpc_server_t * server,
         fd_dragon_rpc_t *  rpc ) {
  tc->server = server;
  tc->rpc    = rpc;
  tc->now    = 1700000000L*1000000000L; /* a plausible wallclock */
  fd_memset( tc->stream, 0, sizeof(tc->stream) );
  tc->settings_cnt = 0;
  tc->res_sz       = 0UL;
  tc->req_sz       = 0UL;

  fd_dragon_rpc_service( rpc, tc->now );
  tc->conn = fd_grpc_server_conn_open_direct( server, tc->now );
  FD_TEST( tc->conn );

  fd_memcpy( tc->req, fd_h2_client_preface, 24UL );
  tc->req_sz = 24UL;
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, NULL, 0UL );
  tc_flush( tc );
  FD_TEST( tc->settings_cnt==1 );
  tc_frame( tc, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
  tc_flush( tc );
}

static void
tc_close( tc_t * tc ) {
  if( fd_grpc_server_conn_is_open( tc->conn ) ) fd_grpc_server_conn_close( tc->conn );
}

static void
tc_expect_trailers( tc_t *       tc,
                    uint         stream_id,
                    char const * grpc_status,
                    char const * grpc_message ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  if( FD_UNLIKELY( !s->end_stream ) )
    FD_LOG_ERR(( "stream %u: no trailers (status `%s` grpc-status `%s` hdr_blocks %d data_sz %lu)",
                 stream_id, s->status, s->grpc_status, s->hdr_block_cnt, s->data_sz ));
  FD_TEST( !strcmp( s->status, "200" ) );
  FD_TEST( !strcmp( s->content_type, "application/grpc" ) );
  if( FD_UNLIKELY( strcmp( s->grpc_status, grpc_status ) ) )
    FD_LOG_ERR(( "stream %u: grpc-status %s, expected %s (message `%s`)", stream_id, s->grpc_status, grpc_status, s->grpc_message ));
  if( grpc_message && FD_UNLIKELY( strcmp( s->grpc_message, grpc_message ) ) )
    FD_LOG_ERR(( "stream %u: grpc-message `%s`, expected `%s`", stream_id, s->grpc_message, grpc_message ));
}

static ulong
tc_msg_at( tc_stream_t *  s,
           ulong          off,
           uchar *        flag,
           uchar const ** msg,
           ulong *        msg_sz ) {
  FD_TEST( off+5UL<=s->data_sz );
  *flag   = s->data[ off ];
  *msg_sz = fd_uint_bswap( FD_LOAD( uint, s->data+off+1UL ) );
  FD_TEST( off+5UL+*msg_sz<=s->data_sz );
  *msg    = s->data+off+5UL;
  return off+5UL+*msg_sz;
}

/* tc_one_msg returns the stream's only response message */

static void
tc_one_msg( tc_t *         tc,
            uint           stream_id,
            uchar const ** msg,
            ulong *        msg_sz ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar flag;
  ulong off = tc_msg_at( s, 0UL, &flag, msg, msg_sz );
  FD_TEST( !flag );
  FD_TEST( off==s->data_sz );
}

/* Server construction ************************************************/

static uchar server_mem[ 32UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));
static uchar rpc_mem   [ 16UL<<20 ] __attribute__((aligned(FD_DRAGON_RPC_ALIGN)));
static uchar core_mem  [  4UL<<20 ] __attribute__((aligned(FD_GEYSER_CORE_ALIGN)));

/* The ring the buffered levels are served from: an mcache of
   TEST_BUF_DEPTH entries and a dcache of up to 8 MiB, the test's
   choice of size formatted into it per server. */

#define TEST_BUF_DEPTH (4096UL)

static uchar buf_mcache_mem[ 1UL<<20 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar buf_dcache_mem[ 9UL<<20 ] __attribute__((aligned(FD_DCACHE_ALIGN)));

/* Where the buffered levels' filters run in the servers the tests
   make, FD_DRAGON_FILTER_AT_INGEST unless a test says otherwise. */

static int g_filter_at;

#define ROUTE(m) "/geyser.Geyser/" m

#define TEST_BANK_IDX_MAX (64UL)

static fd_dragon_rpc_t * g_rpc;
static fd_geyser_core_t * g_core;

/* The test stands in for replay: every notification grants a bank
   reference, and a release message takes all of a bank's back. */

static ulong g_refcnt[ TEST_BANK_IDX_MAX ];
static ulong g_seq;

/* The test also stands in for the accounts database, which the core
   is given a reader for.  Nothing the service serves reads through
   it: the buffered levels are served from the buffer, and the tests
   check that the count of reads stays at zero. */

#define TEST_ACCT_MAX (16UL)

struct test_acct {
  int   used;
  uchar pubkey[ 32 ];
  ulong lamports;
  uchar owner[ 32 ];
  int   executable;
  uchar data[ 512 ];
  ulong data_sz;
};

typedef struct test_acct test_acct_t;

static test_acct_t g_acct[ TEST_ACCT_MAX ];
static ulong       g_acct_read_cnt;
static ushort      g_acct_read_fork; /* the fork the last read was made at */

static void
test_acct_reset( void ) {
  fd_memset( g_acct, 0, sizeof(g_acct) );
  g_acct_read_cnt  = 0UL;
  g_acct_read_fork = 0;
}

static uchar g_read_owner[ 32 ];
static uchar g_read_data [ 512 ];

static int
test_read_account( void *                ctx,
                   fd_accdb_fork_id_t    fork_id,
                   uchar const *         pubkey,
                   fd_geyser_account_t * out ) {
  (void)ctx;
  g_acct_read_cnt++;
  g_acct_read_fork = fork_id.val;

  fd_memset( g_read_owner, 0, sizeof(g_read_owner) );
  out->owner = g_read_owner;

  for( ulong i=0UL; i<TEST_ACCT_MAX; i++ ) {
    test_acct_t const * a = g_acct + i;
    if( !a->used || !fd_memeq( a->pubkey, pubkey, 32UL ) ) continue;
    fd_memcpy( g_read_owner, a->owner, 32UL );
    if( a->data_sz ) fd_memcpy( g_read_data, a->data, a->data_sz );
    out->lamports   = a->lamports;
    out->executable = a->executable;
    out->data       = a->data_sz ? g_read_data : NULL;
    out->data_sz    = a->data_sz;
    return 0;
  }
  return 0;
}

static void
test_release( void * ctx,
              ulong  bank_idx,
              ulong  seq_bound ) {
  (void)ctx; (void)seq_bound;
  FD_TEST( bank_idx<TEST_BANK_IDX_MAX );
  g_refcnt[ bank_idx ] = 0UL;
}

/* core_slot publishes one completed slot, with a block hash derived
   from the slot so that a test can predict it. */

static void
core_slot( ulong slot,
           ulong block_height ) {
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = slot-1UL,
    .bank_seq          = slot,
    .parent_bank_seq   = slot>1UL ? slot-1UL : ULONG_MAX,
    .bank_idx          = slot % TEST_BANK_IDX_MAX,
    .accdb_fork_id     = { .val = (ushort)slot },
    .block_height      = block_height,
    .transaction_count = 10UL*slot
  };
  msg.block_hash.ul[ 0 ] = 0x100UL + slot;
  g_refcnt[ msg.bank_idx ]++;
  fd_geyser_core_slot_completed( g_core, &msg, g_seq++ );
}

static void
core_oc( ulong slot ) {
  fd_replay_oc_advanced_t msg = { .slot = slot, .bank_seq = slot, .bank_idx = slot % TEST_BANK_IDX_MAX };
  fd_geyser_core_oc_advanced( g_core, &msg, g_seq++ );
}

static void
core_root( ulong slot ) {
  fd_replay_root_advanced_t msg = { .slot = slot, .bank_seq = slot, .bank_idx = slot % TEST_BANK_IDX_MAX };
  g_refcnt[ msg.bank_idx ]++;
  fd_geyser_core_root_advanced( g_core, &msg, g_seq++ );
}

static void
core_dead( ulong slot ) {
  fd_replay_slot_dead_t msg = { .slot = slot };
  fd_geyser_core_slot_dead( g_core, &msg, g_seq++ );
}

/* block_hash_b58 is the base58 of the block hash core_slot gives a
   slot. */

static void
block_hash_b58( ulong  slot,
                char * out ) {
  fd_hash_t hash = {0};
  hash.ul[ 0 ] = 0x100UL + slot;
  fd_base58_encode_32( hash.uc, NULL, out );
}

/* test_server_opt_t is what the tests vary about the server: the
   shared secret, the size of a client's response queue, whether the
   buffered levels are served and with how large a ring, and whether a
   bank has to account for its records before it seals. */

struct test_server_opt {
  char const * x_token;
  ulong        tx_ring_sz;
  int          no_deferred;
  ulong        buf_bytes;
  int          records_gate;
  ulong        max_stream_cnt; /* 0 for the default of four */
  /* The large send path: max_msg_sz is the largest message the
     transport accepts (0 for the queue size, which leaves no large
     path) and large_slot_cnt how many oversized messages may be in
     flight.  msg_max_bytes is the same bound on the layer's assembly
     buffer. */
  ulong        max_msg_sz;
  ulong        ref_max;
  ulong        msg_max_bytes;
  /* Memory for the transport and the service layer.  A test that
     wants buffers larger than the shared regions brings its own. */
  void *       server_mem;
  ulong        server_mem_sz;
  void *       rpc_mem;
  ulong        rpc_mem_sz;
};

typedef struct test_server_opt test_server_opt_t;

static fd_grpc_server_t *
test_server_new_opt( test_server_opt_t const * opt ) {
  ulong tx_ring_sz = opt->tx_ring_sz ? opt->tx_ring_sz : 262144UL;
  ulong buf_bytes  = opt->buf_bytes  ? opt->buf_bytes  : (1UL<<20);
  FD_TEST( fd_mcache_footprint( TEST_BUF_DEPTH, 0UL )<=sizeof(buf_mcache_mem) );
  FD_TEST( fd_dcache_footprint( buf_bytes, 0UL )<=sizeof(buf_dcache_mem) );
  fd_dragon_rpc_params_t rpc_params = {
    .stream_max            = 8UL,
    .ping_interval_nanos   = 10000000000L,
    .x_token               = opt->x_token,
    .finalized             = !opt->no_deferred,
    .filter_at             = g_filter_at,
    .buf_mcache            = fd_mcache_join( fd_mcache_new( buf_mcache_mem, TEST_BUF_DEPTH, 0UL, 0UL ) ),
    .buf_dcache            = fd_dcache_join( fd_dcache_new( buf_dcache_mem, buf_bytes, 0UL ) ),
    .buf_base              = buf_dcache_mem,
    .buf_depth             = TEST_BUF_DEPTH,
    .bank_max              = 2UL*TEST_BANK_IDX_MAX,
    .msg_max_bytes         = opt->msg_max_bytes,
    .cuckoo_bytes          = 8UL<<10
  };
  FD_TEST( rpc_params.buf_mcache && rpc_params.buf_dcache );
  void * rmem    = opt->rpc_mem ? opt->rpc_mem    : rpc_mem;
  ulong  rmem_sz = opt->rpc_mem ? opt->rpc_mem_sz : sizeof(rpc_mem);
  FD_TEST( fd_dragon_rpc_footprint( &rpc_params )<=rmem_sz );
  g_rpc = fd_dragon_rpc_join( fd_dragon_rpc_new( rmem, &rpc_params ) );
  FD_TEST( g_rpc );

  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = 2UL;
  params->max_stream_cnt     = opt->max_stream_cnt ? opt->max_stream_cnt : 4UL;
  params->max_request_msg_sz = 16384UL;
  params->max_msg_sz         = opt->max_msg_sz ? opt->max_msg_sz : tx_ring_sz;
  params->tx_ring_sz         = fd_ulong_max( tx_ring_sz, 3UL*( params->max_msg_sz+5UL ) );
  params->stream_tx_ref_max  = opt->ref_max ? opt->ref_max : 256UL;
  params->conn_rx_buf_sz     = 32768UL;
  params->conn_tx_buf_sz     = 32768UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<20;
  /* The transport's own timers are tested in test_grpc_server; here
     they would close a connection while the test moves the clock. */
  params->idle_timeout_nanos       = 0L;
  params->compression        = FD_GRPC_SERVER_COMPRESSION_ZSTD;
  params->compression_min_sz = 1024UL;
  params->compression_level  = 1;
  void * smem    = opt->server_mem ? opt->server_mem    : server_mem;
  ulong  smem_sz = opt->server_mem ? opt->server_mem_sz : sizeof(server_mem);
  FD_TEST( fd_grpc_server_footprint( params )<=smem_sz );

  fd_grpc_server_t * server = fd_grpc_server_join( fd_grpc_server_new( smem, params, fd_dragon_rpc_callbacks(), g_rpc ) );
  FD_TEST( server );

  fd_geyser_core_params_t core_params = {
    .max_live_banks = TEST_BANK_IDX_MAX,
    .records_gate   = opt->records_gate,
    .release_fn     = test_release,
    .read_fn        = test_read_account
  };
  FD_TEST( fd_geyser_core_footprint( &core_params )<=sizeof(core_mem) );
  g_core = fd_geyser_core_join( fd_geyser_core_new( core_mem, &core_params ) );
  FD_TEST( g_core );
  fd_geyser_consumer_t consumer[1];
  FD_TEST( !fd_geyser_core_register( g_core, fd_dragon_rpc_consumer( g_rpc, g_core, consumer ) ) );
  fd_memset( g_refcnt, 0, sizeof(g_refcnt) );
  g_seq = 1000UL;
  test_acct_reset();

  return server;
}

static fd_grpc_server_t *
test_server_new( char const * x_token,
                 ulong        tx_ring_sz ) {
  test_server_opt_t opt = { .x_token = x_token, .tx_ring_sz = tx_ring_sz };
  return test_server_new_opt( &opt );
}

static void
test_server_delete( fd_grpc_server_t * server ) {
  fd_grpc_server_delete( fd_grpc_server_leave( server ) );
}

/* Tests **************************************************************/

static void
test_ping( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  req_opt_t opt = { .path = ROUTE( "Ping" ) };
  tc_request( tc, 1U, &opt );
  uchar req[ 16 ];
  ulong req_sz = pb_varint_field( req, 1U, 42UL );
  tc_msg( tc, 1U, req, req_sz, 1 );
  tc_flush( tc );

  tc_expect_trailers( tc, 1U, "0", NULL );

  uchar const * msg; ulong msg_sz;
  tc_one_msg( tc, 1U, &msg, &msg_sz );
  geyser_PongResponse res = geyser_PongResponse_init_zero;
  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_PongResponse_fields, &res ) );
  FD_TEST( res.count==42 );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->request_cnt[ FD_DRAGON_METHOD_PING ]==1UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_get_version( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A request with no message body at all, which is what curl sends */
  req_opt_t opt = { .path = ROUTE( "GetVersion" ), .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  tc_expect_trailers( tc, 1U, "0", NULL );

  uchar const * msg; ulong msg_sz;
  tc_one_msg( tc, 1U, &msg, &msg_sz );
  geyser_GetVersionResponse res = geyser_GetVersionResponse_init_zero;
  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_GetVersionResponse_fields, &res ) );

  char const * json = res.version;
  FD_LOG_NOTICE(( "GetVersion: %s", json ));
  FD_TEST( !strcmp( json, fd_dragon_rpc_version_json( g_rpc ) ) );

  /* The two level yellowstone shape, key by key and in order */
  char const * p = json;
  FD_TEST( !strncmp( p, "{\"version\":{\"package\":\"firedancer-dragon\",\"version\":\"", 52UL ) );
  p = strstr( p, "\",\"proto\":\"" FD_DRAGON_PROTO_VERSION "\",\"solana\":\"" ); FD_TEST( p );
  p = strstr( p, "\",\"git\":\"" );                                             FD_TEST( p );
  p = strstr( p, "\",\"rustc\":\"" );                                           FD_TEST( p );
  p = strstr( p, "\",\"buildts\":\"\"},\"extra\":{\"hostname\":\"" );           FD_TEST( p );
  p = strstr( p, "\"}}" );                                                      FD_TEST( p );
  FD_TEST( p[3]=='\0' );

  tc_close( tc );
  test_server_delete( server );
}

/* Health service *****************************************************/

#define HEALTH_CHECK "/grpc.health.v1.Health/Check"
#define HEALTH_WATCH "/grpc.health.v1.Health/Watch"

/* health_request sends one HealthCheckRequest naming service, or no
   message at all when service is NULL, which is how a client asks
   about the whole server without sending a body. */

static void
health_request( tc_t *       tc,
                uint         stream_id,
                char const * path,
                char const * service,
                int          end_stream ) {
  req_opt_t opt = { .path = path, .end_stream = !service && end_stream };
  tc_request( tc, stream_id, &opt );
  if( !service ) { tc_flush( tc ); return; }
  uchar req[ 512 ];
  ulong name_len = strlen( service );
  FD_TEST( name_len+8UL<=sizeof(req) );
  ulong req_sz = name_len ? pb_bytes_field( req, 1U, service, name_len ) : 0UL;
  tc_msg( tc, stream_id, req, req_sz, end_stream );
  tc_flush( tc );
}

static int
health_status_at( tc_t * tc,
                  uint   stream_id,
                  ulong  off,
                  ulong * next ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  *next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );
  grpc_health_v1_HealthCheckResponse res = grpc_health_v1_HealthCheckResponse_init_zero;
  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, grpc_health_v1_HealthCheckResponse_fields, &res ) );
  return (int)res.status;
}

static void
test_health_check( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* Before the owner serves, every name it knows is NOT_SERVING. */
  health_request( tc, 1U, HEALTH_CHECK, "geyser.Geyser", 1 );
  tc_expect_trailers( tc, 1U, "0", NULL );
  ulong next;
  FD_TEST( health_status_at( tc, 1U, 0UL, &next )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_NOT_SERVING );

  fd_dragon_rpc_set_serving( g_rpc, 1 );

  /* The service the tile serves, and the empty name that stands for
     the whole server, both of them SERVING now. */
  health_request( tc, 3U, HEALTH_CHECK, "geyser.Geyser", 1 );
  tc_expect_trailers( tc, 3U, "0", NULL );
  FD_TEST( health_status_at( tc, 3U, 0UL, &next )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING );

  health_request( tc, 5U, HEALTH_CHECK, "", 1 );
  tc_expect_trailers( tc, 5U, "0", NULL );
  FD_TEST( health_status_at( tc, 5U, 0UL, &next )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING );

  /* A request with no body at all is the empty name, which is what
     curl sends. */
  health_request( tc, 7U, HEALTH_CHECK, NULL, 1 );
  tc_expect_trailers( tc, 7U, "0", NULL );
  FD_TEST( health_status_at( tc, 7U, 0UL, &next )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING );

  /* Any other name is not found, with tonic-health's own text. */
  health_request( tc, 9U, HEALTH_CHECK, "some.Other", 1 );
  tc_expect_trailers( tc, 9U, "5", "service not registered" );

  /* A name longer than any the tile serves is not found either, not a
     decode failure. */
  char long_name[ 300 ];
  fd_memset( long_name, 'x', sizeof(long_name)-1UL );
  long_name[ sizeof(long_name)-1UL ] = '\0';
  health_request( tc, 11U, HEALTH_CHECK, long_name, 1 );
  tc_expect_trailers( tc, 11U, "5", "service not registered" );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->request_cnt[ FD_DRAGON_METHOD_HEALTH_CHECK ]==6UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_health_watch( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A watch opened before the owner serves gets NOT_SERVING at once
     and stays open. */
  health_request( tc, 1U, HEALTH_WATCH, "geyser.Geyser", 0 );
  ulong off = 0UL;
  FD_TEST( health_status_at( tc, 1U, off, &off )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_NOT_SERVING );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  /* The startup gate opening is one message. */
  fd_dragon_rpc_set_serving( g_rpc, 1 );
  tc_flush( tc );
  FD_TEST( health_status_at( tc, 1U, off, &off )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* Setting the same status again is not a change. */
  fd_dragon_rpc_set_serving( g_rpc, 1 );
  tc_flush( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* A watch opened while the owner serves starts at SERVING. */
  health_request( tc, 3U, HEALTH_WATCH, "", 0 );
  ulong off3 = 0UL;
  FD_TEST( health_status_at( tc, 3U, off3, &off3 )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_SERVING );
  FD_TEST( !tc_stream( tc, 3U )->end_stream );

  /* Shutting down reaches both of them. */
  fd_dragon_rpc_set_serving( g_rpc, 0 );
  tc_flush( tc );
  FD_TEST( health_status_at( tc, 1U, off, &off )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_NOT_SERVING );
  FD_TEST( health_status_at( tc, 3U, off3, &off3 )==
           grpc_health_v1_HealthCheckResponse_ServingStatus_NOT_SERVING );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );
  FD_TEST( !tc_stream( tc, 3U )->end_stream );

  /* An unknown service ends the watch, as tonic-health ends it. */
  health_request( tc, 5U, HEALTH_WATCH, "some.Other", 0 );
  tc_expect_trailers( tc, 5U, "5", "service not registered" );
  FD_TEST( tc_stream( tc, 5U )->data_sz==0UL );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->request_cnt[ FD_DRAGON_METHOD_HEALTH_WATCH ]==3UL );

  tc_close( tc );
  test_server_delete( server );
}

/* subscribe_update is defined with the subscription tests below. */

static ulong
subscribe_update( tc_t *                   tc,
                  uint                     stream_id,
                  ulong                    off,
                  geyser_SubscribeUpdate * update );

/* unary_commitment sends one unary call with an optional
   commitment. */

static void
unary_commitment( tc_t *         tc,
                  uint           stream_id,
                  char const *   path,
                  int            has_commitment,
                  ulong          commitment ) {
  req_opt_t opt = { .path = path };
  tc_request( tc, stream_id, &opt );
  uchar req[ 16 ];
  ulong req_sz = has_commitment ? pb_varint_field( req, 1U, commitment ) : 0UL;
  tc_msg( tc, stream_id, req, req_sz, 1 );
  tc_flush( tc );
}

static void
test_unary_slots( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* Nothing replayed yet */
  req_opt_t opt = { .path = ROUTE( "GetSlot" ), .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "13", "block is not available yet" );
  FD_TEST( tc_stream( tc, 1U )->data_sz==0UL );
  FD_TEST( !fd_dragon_rpc_is_ready( g_rpc ) );

  /* A chain of slots with the root 32 behind, which is the shape of a
     validator running tower.  The server is not ready on the
     processed statuses alone: it takes a root. */
  for( ulong slot=1UL; slot<=32UL; slot++ ) core_slot( slot, 1000UL+slot );
  FD_TEST( !fd_dragon_rpc_is_ready( g_rpc ) );

  for( ulong slot=33UL; slot<=100UL; slot++ ) {
    core_slot( slot, 1000UL+slot );
    core_oc  ( slot-32UL );
    core_root( slot-32UL );
  }
  FD_TEST( fd_dragon_rpc_is_ready( g_rpc ) );

  uchar const * msg; ulong msg_sz;
  pb_istream_t is;

  /* GetSlot per level: processed is the latest slot, confirmed and
     finalized are the last rooted one. */
  ulong const level_slot[ 3 ] = { 100UL, 68UL, 68UL };
  for( ulong level=0UL; level<3UL; level++ ) {
    uint sid = (uint)( 3UL + 2UL*level );
    unary_commitment( tc, sid, ROUTE( "GetSlot" ), 1, level );
    tc_expect_trailers( tc, sid, "0", NULL );
    tc_one_msg( tc, sid, &msg, &msg_sz );
    geyser_GetSlotResponse res = geyser_GetSlotResponse_init_zero;
    is = pb_istream_from_buffer( msg, msg_sz );
    FD_TEST( pb_decode( &is, geyser_GetSlotResponse_fields, &res ) );
    if( FD_UNLIKELY( res.slot!=level_slot[ level ] ) )
      FD_LOG_ERR(( "GetSlot at level %lu returned %lu, expected %lu", level, res.slot, level_slot[ level ] ));
  }

  /* An absent commitment means processed */
  tc_request( tc, 9U, &opt );
  tc_flush( tc );
  tc_expect_trailers( tc, 9U, "0", NULL );
  tc_one_msg( tc, 9U, &msg, &msg_sz );
  geyser_GetSlotResponse slot_res = geyser_GetSlotResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_GetSlotResponse_fields, &slot_res ) );
  FD_TEST( slot_res.slot==100UL );

  /* GetBlockHeight per level */
  for( ulong level=0UL; level<3UL; level++ ) {
    uint sid = (uint)( 11UL + 2UL*level );
    unary_commitment( tc, sid, ROUTE( "GetBlockHeight" ), 1, level );
    tc_expect_trailers( tc, sid, "0", NULL );
    tc_one_msg( tc, sid, &msg, &msg_sz );
    geyser_GetBlockHeightResponse res = geyser_GetBlockHeightResponse_init_zero;
    is = pb_istream_from_buffer( msg, msg_sz );
    FD_TEST( pb_decode( &is, geyser_GetBlockHeightResponse_fields, &res ) );
    FD_TEST( res.block_height==1000UL+level_slot[ level ] );
  }

  /* GetLatestBlockhash: the block hash of the level's slot, valid for
     another MAX_RECENT_BLOCKHASHES blocks */
  for( ulong level=0UL; level<3UL; level++ ) {
    uint sid = (uint)( 17UL + 2UL*level );
    unary_commitment( tc, sid, ROUTE( "GetLatestBlockhash" ), 1, level );
    tc_expect_trailers( tc, sid, "0", NULL );
    tc_one_msg( tc, sid, &msg, &msg_sz );
    geyser_GetLatestBlockhashResponse res = geyser_GetLatestBlockhashResponse_init_zero;
    is = pb_istream_from_buffer( msg, msg_sz );
    FD_TEST( pb_decode( &is, geyser_GetLatestBlockhashResponse_fields, &res ) );
    FD_TEST( res.slot==level_slot[ level ] );
    FD_TEST( res.last_valid_block_height==1000UL+level_slot[ level ]+300UL );
    char expected[ FD_BASE58_ENCODED_32_SZ ];
    block_hash_b58( level_slot[ level ], expected );
    FD_TEST( !strcmp( res.blockhash, expected ) );
  }

  /* An unknown commitment level */
  unary_commitment( tc, 23U, ROUTE( "GetSlot" ), 1, 7UL );
  tc_expect_trailers( tc, 23U, "2", "failed to create CommitmentLevel from 7" );

  tc_close( tc );
  test_server_delete( server );
}

/* is_blockhash_valid_req asks IsBlockhashValid about one base58 hash
   at one commitment. */

static void
is_blockhash_valid_req( tc_t *       tc,
                        uint         stream_id,
                        char const * hash_b58,
                        ulong        commitment ) {
  req_opt_t opt = { .path = ROUTE( "IsBlockhashValid" ) };
  tc_request( tc, stream_id, &opt );
  uchar req[ 128 ];
  ulong req_sz = pb_bytes_field( req, 1U, hash_b58, strlen( hash_b58 ) );
  req_sz += pb_varint_field( req+req_sz, 2U, commitment );
  tc_msg( tc, stream_id, req, req_sz, 1 );
  tc_flush( tc );
}

static void
test_is_blockhash_valid( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  char hash[ FD_BASE58_ENCODED_32_SZ ];
  block_hash_b58( 100UL, hash );

  /* A server that has not seen a whole blockhash window answers
     startup, whatever it knows about the hash */
  for( ulong slot=1UL; slot<=100UL; slot++ ) {
    core_slot( slot, 1000UL+slot );
    if( slot>32UL ) { core_oc( slot-32UL ); core_root( slot-32UL ); }
  }
  is_blockhash_valid_req( tc, 1U, hash, 0UL );
  tc_expect_trailers( tc, 1U, "13", "startup" );

  /* 332 finalized blockhashes later it answers */
  for( ulong slot=101UL; slot<=400UL; slot++ ) {
    core_slot( slot, 1000UL+slot );
    core_oc  ( slot-32UL );
    core_root( slot-32UL );
    fd_geyser_core_housekeeping( g_core );
  }
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->blockhash_cnt>=332UL );

  /* Block metas are kept for the three slots below the finalized one
     and for the slots above it that have not been rooted yet, which is
     the 32 slot rooting delay of this run, not for all 400. */
  ulong meta_cnt = fd_dragon_rpc_metrics( g_rpc )->block_meta_tracked;
  if( FD_UNLIKELY( meta_cnt<4UL || meta_cnt>40UL ) )
    FD_LOG_ERR(( "%lu block metas retained, expected the rooting delay plus a few", meta_cnt ));

  uchar const * msg; ulong msg_sz;
  pb_istream_t is;

  /* A finalized slot's hash has reached every level */
  char final_hash[ FD_BASE58_ENCODED_32_SZ ];
  block_hash_b58( 368UL, final_hash );
  for( ulong level=0UL; level<3UL; level++ ) {
    uint sid = (uint)( 3UL + 2UL*level );
    is_blockhash_valid_req( tc, sid, final_hash, level );
    tc_expect_trailers( tc, sid, "0", NULL );
    tc_one_msg( tc, sid, &msg, &msg_sz );
    geyser_IsBlockhashValidResponse res = geyser_IsBlockhashValidResponse_init_zero;
    is = pb_istream_from_buffer( msg, msg_sz );
    FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
    FD_TEST( res.valid );
    FD_TEST( res.slot==( level==0UL ? 400UL : 368UL ) );
  }

  /* A slot that is only processed has not reached the deferred levels */
  char processed_hash[ FD_BASE58_ENCODED_32_SZ ];
  block_hash_b58( 400UL, processed_hash );
  is_blockhash_valid_req( tc, 9U, processed_hash, 0UL );
  tc_expect_trailers( tc, 9U, "0", NULL );
  tc_one_msg( tc, 9U, &msg, &msg_sz );
  geyser_IsBlockhashValidResponse res = geyser_IsBlockhashValidResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
  FD_TEST( res.valid );

  is_blockhash_valid_req( tc, 11U, processed_hash, 2UL );
  tc_expect_trailers( tc, 11U, "0", NULL );
  tc_one_msg( tc, 11U, &msg, &msg_sz );
  res = (geyser_IsBlockhashValidResponse)geyser_IsBlockhashValidResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
  FD_TEST( !res.valid );

  /* A blockhash that fell out of the window, and one that never
     existed, are both unknown */
  char old_hash[ FD_BASE58_ENCODED_32_SZ ];
  block_hash_b58( 2UL, old_hash );
  is_blockhash_valid_req( tc, 13U, old_hash, 2UL );
  tc_expect_trailers( tc, 13U, "0", NULL );
  tc_one_msg( tc, 13U, &msg, &msg_sz );
  res = (geyser_IsBlockhashValidResponse)geyser_IsBlockhashValidResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
  FD_TEST( !res.valid );

  is_blockhash_valid_req( tc, 15U, "11111111111111111111111111111111", 2UL );
  tc_expect_trailers( tc, 15U, "0", NULL );
  tc_one_msg( tc, 15U, &msg, &msg_sz );
  res = (geyser_IsBlockhashValidResponse)geyser_IsBlockhashValidResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
  FD_TEST( !res.valid );

  /* A base58 string that decodes to nothing is not an error */
  is_blockhash_valid_req( tc, 17U, "not base 58!", 2UL );
  tc_expect_trailers( tc, 17U, "0", NULL );
  tc_one_msg( tc, 17U, &msg, &msg_sz );
  res = (geyser_IsBlockhashValidResponse)geyser_IsBlockhashValidResponse_init_zero;
  is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_IsBlockhashValidResponse_fields, &res ) );
  FD_TEST( !res.valid );

  /* GetSlot of a slot whose meta fell out of the store is answered as
     unavailable, like yellowstone's */
  tc_close( tc );
  test_server_delete( server );
}

/* Slot subscriptions *************************************************/

/* sub_filter_slots writes a slots filter map entry with the two
   flags. */

static ulong
sub_filter_slots( uchar *      p,
                  char const * name,
                  int          filter_by_commitment,
                  int          interslot_updates ) {
  uchar value[ 16 ];
  ulong value_sz = 0UL;
  if( filter_by_commitment ) value_sz += pb_varint_field( value+value_sz, 1U, 1UL );
  if( interslot_updates    ) value_sz += pb_varint_field( value+value_sz, 2U, 1UL );

  uchar entry[ 256 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, name, strlen( name ) );
  if( value_sz ) entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );

  return pb_bytes_field( p, 2U /* slots */, entry, entry_sz );
}

/* next_slot_update decodes the next SubscribeUpdate of a subscription
   and checks it is the expected slot status with the expected filter
   name. */

struct slot_filters {
  ulong cnt;
  char  name[ 4 ][ FD_DRAGON_FILTER_NAME_MAX+1UL ];
};

typedef struct slot_filters slot_filters_t;

static bool
decode_filter_name( pb_istream_t *     stream,
                    pb_field_t const * field,
                    void **            arg ) {
  (void)field;
  slot_filters_t * out = *arg;
  FD_TEST( out->cnt<4UL );
  ulong len = (ulong)stream->bytes_left;
  FD_TEST( len<=FD_DRAGON_FILTER_NAME_MAX );
  FD_TEST( pb_read( stream, (pb_byte_t *)out->name[ out->cnt ], (size_t)len ) );
  out->name[ out->cnt ][ len ] = '\0';
  out->cnt++;
  return true;
}

static ulong
expect_slot_update( tc_t *       tc,
                    uint         stream_id,
                    ulong        off,
                    ulong        slot,
                    int          status,
                    long         bank_id,
                    char const * filter_name ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  if( FD_UNLIKELY( off>=s->data_sz ) ) FD_LOG_ERR(( "no update at offset %lu of %lu", off, s->data_sz ));
  ulong next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );

  slot_filters_t         filters[1] = {{0}};
  geyser_SubscribeUpdate update    = geyser_SubscribeUpdate_init_zero;
  update.filters.funcs.decode = decode_filter_name;
  update.filters.arg          = filters;
  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_SubscribeUpdate_fields, &update ) );
  FD_TEST( update.has_created_at );

  if( FD_UNLIKELY( update.which_update_oneof!=geyser_SubscribeUpdate_slot_tag ) )
    FD_LOG_ERR(( "update at %lu is oneof %u, expected a slot status", off, update.which_update_oneof ));
  geyser_SubscribeUpdateSlot const * u = &update.update_oneof.slot;
  if( FD_UNLIKELY( u->slot!=slot || (int)u->status!=status ) )
    FD_LOG_ERR(( "update at %lu is slot %lu status %d, expected slot %lu status %d",
                 off, u->slot, (int)u->status, slot, status ));
  if( bank_id<0 ) FD_TEST( !u->has_bank_id );
  else            FD_TEST( u->has_bank_id && u->bank_id==(ulong)bank_id );
  FD_TEST( filters->cnt==1UL );
  FD_TEST( !strcmp( filters->name[ 0 ], filter_name ) );
  return next;
}

static void
test_subscribe_slots( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* Three subscriptions: one plain at processed, one with
     interslot_updates, one with filter_by_commitment at confirmed. */
  static uchar req[ 1024 ];

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  ulong req_sz = sub_filter_slots( req, "plain", 0, 0 );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );

  tc_request( tc, 3U, &opt );
  req_sz = sub_filter_slots( req, "all", 0, 1 );
  tc_msg( tc, 3U, req, req_sz, 0 );
  tc_flush( tc );

  tc_request( tc, 5U, &opt );
  req_sz  = sub_filter_slots( req, "conf", 1, 1 );
  req_sz += pb_varint_field( req+req_sz, 6U /* commitment */, 1UL /* CONFIRMED */ );
  tc_msg( tc, 5U, req, req_sz, 0 );
  tc_flush( tc );

  /* Each stream opened with a server ping, which is the first message
     on it. */
  ulong off1 = 0UL, off3 = 0UL, off5 = 0UL;
  geyser_SubscribeUpdate ping;
  off1 = subscribe_update( tc, 1U, off1, &ping );
  FD_TEST( ping.which_update_oneof==geyser_SubscribeUpdate_ping_tag );
  off3 = subscribe_update( tc, 3U, off3, &ping );
  off5 = subscribe_update( tc, 5U, off5, &ping );

  /* One slot, then its confirmation and its rooting. */
  core_slot( 10UL, 500UL );
  core_slot( 11UL, 501UL );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );

  /* Without interslot_updates a plain subscription sees only the three
     commitment statuses. */
  off1 = expect_slot_update( tc, 1U, off1, 10UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 10L, "plain" );
  off1 = expect_slot_update( tc, 1U, off1, 11UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 11L, "plain" );
  off1 = expect_slot_update( tc, 1U, off1, 10UL, (int)geyser_SlotStatus_SLOT_CONFIRMED, 10L, "plain" );
  off1 = expect_slot_update( tc, 1U, off1, 10UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 10L, "plain" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* With it, the lifecycle status comes too, before the processed one
     of the same bank. */
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_CREATED_BANK, 10L, "all" );
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_PROCESSED,    10L, "all" );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_CREATED_BANK, 11L, "all" );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_PROCESSED,    11L, "all" );
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_CONFIRMED,    10L, "all" );
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_FINALIZED,    10L, "all" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  /* filter_by_commitment keeps only the subscription's own level, and
     drops the lifecycle statuses with it. */
  off5 = expect_slot_update( tc, 5U, off5, 10UL, (int)geyser_SlotStatus_SLOT_CONFIRMED, 10L, "conf" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  /* A dead slot is a lifecycle status and belongs to no bank. */
  core_dead( 11UL );
  tc_service( tc );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_DEAD, -1L, "all" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  /* Four statuses on the plain subscription, seven on the one that
     takes the lifecycle statuses too, one on the one filtered by
     commitment. */
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->slot_update_cnt==12UL );

  /* A subscription with no slots filter gets nothing. */
  tc_request( tc, 7U, &opt );
  req_sz = pb_map_entry( req, 1U /* accounts */, "acct", 4UL );
  tc_msg( tc, 7U, req, req_sz, 0 );
  tc_flush( tc );
  ulong off7 = 0UL;
  off7 = subscribe_update( tc, 7U, off7, &ping );
  core_slot( 12UL, 502UL );
  tc_service( tc );
  FD_TEST( off7==tc_stream( tc, 7U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A request replaces the filter set, so a subscription can stop and
   start seeing statuses. */

static void
test_subscribe_slots_replace( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 1024 ];
  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  ulong req_sz = sub_filter_slots( req, "first", 0, 1 );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );

  ulong off = 0UL;
  geyser_SubscribeUpdate ping;
  off = subscribe_update( tc, 1U, off, &ping );

  core_slot( 10UL, 500UL );
  tc_service( tc );
  off = expect_slot_update( tc, 1U, off, 10UL, (int)geyser_SlotStatus_SLOT_CREATED_BANK, 10L, "first" );
  off = expect_slot_update( tc, 1U, off, 10UL, (int)geyser_SlotStatus_SLOT_PROCESSED,    10L, "first" );

  /* A new request with a different name replaces the old filter. */
  req_sz = sub_filter_slots( req, "second", 0, 0 );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );
  core_slot( 11UL, 501UL );
  tc_service( tc );
  off = expect_slot_update( tc, 1U, off, 11UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 11L, "second" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* An empty request leaves no filters at all. */
  tc_msg( tc, 1U, req, 0UL, 0 );
  tc_flush( tc );
  core_slot( 12UL, 502UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_replay_info( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  req_opt_t opt = { .path = ROUTE( "SubscribeReplayInfo" ), .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "0", NULL );

  /* first_available unset, so the response message is empty */
  uchar const * msg; ulong msg_sz;
  tc_one_msg( tc, 1U, &msg, &msg_sz );
  FD_TEST( msg_sz==0UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_unimplemented( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  req_opt_t deshred = { .path = ROUTE( "SubscribeDeshred" ), .end_stream = 1 };
  tc_request( tc, 1U, &deshred );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "12", "method disabled" );
  FD_TEST( tc_stream( tc, 1U )->hdr_block_cnt==1 ); /* Trailers-Only */

  req_opt_t gossip = { .path = ROUTE( "SubscribeGossip" ), .end_stream = 1 };
  tc_request( tc, 3U, &gossip );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "12", "method disabled" );

  req_opt_t unknown = { .path = ROUTE( "Nonsense" ), .end_stream = 1 };
  tc_request( tc, 5U, &unknown );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "12", "unknown method" );

  req_opt_t other = { .path = "/other.Service/Method", .end_stream = 1 };
  tc_request( tc, 7U, &other );
  tc_flush( tc );
  tc_expect_trailers( tc, 7U, "12", "unknown method" );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->unimplemented_cnt==4UL );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->request_cnt[ FD_DRAGON_METHOD_UNKNOWN ]==2UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_auth( void ) {
  fd_grpc_server_t * server = test_server_new( "s3cret", 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* No token */
  req_opt_t opt = { .path = ROUTE( "GetVersion" ), .end_stream = 1 };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "16", "No valid auth token" );
  FD_TEST( tc_stream( tc, 1U )->hdr_block_cnt==1 );
  FD_TEST( tc_stream( tc, 1U )->data_sz==0UL );

  /* Wrong token */
  req_opt_t bad = { .path = ROUTE( "GetVersion" ), .x_token = "s3cre", .end_stream = 1 };
  tc_request( tc, 3U, &bad );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "16", "No valid auth token" );

  req_opt_t bad2 = { .path = ROUTE( "GetVersion" ), .x_token = "S3cret", .end_stream = 1 };
  tc_request( tc, 5U, &bad2 );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "16", "No valid auth token" );

  /* Right token */
  req_opt_t good = { .path = ROUTE( "GetVersion" ), .x_token = "s3cret", .end_stream = 1 };
  tc_request( tc, 7U, &good );
  tc_flush( tc );
  tc_expect_trailers( tc, 7U, "0", NULL );
  FD_TEST( tc_stream( tc, 7U )->data_sz>0UL );

  /* An unknown path with a wrong token fails authentication first */
  req_opt_t unknown = { .path = ROUTE( "Nonsense" ), .end_stream = 1 };
  tc_request( tc, 9U, &unknown );
  tc_flush( tc );
  tc_expect_trailers( tc, 9U, "16", "No valid auth token" );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->auth_fail_cnt==4UL );

  tc_close( tc );
  test_server_delete( server );
}

/* subscribe_update decodes one SubscribeUpdate from a subscription
   stream at off, and returns the offset of the next one. */

static ulong
subscribe_update( tc_t *                   tc,
                  uint                     stream_id,
                  ulong                    off,
                  geyser_SubscribeUpdate * update ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  ulong next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );
  *update = (geyser_SubscribeUpdate)geyser_SubscribeUpdate_init_zero;
  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_SubscribeUpdate_fields, update ) );
  FD_TEST( update->has_created_at );
  FD_TEST( update->created_at.seconds==tc->now/1000000000L );
  return next;
}

static void
test_subscribe_ping( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  /* The server pings a new subscription immediately */
  geyser_SubscribeUpdate update;
  ulong off = subscribe_update( tc, 1U, 0UL, &update );
  FD_TEST( update.which_update_oneof==geyser_SubscribeUpdate_ping_tag );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  /* A ping in a request is answered with a pong carrying the same id */
  uchar req[ 32 ];
  uchar ping[ 8 ];
  ulong ping_sz = pb_varint_field( ping, 1U, 7UL );
  ulong req_sz  = pb_bytes_field( req, 9U, ping, ping_sz );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );

  off = subscribe_update( tc, 1U, off, &update );
  FD_TEST( update.which_update_oneof==geyser_SubscribeUpdate_pong_tag );
  FD_TEST( update.update_oneof.pong.id==7 );

  /* No further ping before the interval elapses */
  tc->now += 9000000000L;
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  tc->now += 2000000000L;
  tc_service( tc );
  off = subscribe_update( tc, 1U, off, &update );
  FD_TEST( update.which_update_oneof==geyser_SubscribeUpdate_ping_tag );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->server_ping_cnt==2UL );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->pong_cnt==1UL );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->subscription_cnt==1UL );

  tc_close( tc );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->subscription_cnt==0UL );
  test_server_delete( server );
}

static void
test_subscribe_from_slot( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  core_slot( 900UL, 800UL );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  uchar req[ 32 ];
  ulong req_sz = pb_varint_field( req, 11U, 850UL );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );

  tc_expect_trailers( tc, 1U, "11", "broadcast from 850 is not available, last available: 900" );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->from_slot_reject_cnt==1UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_subscribe_filters( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A filter name of the maximum size is accepted */
  static uchar req[ 8192 ];
  char name[ 256 ];
  fd_memset( name, 'a', sizeof(name) );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  ulong req_sz = pb_map_entry( req, 1U, name, FD_DRAGON_FILTER_NAME_MAX );
  tc_msg( tc, 1U, req, req_sz, 0 );
  tc_flush( tc );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  /* One byte more is not */
  tc_request( tc, 3U, &opt );
  req_sz = pb_map_entry( req, 1U, name, FD_DRAGON_FILTER_NAME_MAX+1UL );
  tc_msg( tc, 3U, req, req_sz, 0 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "3", "failed to create filter: oversized filter name (max allowed size 128), found 129" );

  /* More filters than the server keeps */
  tc_request( tc, 5U, &opt );
  req_sz = 0UL;
  for( ulong i=0UL; i<FD_DRAGON_FILTER_MAX+1UL; i++ ) {
    char one[ 32 ];
    FD_TEST( fd_cstr_printf_check( one, sizeof(one), NULL, "f%lu", i ) );
    req_sz += pb_map_entry( req+req_sz, 2U, one, strlen( one ) );
  }
  tc_msg( tc, 5U, req, req_sz, 0 );
  tc_flush( tc );
  tc_expect_trailers( tc, 5U, "3", "failed to create filter: Max amount of filters/data_slices reached, only 64 allowed" );

  /* Data slices must be ordered and must not overlap */
  uchar slice[ 32 ];
  ulong slice_sz;

  tc_request( tc, 7U, &opt );
  req_sz   = 0UL;
  slice_sz = pb_varint_field( slice, 1U, 100UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 10UL );
  req_sz  += pb_bytes_field( req+req_sz, 7U, slice, slice_sz );
  slice_sz = pb_varint_field( slice, 1U, 50UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 10UL );
  req_sz  += pb_bytes_field( req+req_sz, 7U, slice, slice_sz );
  tc_msg( tc, 7U, req, req_sz, 0 );
  tc_flush( tc );
  tc_expect_trailers( tc, 7U, "3", "failed to create filter: failed to create filter: data slices out of order" );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->filter_reject_cnt==3UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_subscribe_lagged( void ) {
  /* The smallest segment queue the transport allows, so that a
     handful of pings overruns it while the client's window is shut */
  test_server_opt_t sopt = { .ref_max = 2UL };
  fd_grpc_server_t * server = test_server_new_opt( &sopt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  /* An empty request subscribes to nothing, so pings are the only
     traffic the call ever carries. */
  tc_msg( tc, 1U, NULL, 0UL, 0 );
  tc_flush( tc );

  /* Each tick is one server ping; the one that does not fit ends the
     call.  The loop stops on that tick, so the reap deadline is a full
     interval away. */
  for( ulong i=0UL; i<8UL && !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt; i++ ) {
    tc->now += 10000000000L;
    tc_service( tc );
  }

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt==1UL );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );

  /* Dropping what the client never took lets the status go out at
     once, since trailers are not flow controlled, and the connection
     is never reaped */
  tc_window_update( tc, 1U, 1UL<<20 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "13", "grpc: client is too slow" );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->subscription_cnt==0UL );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );

  tc->now += 60000000000L;
  tc_service( tc );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->lagged_reap_cnt==0UL );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );

  tc_close( tc );
  test_server_delete( server );
}

/* A subscriber the transport dropped is told at once, so dragon's reap
   never has to run.  The reap stays as the backstop for a session
   dragon itself finished whose trailers cannot leave the connection
   because its send ring is full. */

static void
test_subscribe_lagged_no_reap( void ) {
  test_server_opt_t sopt = { .ref_max = 2UL };
  fd_grpc_server_t * server = test_server_new_opt( &sopt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  tc_settings( tc, FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0U );
  tc_flush( tc );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  tc_msg( tc, 1U, NULL, 0UL, 0 );
  tc_flush( tc );

  for( ulong i=0UL; i<8UL && !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt; i++ ) {
    tc->now += 10000000000L;
    tc_service( tc );
  }
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt==1UL );

  /* The window is still shut, and the status arrived anyway */
  tc_expect_trailers( tc, 1U, "13", "grpc: client is too slow" );

  tc->now += 60000000000L;
  tc_service( tc );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->lagged_reap_cnt==0UL );
  FD_TEST( fd_grpc_server_conn_is_open( tc->conn ) );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->subscription_cnt==0UL );

  tc_close( tc );
  test_server_delete( server );
}

static void
test_shutdown( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &opt );
  tc_flush( tc );

  fd_grpc_server_shutdown( server );
  tc_service( tc );
  tc_expect_trailers( tc, 1U, "14", "server is shutting down" );

  tc_close( tc );
  test_server_delete( server );
}

/* Filter decoding, without a transport ********************************/

/* The limits and the cuckoo arena the decoder is exercised with: the
   most permissive limits, and room for a filter of 1024 buckets. */

#define G_CUCKOO_ENTRY_MAX (4096UL)

static fd_dragon_filter_limits_t const * g_limits = NULL;
static ushort                            g_cuckoo[ G_CUCKOO_ENTRY_MAX ];

static void
test_filter_decode( void ) {
  static uchar buf[ 1UL<<20 ];
  fd_dragon_filter_set_t set[1];
  char  err[ FD_DRAGON_ERR_MAX ];
  ulong names_seen;

  /* Every map is counted, and every name is kept with its type */
  ulong sz = 0UL;
  sz += pb_map_entry( buf+sz, 1U,  "acct",  4UL );
  sz += pb_map_entry( buf+sz, 2U,  "slot",  4UL );
  sz += pb_map_entry( buf+sz, 3U,  "txn",   3UL );
  sz += pb_map_entry( buf+sz, 10U, "txns",  4UL );
  sz += pb_map_entry( buf+sz, 4U,  "blk",   3UL );
  sz += pb_map_entry( buf+sz, 5U,  "blkm",  4UL );
  sz += pb_map_entry( buf+sz, 8U,  "entry", 5UL );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==7UL );
  FD_TEST( names_seen==7UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_ACCOUNTS            ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_SLOTS               ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS        ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_TRANSACTIONS_STATUS ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_BLOCKS              ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_BLOCKS_META         ]==1UL );
  FD_TEST( set->type_cnt[ FD_DRAGON_FILTER_ENTRY               ]==1UL );
  FD_TEST( set->commitment==FD_DRAGON_COMMITMENT_PROCESSED );
  FD_TEST( !strcmp( set->name[ 0 ].cstr, "acct" ) );
  FD_TEST( set->name[ 0 ].type==FD_DRAGON_FILTER_ACCOUNTS );

  /* A request with thousands of entries stops at the limit, and the
     set it leaves behind is empty */
  sz = 0UL;
  for( ulong i=0UL; i<4000UL; i++ ) {
    char one[ 32 ];
    FD_TEST( fd_cstr_printf_check( one, sizeof(one), NULL, "filter-%lu", i ) );
    sz += pb_map_entry( buf+sz, 1U, one, strlen( one ) );
  }
  names_seen = 0UL;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "Max amount of filters/data_slices reached, only 64 allowed" ) );
  FD_TEST( set->name_cnt==0UL );

  /* A name over the limit, reported with its size */
  char name[ 512 ];
  fd_memset( name, 'x', sizeof(name) );
  sz = pb_map_entry( buf, 3U, name, 400UL );
  names_seen = 0UL;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "oversized filter name (max allowed size 128), found 400" ) );
  FD_TEST( names_seen==0UL );

  /* Names accumulate over a stream's lifetime */
  sz = pb_map_entry( buf, 1U, "a", 1UL );
  names_seen = FD_DRAGON_FILTER_NAMES_MAX;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "Max amount of filters/data_slices reached, only 4096 allowed" ) );

  /* Commitment, ping and from_slot */
  sz  = pb_varint_field( buf, 6U, 2UL );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->commitment==FD_DRAGON_COMMITMENT_FINALIZED );

  sz = pb_varint_field( buf, 6U, 9UL );
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "failed to create CommitmentLevel from 9" ) );

  uchar ping[ 8 ];
  ulong ping_sz = pb_varint_field( ping, 1U, -1L & 0x7FFFFFFFL );
  sz = pb_bytes_field( buf, 9U, ping, ping_sz );
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->has_ping );
  FD_TEST( set->ping_id==0x7FFFFFFF );

  sz = pb_varint_field( buf, 11U, 42UL );
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->has_from_slot );
  FD_TEST( set->from_slot==42UL );

  /* Data slices */
  uchar slice[ 32 ];
  ulong slice_sz;
  sz       = 0UL;
  slice_sz = pb_varint_field( slice, 1U, 0UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 8UL );
  sz      += pb_bytes_field( buf+sz, 7U, slice, slice_sz );
  slice_sz = pb_varint_field( slice, 1U, 8UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 8UL );
  sz      += pb_bytes_field( buf+sz, 7U, slice, slice_sz );
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->slice_cnt==2UL );
  FD_TEST( set->slice[ 0 ].offset==0UL && set->slice[ 0 ].length==8UL );
  FD_TEST( set->slice[ 1 ].offset==8UL && set->slice[ 1 ].length==8UL );

  /* Overlapping slices */
  sz       = 0UL;
  slice_sz = pb_varint_field( slice, 1U, 0UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 16UL );
  sz      += pb_bytes_field( buf+sz, 7U, slice, slice_sz );
  slice_sz = pb_varint_field( slice, 1U, 8UL );
  slice_sz += pb_varint_field( slice+slice_sz, 2U, 8UL );
  sz      += pb_bytes_field( buf+sz, 7U, slice, slice_sz );
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "failed to create filter: data slices overlapped" ) );

  /* More slices than the server keeps */
  sz = 0UL;
  for( ulong i=0UL; i<FD_DRAGON_DATA_SLICE_MAX+1UL; i++ ) {
    slice_sz = pb_varint_field( slice, 1U, i*8UL );
    slice_sz += pb_varint_field( slice+slice_sz, 2U, 8UL );
    sz += pb_bytes_field( buf+sz, 7U, slice, slice_sz );
  }
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "Max amount of filters/data_slices reached, only 16 allowed" ) );

  /* Truncated protobuf */
  buf[ 0 ] = 0x0A; buf[ 1 ] = 0x40;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, 2UL, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "failed to decode SubscribeRequest" ) );

  /* An unknown field is ignored, like any protobuf reader */
  sz = pb_varint_field( buf, 15U, 1UL );
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==0UL );

  /* The predicates of an accounts filter: the account and owner sets
     land in the address pool, the state predicates in the set's own
     list, and the memcmp bytes are decoded from whichever encoding
     the request used. */
  uchar key[ 32 ];
  char  b58[ 64 ];
  fd_memset( key, 0x40, 32UL );
  fd_base58_encode_32( key, NULL, b58 );

  uchar value[ 1024 ];
  ulong value_sz = 0UL;
  value_sz += pb_bytes_field( value+value_sz, 2U, b58, strlen( b58 ) ); /* account */
  value_sz += pb_bytes_field( value+value_sz, 3U, b58, strlen( b58 ) ); /* owner */
  {
    uchar one[ 64 ];
    ulong one_sz = pb_varint_field( one, 2U, 165UL );                   /* datasize */
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  {
    uchar mc[ 128 ];
    ulong mc_sz = pb_varint_field( mc, 1U, 8UL );
    mc_sz += pb_bytes_field( mc+mc_sz, 3U, b58, strlen( b58 ) );        /* memcmp base58 */
    uchar one[ 192 ];
    ulong one_sz = pb_bytes_field( one, 1U, mc, mc_sz );
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  value_sz += pb_varint_field( value+value_sz, 5U, 1UL );               /* nonempty_txn_signature */

  uchar entry[ 1280 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, "a", 1UL );
  entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
  sz = pb_bytes_field( buf, 1U, entry, entry_sz );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==1UL );
  FD_TEST( set->acct_cnt==2UL );
  FD_TEST( set->name[ 0 ].acct_cnt==1UL && set->name[ 0 ].owner_cnt==1UL );
  FD_TEST( set->name[ 0 ].has_txn_sig && set->name[ 0 ].txn_sig );
  FD_TEST( set->name[ 0 ].state_cnt==2UL );
  FD_TEST( set->state[ 0 ].kind==FD_DRAGON_ACCT_STATE_DATASIZE && set->state[ 0 ].value==165UL );
  FD_TEST( set->state[ 1 ].kind==FD_DRAGON_ACCT_STATE_MEMCMP );
  FD_TEST( set->state[ 1 ].offset==8UL && set->state[ 1 ].data_sz==32UL );
  FD_TEST( fd_memeq( set->state_byte+set->state[ 1 ].data_off, key, 32UL ) );

  /* A memcmp whose bytes are base64 of the same address decodes to the
     same bytes. */
  {
    char  b64[ 128 ];
    ulong b64_sz = fd_base64_encode( b64, key, 32UL );
    uchar mc[ 192 ];
    ulong mc_sz = pb_bytes_field( mc, 4U, b64, b64_sz );
    uchar one[ 256 ];
    ulong one_sz = pb_bytes_field( one, 1U, mc, mc_sz );
    value_sz = pb_bytes_field( value, 4U, one, one_sz );
    entry_sz = pb_bytes_field( entry, 1U, "b", 1UL );
    entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
    sz = pb_bytes_field( buf, 1U, entry, entry_sz );
    names_seen = 0UL;
    FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
    FD_TEST( set->name[ 0 ].state_cnt==1UL );
    FD_TEST( set->state[ 0 ].kind==FD_DRAGON_ACCT_STATE_MEMCMP );
    FD_TEST( set->state[ 0 ].data_sz==32UL );
    FD_TEST( fd_memeq( set->state_byte+set->state[ 0 ].data_off, key, 32UL ) );
  }

  /* The reasons a state predicate is refused, with yellowstone's
     texts. */
  struct {
    char const * err;
    uint         field;   /* of SubscribeRequestFilterAccountsFilter */
    ulong        value;
    char const * bytes;   /* memcmp base58, when field is 1 */
    int          twice;
  } const bad[] = {
    { "token_account_state only allowed to be true", 3U, 0UL,   NULL,       0 },
    { "datasize used more than once",                2U, 165UL, NULL,       1 },
    { "filter should be defined",                    9U, 1UL,   NULL,       0 },
    { "invalid base58",                              1U, 0UL,   "0OIl",     0 }
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
    uchar one[ 256 ];
    ulong one_sz;
    if( bad[ i ].field==1U ) {
      uchar mc[ 192 ];
      ulong mc_sz = pb_bytes_field( mc, 3U, bad[ i ].bytes, strlen( bad[ i ].bytes ) );
      one_sz = pb_bytes_field( one, 1U, mc, mc_sz );
    } else {
      one_sz = pb_varint_field( one, bad[ i ].field, bad[ i ].value );
    }
    value_sz  = pb_bytes_field( value, 4U, one, one_sz );
    if( bad[ i ].twice ) value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
    entry_sz  = pb_bytes_field( entry, 1U, "x", 1UL );
    entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
    sz = pb_bytes_field( buf, 1U, entry, entry_sz );
    names_seen = 0UL;
    FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
    if( FD_UNLIKELY( strcmp( err, bad[ i ].err ) ) )
      FD_LOG_ERR(( "state predicate %lu: err `%s`, expected `%s`", i, err, bad[ i ].err ));
  }

  /* More state predicates in one filter than yellowstone allows */
  {
    uchar one[ 64 ];
    ulong one_sz = pb_varint_field( one, 3U, 1UL );
    value_sz = 0UL;
    for( ulong i=0UL; i<FD_DRAGON_ACCT_STATE_MAX+1UL; i++ )
      value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
    entry_sz  = pb_bytes_field( entry, 1U, "y", 1UL );
    entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
    sz = pb_bytes_field( buf, 1U, entry, entry_sz );
    names_seen = 0UL;
    FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
    FD_TEST( !strcmp( err, "Too many filters provided; max 4" ) );
  }

  /* A blocks filter carries its transactions unless the request turns
     them off, and its accounts only when asked for. */
  value_sz  = pb_bytes_field( value, 1U, b58, strlen( b58 ) ); /* account_include */
  value_sz += pb_varint_field( value+value_sz, 3U, 1UL );      /* include_accounts */
  entry_sz  = pb_bytes_field( entry, 1U, "b", 1UL );
  entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
  sz  = pb_bytes_field( buf, 4U, entry, entry_sz );
  sz += pb_map_entry( buf+sz, 4U, "plain", 5UL );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==2UL );
  FD_TEST( set->name[ 0 ].acct_cnt==1UL );
  FD_TEST( set->name[ 0 ].include_txns && set->name[ 0 ].include_accts && !set->name[ 0 ].include_entries );
  FD_TEST( !set->name[ 1 ].acct_cnt );
  FD_TEST( set->name[ 1 ].include_txns && !set->name[ 1 ].include_accts );

  /* A cuckoo account filter, which is field 6 of the accounts filter,
     that does not fit the arena is refused rather than truncated. */
  static uchar huge[ 2UL*G_CUCKOO_ENTRY_MAX*sizeof(ushort) ];
  static uchar huge_cuckoo[ sizeof(huge)+16UL ];
  ulong huge_cuckoo_sz = pb_bytes_field( huge_cuckoo, 1U, huge, sizeof(huge) );
  static uchar huge_value[ sizeof(huge_cuckoo)+16UL ];
  ulong huge_value_sz = pb_bytes_field( huge_value, 6U, huge_cuckoo, huge_cuckoo_sz );
  static uchar huge_entry[ sizeof(huge_value)+32UL ];
  ulong huge_entry_sz  = pb_bytes_field( huge_entry, 1U, "c", 1UL );
  huge_entry_sz += pb_bytes_field( huge_entry+huge_entry_sz, 2U, huge_value, huge_value_sz );
  static uchar huge_req[ sizeof(huge_entry)+32UL ];
  ulong huge_req_sz = pb_bytes_field( huge_req, 1U, huge_entry, huge_entry_sz );
  names_seen = 0UL;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen,
                                    huge_req, huge_req_sz, err, sizeof(err) ) );
  FD_TEST( !strncmp( err, "cuckoo filters of one subscription have to fit", 45UL ) );

  /* With no arena at all, every cuckoo filter is refused */
  ulong small_cuckoo_sz = pb_bytes_field( huge_cuckoo, 1U, huge, 8UL );
  huge_value_sz = pb_bytes_field( huge_value, 6U, huge_cuckoo, small_cuckoo_sz );
  huge_entry_sz  = pb_bytes_field( huge_entry, 1U, "c", 1UL );
  huge_entry_sz += pb_bytes_field( huge_entry+huge_entry_sz, 2U, huge_value, huge_value_sz );
  huge_req_sz = pb_bytes_field( huge_req, 1U, huge_entry, huge_entry_sz );
  names_seen = 0UL;
  FD_TEST( fd_dragon_filter_decode( set, g_limits, NULL, 0UL, &names_seen,
                                    huge_req, huge_req_sz, err, sizeof(err) ) );
  FD_TEST( !strncmp( err, "cuckoo filters of one subscription have to fit", 45UL ) );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen,
                                     huge_req, huge_req_sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==1UL );
  FD_TEST( set->name[ 0 ].cuckoo_bucket_cnt==1UL );
  FD_TEST( set->cuckoo_entry_cnt==4UL );
}


/* Transactions and the deferred levels *******************************/

/* txn_payload writes a legacy transaction with key_cnt addresses, the
   last of which is the program of its one instruction.  Address i is
   32 bytes of key_byte[ i ]. */

static ulong
txn_payload( uchar *       out,
             uint          sig_byte,
             uchar const * key_byte,
             ulong         key_cnt ) {
  FD_TEST( key_cnt>=2UL );
  ulong o = 0UL;
  out[ o++ ] = 1U;                                    /* one signature */
  fd_memset( out+o, (int)sig_byte, 64UL ); o += 64UL;
  out[ o++ ] = 1U;                                    /* signers */
  out[ o++ ] = 0U;                                    /* readonly signers */
  out[ o++ ] = 1U;                                    /* readonly non signers */
  out[ o++ ] = (uchar)key_cnt;
  for( ulong i=0UL; i<key_cnt; i++ ) { fd_memset( out+o, key_byte[ i ], 32UL ); o += 32UL; }
  fd_memset( out+o, 0x30, 32UL ); o += 32UL;           /* recent blockhash */
  out[ o++ ] = 1U;                                    /* one instruction */
  out[ o++ ] = (uchar)( key_cnt-1UL );                /* program */
  out[ o++ ] = 1U;                                    /* one account */
  out[ o++ ] = 0U;
  out[ o++ ] = 1U;                                    /* one data byte */
  out[ o++ ] = 0x77;
  return o;
}

/* core_txn reports one committed transaction to the geyser core, as
   the ingest side would after reassembling its record.  The keys of
   the record are the transaction's own addresses followed by loaded_w
   writable and loaded_r readonly addresses a lookup table would have
   loaded, whose first byte is 0x50 and up. */

static void
core_txn( ulong         bank_seq,
          ulong         slot,
          ulong         index,
          uint          sig_byte,
          int           is_vote,
          long          txn_err,
          uchar const * key_byte,
          ulong         static_cnt,
          ulong         loaded_w,
          ulong         loaded_r ) {
  static uchar payload[ FD_TXN_MTU ];
  static uchar keys[ 16 ][ 32 ];
  static ulong pre [ 16 ];
  static ulong post[ 16 ];
  static uchar writable[ 16 ];
  static uchar logs[ 64 ];

  ulong payload_sz = txn_payload( payload, sig_byte, key_byte, static_cnt );

  ulong key_cnt = static_cnt+loaded_w+loaded_r;
  FD_TEST( key_cnt<=16UL );
  for( ulong i=0UL; i<static_cnt; i++ ) fd_memset( keys[ i ], key_byte[ i ], 32UL );
  for( ulong i=0UL; i<loaded_w+loaded_r; i++ ) fd_memset( keys[ static_cnt+i ], (int)( 0x50UL+i ), 32UL );
  for( ulong i=0UL; i<key_cnt; i++ ) {
    pre     [ i ] = 100UL+i;
    post    [ i ] = 100UL+i-1UL;
    writable[ i ] = (uchar)( i<static_cnt-1UL );
  }

  ulong logs_sz = 0UL;
  logs[ logs_sz++ ] = 0x32; /* the tag the log collector serializes with */
  logs[ logs_sz++ ] = 5U;
  fd_memcpy( logs+logs_sz, "hello", 5UL ); logs_sz += 5UL;

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq             = bank_seq;
  ev->slot                 = slot;
  ev->index_in_slot        = index;
  ev->commit_index_in_slot = index;
  ev->is_simple_vote       = !!is_vote;
  ev->txn_err              = txn_err;
  ev->exec_err_idx         = UINT_MAX;
  ev->custom_err           = UINT_MAX;
  ev->rent_err_account_idx = UINT_MAX;
  ev->execution_fee        = 5000UL;
  ev->compute_units_consumed = 1000UL+index;
  ev->cost_units           = 720UL;
  ev->payload_cnt          = payload_sz;
  ev->acct_addr_cnt        = (uint)static_cnt;
  ev->adtl_writable_cnt    = (uint)loaded_w;
  ev->keys_cnt             = key_cnt;
  ev->pre_lamports_cnt     = key_cnt;
  ev->post_lamports_cnt    = key_cnt;
  ev->is_writable_cnt      = key_cnt;
  ev->logs_cnt             = logs_sz;
  fd_memset( ev->signature, (int)sig_byte, 64UL );

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = pre,
    .post_lamports = post,
    .is_writable   = writable,
    .logs          = logs,
    .trace         = NULL,
    .trace_accts   = NULL,
    .trace_data    = NULL,
    .return_data   = NULL,
    .touched       = NULL
  };
  FD_TEST( !fd_geyser_core_commit_record( g_core, &parts ) );
}

/* core_txn_simple is one transaction of three addresses. */

static void
core_txn_simple( ulong bank_seq,
                 ulong slot,
                 ulong index,
                 uint  sig_byte ) {
  uchar key_byte[ 3 ] = { 0x20, 0x21, 0x22 };
  core_txn( bank_seq, slot, index, sig_byte, 0, 0L, key_byte, 3UL, 0UL, 0UL );
}

/* core_sysvars reports the four sysvar writes a bank has to have been
   seen to seal when the core is told to account for records. */

static void
core_sysvars( ulong bank_seq,
              ulong slot ) {
  uchar const * ids[ 4 ] = { fd_sysvar_clock_id.uc, fd_sysvar_slot_hashes_id.uc,
                             fd_sysvar_slot_history_id.uc, fd_sysvar_recent_block_hashes_id.uc };
  for( ulong i=0UL; i<4UL; i++ ) {
    uchar keys[ 1 ][ 32 ];
    fd_memcpy( keys[ 0 ], ids[ i ], 32UL );

    fd_event_internal_runtime_write_t ev[1];
    fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
    ev->bank_seq   = bank_seq;
    ev->slot       = slot;
    ev->phase      = 0U;
    ev->write_seq  = i;
    ev->keys_cnt   = 1UL;
    ev->touched_cnt = 1UL;

    fd_event_internal_runtime_write_touched_t touched[1] = {{ .key_idx = 0U, .lamports = 1UL }};

    fd_event_internal_runtime_write_parts_t parts = {
      .prefix       = ev,
      .keys         = (uchar const (*)[ 32UL ])keys,
      .touched      = touched
    };
    FD_TEST( !fd_geyser_core_runtime_write_record( g_core, &parts ) );
  }
}

/* core_slot_txns publishes a completed slot that executed txn_cnt
   transactions. */

static void
core_slot_txns( ulong slot,
                ulong block_height,
                ulong txn_cnt ) {
  fd_replay_slot_completed_t msg = {
    .slot              = slot,
    .parent_slot       = slot-1UL,
    .bank_seq          = slot,
    .parent_bank_seq   = slot>1UL ? slot-1UL : ULONG_MAX,
    .bank_idx          = slot % TEST_BANK_IDX_MAX,
    .accdb_fork_id     = { .val = (ushort)slot },
    .block_height      = block_height,
    .transaction_count = 10UL*slot,
    .nonvote_success   = txn_cnt
  };
  msg.block_hash.ul[ 0 ] = 0x100UL + slot;
  g_refcnt[ msg.bank_idx ]++;
  fd_geyser_core_slot_completed( g_core, &msg, g_seq++ );
}

/* Reading content updates ********************************************/

/* sub_filter_txn writes one transactions or transactions_status map
   entry with the predicates the tests use.  A NULL or empty list is
   left out, so a filter with nothing set matches every
   transaction. */

struct sub_txn_filter {
  int           status;     /* a transactions_status filter rather than a transactions one */
  int           has_vote;
  int           vote;
  int           has_failed;
  int           failed;
  uchar const * signature;  /* 64 bytes */
  uchar const * include;    /* one byte per address, repeated to 32 */
  ulong         include_cnt;
  uchar const * exclude;
  ulong         exclude_cnt;
  uchar const * required;
  ulong         required_cnt;
};

typedef struct sub_txn_filter sub_txn_filter_t;

static ulong
sub_filter_txn( uchar *                  p,
                char const *             name,
                sub_txn_filter_t const * f ) {
  uchar value[ 2048 ];
  ulong value_sz = 0UL;
  if( f->has_vote   ) value_sz += pb_varint_field( value+value_sz, 1U, (ulong)!!f->vote   );
  if( f->has_failed ) value_sz += pb_varint_field( value+value_sz, 2U, (ulong)!!f->failed );
  if( f->signature ) {
    char b58[ 128 ];
    fd_base58_encode_64( f->signature, NULL, b58 );
    value_sz += pb_bytes_field( value+value_sz, 5U, b58, strlen( b58 ) );
  }
  struct { uchar const * list; ulong cnt; uint field; } const lists[ 3 ] = {
    { f->include,  f->include_cnt,  3U },
    { f->exclude,  f->exclude_cnt,  4U },
    { f->required, f->required_cnt, 6U }
  };
  for( ulong l=0UL; l<3UL; l++ ) {
    for( ulong i=0UL; i<lists[ l ].cnt; i++ ) {
      uchar key[ 32 ];
      char  b58[ 64 ];
      fd_memset( key, lists[ l ].list[ i ], 32UL );
      fd_base58_encode_32( key, NULL, b58 );
      value_sz += pb_bytes_field( value+value_sz, lists[ l ].field, b58, strlen( b58 ) );
    }
  }

  uchar entry[ 2304 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, name, strlen( name ) );
  if( value_sz ) entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );

  return pb_bytes_field( p, f->status ? 10U : 3U, entry, entry_sz );
}

static ulong
sub_filter_blocks_meta( uchar *      p,
                        char const * name ) {
  return pb_map_entry( p, 5U /* blocks_meta */, name, strlen( name ) );
}


/* tb_field finds the idx-th occurrence of a field of a protobuf
   message: the value of a varint field, or the body of a length
   delimited one.  The updates that carry content are encoded from the
   layer's own buffers, so their submessages are read with this rather
   than with nanopb, which skips the fields it was given no callback
   for. */

static int
tb_field( uchar const *  buf,
          ulong          sz,
          uint           field,
          ulong          idx,
          ulong *        val,
          uchar const ** body,
          ulong *        body_sz ) {
  ulong o    = 0UL;
  ulong seen = 0UL;
  while( o<sz ) {
    ulong key   = 0UL;
    uint  shift = 0U;
    for(;;) {
      FD_TEST( o<sz && shift<=63U );
      uchar c = buf[ o++ ];
      key |= ( (ulong)( c & 0x7F ) )<<shift;
      shift += 7U;
      if( !( c & 0x80 ) ) break;
    }
    ulong wire = key & 7UL;
    uint  f    = (uint)( key>>3 );

    ulong         v   = 0UL;
    uchar const * b   = NULL;
    ulong         bsz = 0UL;

    if( wire==0UL ) {
      shift = 0U;
      for(;;) {
        FD_TEST( o<sz && shift<=63U );
        uchar c = buf[ o++ ];
        v |= ( (ulong)( c & 0x7F ) )<<shift;
        shift += 7U;
        if( !( c & 0x80 ) ) break;
      }
    } else if( wire==2UL ) {
      shift = 0U;
      for(;;) {
        FD_TEST( o<sz && shift<=63U );
        uchar c = buf[ o++ ];
        bsz |= ( (ulong)( c & 0x7F ) )<<shift;
        shift += 7U;
        if( !( c & 0x80 ) ) break;
      }
      FD_TEST( bsz<=sz-o );
      b  = buf+o;
      o += bsz;
    } else FD_TEST( 0 );

    if( f==field ) {
      if( seen==idx ) {
        if( val     ) *val     = v;
        if( body    ) *body    = b;
        if( body_sz ) *body_sz = bsz;
        return 1;
      }
      seen++;
    }
  }
  return 0;
}

static uchar const *
tb_sub( uchar const * buf,
        ulong         sz,
        uint          field,
        ulong *       sub_sz ) {
  uchar const * body = NULL;
  FD_TEST( tb_field( buf, sz, field, 0UL, NULL, &body, sub_sz ) );
  return body;
}

/* tb_err_bytes returns the bincode of the transaction error of a
   status update. */

static uchar const *
tb_status_err( uchar const * msg,
               ulong         msg_sz,
               ulong *       err_sz ) {
  ulong         body_sz;
  uchar const * body = tb_sub( msg, msg_sz, 10U, &body_sz );
  ulong         terr_sz;
  uchar const * terr = tb_sub( body, body_sz, 5U, &terr_sz );
  return tb_sub( terr, terr_sz, 1U, err_sz );
}

/* update_at decodes the next SubscribeUpdate of a subscription with
   nanopb, which skips the fields of the message that are encoded from
   the layer's own buffers.  err_out, when not NULL, receives the bytes
   of the transaction error. */

static ulong
update_at( tc_t *                   tc,
           uint                     stream_id,
           ulong                    off,
           geyser_SubscribeUpdate * update,
           slot_filters_t *         filters,
           uchar const **           raw,
           ulong *                  raw_sz ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  if( FD_UNLIKELY( off>=s->data_sz ) ) FD_LOG_ERR(( "no update at offset %lu of %lu", off, s->data_sz ));
  ulong next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );

  *update = (geyser_SubscribeUpdate)geyser_SubscribeUpdate_init_zero;
  update->filters.funcs.decode = decode_filter_name;
  update->filters.arg          = filters;

  pb_istream_t is = pb_istream_from_buffer( msg, msg_sz );
  FD_TEST( pb_decode( &is, geyser_SubscribeUpdate_fields, update ) );
  FD_TEST( update->has_created_at );
  if( raw    ) *raw    = msg;
  if( raw_sz ) *raw_sz = msg_sz;
  return next;
}

/* expect_txn checks that the next update of a subscription is one
   transaction, with the signature, index and filter name expected. */

static ulong
expect_txn( tc_t *       tc,
            uint         stream_id,
            ulong        off,
            uint         sig_byte,
            ulong        slot,
            ulong        bank_id,
            ulong        index,
            char const * filter_name ) {
  slot_filters_t         filters[1] = {{0}};
  geyser_SubscribeUpdate update;
  ulong next = update_at( tc, stream_id, off, &update, filters, NULL, NULL );

  if( FD_UNLIKELY( update.which_update_oneof!=geyser_SubscribeUpdate_transaction_tag ) )
    FD_LOG_ERR(( "update at %lu is oneof %u, expected a transaction", off, update.which_update_oneof ));

  geyser_SubscribeUpdateTransaction const * u = &update.update_oneof.transaction;
  FD_TEST( u->slot==slot );
  FD_TEST( u->bank_id==bank_id );
  FD_TEST( u->has_transaction );
  FD_TEST( u->transaction.signature.size==64UL );
  FD_TEST( u->transaction.signature.bytes[ 0 ]==(uchar)sig_byte );
  FD_TEST( u->transaction.index==index );
  FD_TEST( u->transaction.has_transaction );
  FD_TEST( u->transaction.has_meta );
  FD_TEST( u->transaction.meta.fee==5000UL );
  FD_TEST( u->transaction.meta.has_compute_units_consumed );
  FD_TEST( u->transaction.meta.compute_units_consumed==1000UL+index );
  FD_TEST( u->transaction.meta.has_cost_units && u->transaction.meta.cost_units==720UL );
  FD_TEST( filters->cnt==1UL && !strcmp( filters->name[ 0 ], filter_name ) );
  return next;
}

static ulong
expect_txn_status( tc_t *         tc,
                   uint           stream_id,
                   ulong          off,
                   uint           sig_byte,
                   ulong          slot,
                   ulong          bank_id,
                   ulong          index,
                   int            failed,
                   char const *   filter_name ) {
  slot_filters_t         filters[1] = {{0}};
  geyser_SubscribeUpdate update;
  uchar const *          raw;
  ulong                  raw_sz;
  ulong next = update_at( tc, stream_id, off, &update, filters, &raw, &raw_sz );

  if( FD_UNLIKELY( update.which_update_oneof!=geyser_SubscribeUpdate_transaction_status_tag ) )
    FD_LOG_ERR(( "update at %lu is oneof %u, expected a transaction status", off, update.which_update_oneof ));

  geyser_SubscribeUpdateTransactionStatus const * u = &update.update_oneof.transaction_status;
  FD_TEST( u->slot==slot );
  FD_TEST( u->bank_id==bank_id );
  FD_TEST( u->index==index );
  FD_TEST( u->signature.size==64UL && u->signature.bytes[ 0 ]==(uchar)sig_byte );
  FD_TEST( !!u->has_err==!!failed );
  if( failed ) {
    ulong err_sz;
    FD_TEST( tb_status_err( raw, raw_sz, &err_sz ) );
    FD_TEST( err_sz==4UL );
  }
  FD_TEST( filters->cnt==1UL && !strcmp( filters->name[ 0 ], filter_name ) );
  return next;
}

static ulong
expect_block_meta( tc_t *       tc,
                   uint         stream_id,
                   ulong        off,
                   ulong        slot,
                   ulong        bank_id,
                   ulong        txn_cnt,
                   char const * filter_name ) {
  slot_filters_t         filters[1] = {{0}};
  geyser_SubscribeUpdate update;
  ulong next = update_at( tc, stream_id, off, &update, filters, NULL, NULL );

  if( FD_UNLIKELY( update.which_update_oneof!=geyser_SubscribeUpdate_block_meta_tag ) )
    FD_LOG_ERR(( "update at %lu is oneof %u, expected a block meta", off, update.which_update_oneof ));

  geyser_SubscribeUpdateBlockMeta const * u = &update.update_oneof.block_meta;
  FD_TEST( u->slot==slot );
  FD_TEST( u->bank_id==bank_id );
  FD_TEST( u->executed_transaction_count==txn_cnt );
  FD_TEST( u->has_rewards );
  FD_TEST( !u->has_block_time );
  FD_TEST( u->has_block_height );
  char expect[ FD_BASE58_ENCODED_32_SZ ];
  block_hash_b58( slot, expect );
  FD_TEST( !strcmp( u->blockhash, expect ) );
  FD_TEST( u->entries_count==0UL );
  FD_TEST( filters->cnt==1UL && !strcmp( filters->name[ 0 ], filter_name ) );
  return next;
}

/* tc_service_all runs the service loop until the transport has handed
   the test everything it had queued, which takes more than one pass
   when a client is sent more in one go than a connection's buffer
   holds. */

static void
tc_service_all( tc_t * tc ) {
  for( int i=0; i<256; i++ ) tc_service( tc );
}

/* sub_open opens a Subscribe stream with the given request and
   swallows the server ping every stream starts with. */

static ulong
sub_open( tc_t *        tc,
          uint          stream_id,
          uchar const * req,
          ulong         req_sz ) {
  req_opt_t opt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, stream_id, &opt );
  tc_msg( tc, stream_id, req, req_sz, 0 );
  tc_flush( tc );

  geyser_SubscribeUpdate ping;
  slot_filters_t         filters[1] = {{0}};
  ulong off = update_at( tc, stream_id, 0UL, &ping, filters, NULL, NULL );
  if( FD_UNLIKELY( ping.which_update_oneof!=geyser_SubscribeUpdate_ping_tag ) )
    FD_LOG_ERR(( "stream %u opened with oneof %u, expected a ping", stream_id, ping.which_update_oneof ));
  return off;
}

/* Transactions at processed, and the encoding shared by clients ******/

static void
test_txn_processed( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 4096 ];
  sub_txn_filter_t all    = {0};
  sub_txn_filter_t status = { .status = 1 };

  /* Two clients that both match everything, under different filter
     names, plus one that asks for the lightweight status. */
  ulong sz   = sub_filter_txn( req, "mine", &all );
  ulong off1 = sub_open( tc, 1U, req, sz );
  sz         = sub_filter_txn( req, "yours", &all );
  ulong off3 = sub_open( tc, 3U, req, sz );
  sz         = sub_filter_txn( req, "st", &status );
  ulong off5 = sub_open( tc, 5U, req, sz );

  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  core_txn_simple( 10UL, 10UL, 1UL, 0xA2U );
  core_slot_txns( 10UL, 500UL, 2UL );
  tc_service( tc );

  /* A transaction arrives as it commits, before the slot is
     complete. */
  uchar const * raw1;
  ulong         raw1_sz;
  slot_filters_t f1[1] = {{0}};
  geyser_SubscribeUpdate u1;
  ulong next1 = update_at( tc, 1U, off1, &u1, f1, &raw1, &raw1_sz );
  FD_TEST( u1.which_update_oneof==geyser_SubscribeUpdate_transaction_tag );
  FD_TEST( f1->cnt==1UL && !strcmp( f1->name[ 0 ], "mine" ) );

  uchar const * raw3;
  ulong         raw3_sz;
  slot_filters_t f3[1] = {{0}};
  geyser_SubscribeUpdate u3;
  ulong next3 = update_at( tc, 3U, off3, &u3, f3, &raw3, &raw3_sz );
  FD_TEST( f3->cnt==1UL && !strcmp( f3->name[ 0 ], "yours" ) );

  /* The two clients got the same payload bytes: the message is the
     client's own filter name, then the shared body, then the
     timestamp.  The names differ in length by one, so the bodies line
     up one byte apart. */
  ulong body1 = 1UL+1UL+strlen( "mine"  );
  ulong body3 = 1UL+1UL+strlen( "yours" );
  FD_TEST( raw1_sz+1UL==raw3_sz );
  FD_TEST( !memcmp( raw1+body1, raw3+body3, raw1_sz-body1 ) );

  off1 = expect_txn( tc, 1U, off1, 0xA1U, 10UL, 10UL, 0UL, "mine" );
  FD_TEST( off1==next1 );
  off1 = expect_txn( tc, 1U, off1, 0xA2U, 10UL, 10UL, 1UL, "mine" );
  off3 = expect_txn( tc, 3U, off3, 0xA1U, 10UL, 10UL, 0UL, "yours" );
  FD_TEST( off3==next3 );
  off3 = expect_txn( tc, 3U, off3, 0xA2U, 10UL, 10UL, 1UL, "yours" );

  /* The status subscription got the lightweight message for both. */
  off5 = expect_txn_status( tc, 5U, off5, 0xA1U, 10UL, 10UL, 0UL, 0, "st" );
  off5 = expect_txn_status( tc, 5U, off5, 0xA2U, 10UL, 10UL, 1UL, 0, "st" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  /* Nothing else: a processed subscription is served as the records
     arrive, and the confirmation and rooting of the bank add
     nothing. */
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->txn_update_cnt==4UL );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->txn_status_cnt==2UL );
  FD_TEST( !fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) ) );

  tc_close( tc );
  test_server_delete( server );
}

/* The transaction predicates *****************************************/

static void
test_txn_filters( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .max_stream_cnt = 8UL };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 4096 ];
  uchar sig_a2[ 64 ];
  fd_memset( sig_a2, 0xA2, 64UL );

  uchar const inc_20  [ 1 ] = { 0x20 };
  uchar const inc_50  [ 1 ] = { 0x50 }; /* the first loaded writable address */
  uchar const exc_21  [ 1 ] = { 0x21 };
  uchar const req_both[ 2 ] = { 0x20, 0x22 };

  sub_txn_filter_t votes    = { .has_vote = 1, .vote = 1 };
  sub_txn_filter_t nonvotes = { .has_vote = 1, .vote = 0 };
  sub_txn_filter_t failed   = { .has_failed = 1, .failed = 1 };
  sub_txn_filter_t bysig    = { .signature = sig_a2 };
  sub_txn_filter_t include  = { .include = inc_20, .include_cnt = 1UL };
  sub_txn_filter_t loaded   = { .include = inc_50, .include_cnt = 1UL };
  sub_txn_filter_t exclude  = { .exclude = exc_21, .exclude_cnt = 1UL };
  sub_txn_filter_t required = { .required = req_both, .required_cnt = 2UL };

  struct { uint id; char const * name; sub_txn_filter_t const * f; } const sub[ 8 ] = {
    {  1U, "vote",     &votes    },
    {  3U, "nonvote",  &nonvotes },
    {  5U, "failed",   &failed   },
    {  7U, "sig",      &bysig    },
    {  9U, "inc",      &include  },
    { 11U, "loaded",   &loaded   },
    { 13U, "exc",      &exclude  },
    { 15U, "req",      &required }
  };
  ulong off[ 8 ];
  for( ulong i=0UL; i<8UL; i++ ) {
    ulong sz = sub_filter_txn( req, sub[ i ].name, sub[ i ].f );
    off[ i ] = sub_open( tc, sub[ i ].id, req, sz );
  }

  uchar key_a[ 3 ] = { 0x20, 0x21, 0x22 };
  uchar key_b[ 3 ] = { 0x23, 0x24, 0x22 };

  /* A plain transaction of addresses 0x20,0x21,0x22 */
  core_txn( 10UL, 10UL, 0UL, 0xA1U, 0, 0L, key_a, 3UL, 0UL, 0UL );
  /* A vote that failed, of the same addresses */
  core_txn( 10UL, 10UL, 1UL, 0xA2U, 1, -9L, key_a, 3UL, 0UL, 0UL );
  /* One of other addresses, with two loaded ones */
  core_txn( 10UL, 10UL, 2UL, 0xA3U, 0, 0L, key_b, 3UL, 1UL, 1UL );
  tc_service( tc );

  /* vote: only the vote */
  off[ 0 ] = expect_txn( tc, 1U, off[ 0 ], 0xA2U, 10UL, 10UL, 1UL, "vote" );
  FD_TEST( off[ 0 ]==tc_stream( tc, 1U )->data_sz );

  /* not a vote: the other two */
  off[ 1 ] = expect_txn( tc, 3U, off[ 1 ], 0xA1U, 10UL, 10UL, 0UL, "nonvote" );
  off[ 1 ] = expect_txn( tc, 3U, off[ 1 ], 0xA3U, 10UL, 10UL, 2UL, "nonvote" );
  FD_TEST( off[ 1 ]==tc_stream( tc, 3U )->data_sz );

  /* failed: only the one that carries an error */
  off[ 2 ] = expect_txn( tc, 5U, off[ 2 ], 0xA2U, 10UL, 10UL, 1UL, "failed" );
  FD_TEST( off[ 2 ]==tc_stream( tc, 5U )->data_sz );

  /* signature: the one it names */
  off[ 3 ] = expect_txn( tc, 7U, off[ 3 ], 0xA2U, 10UL, 10UL, 1UL, "sig" );
  FD_TEST( off[ 3 ]==tc_stream( tc, 7U )->data_sz );

  /* account_include over the message's own addresses */
  off[ 4 ] = expect_txn( tc, 9U, off[ 4 ], 0xA1U, 10UL, 10UL, 0UL, "inc" );
  off[ 4 ] = expect_txn( tc, 9U, off[ 4 ], 0xA2U, 10UL, 10UL, 1UL, "inc" );
  FD_TEST( off[ 4 ]==tc_stream( tc, 9U )->data_sz );

  /* account_include over an address a lookup table loaded */
  off[ 5 ] = expect_txn( tc, 11U, off[ 5 ], 0xA3U, 10UL, 10UL, 2UL, "loaded" );
  FD_TEST( off[ 5 ]==tc_stream( tc, 11U )->data_sz );

  /* account_exclude drops the two that use 0x21 */
  off[ 6 ] = expect_txn( tc, 13U, off[ 6 ], 0xA3U, 10UL, 10UL, 2UL, "exc" );
  FD_TEST( off[ 6 ]==tc_stream( tc, 13U )->data_sz );

  /* account_required needs both of its addresses */
  off[ 7 ] = expect_txn( tc, 15U, off[ 7 ], 0xA1U, 10UL, 10UL, 0UL, "req" );
  off[ 7 ] = expect_txn( tc, 15U, off[ 7 ], 0xA2U, 10UL, 10UL, 1UL, "req" );
  FD_TEST( off[ 7 ]==tc_stream( tc, 15U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A failed transaction carries the bincode of its error. */

static void
test_txn_failed_err( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 1024 ];
  sub_txn_filter_t status = { .status = 1 };
  ulong sz   = sub_filter_txn( req, "st", &status );
  ulong off1 = sub_open( tc, 1U, req, sz );

  uchar key_a[ 3 ] = { 0x20, 0x21, 0x22 };
  core_txn( 10UL, 10UL, 0UL, 0xA1U, 0, -3L /* account not found */, key_a, 3UL, 0UL, 0UL );
  tc_service( tc );

  slot_filters_t         f[1] = {{0}};
  geyser_SubscribeUpdate u;
  uchar const *          raw;
  ulong                  raw_sz;
  update_at( tc, 1U, off1, &u, f, &raw, &raw_sz );
  ulong         err_sz;
  uchar const * err = tb_status_err( raw, raw_sz, &err_sz );
  /* AccountNotFound is variant 2 of agave's TransactionError, which is
     Firedancer's -3 as -(2+1). */
  FD_TEST( err_sz==4UL && err[ 0 ]==2 && !err[ 1 ] && !err[ 2 ] && !err[ 3 ] );
  off1 = expect_txn_status( tc, 1U, off1, 0xA1U, 10UL, 10UL, 0UL, 1, "st" );

  tc_close( tc );
  test_server_delete( server );
}

/* Block metas at every level *****************************************/

static void
test_block_meta( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 1024 ];
  ulong sz   = sub_filter_blocks_meta( req, "bm" );
  ulong off1 = sub_open( tc, 1U, req, sz );

  ulong sz3  = sub_filter_blocks_meta( req+sz, "bmc" );
  memmove( req, req+sz, sz3 );
  sz3 += pb_varint_field( req+sz3, 6U, 1UL ); /* confirmed */
  ulong off3 = sub_open( tc, 3U, req, sz3 );

  ulong sz5 = sub_filter_blocks_meta( req, "bmf" );
  sz5 += pb_varint_field( req+sz5, 6U, 2UL ); /* finalized */
  ulong off5 = sub_open( tc, 5U, req, sz5 );

  core_slot_txns( 10UL, 500UL, 2UL );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );

  /* At processed the summary goes out when the bank freezes. */
  off1 = expect_block_meta( tc, 1U, off1, 10UL, 10UL, 2UL, "bm" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* The confirmed and finalized subscriptions were installed before
     the bank existed, so they see it at their own level. */
  off3 = expect_block_meta( tc, 3U, off3, 10UL, 10UL, 2UL, "bmc" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );
  off5 = expect_block_meta( tc, 5U, off5, 10UL, 10UL, 2UL, "bmf" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* The deferred levels ************************************************/

static void
test_defer_delivery( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A bank that is already in flight when the client subscribes. */
  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  /* The slots filter keeps the subscription's own commitment only, so
     that what the test sees is what the deferred path delivers; the
     statuses of the other levels reach a client whatever its
     commitment, as they do in yellowstone. */
  ulong sz  = sub_filter_txn( req, "tx", &all );
  sz       += sub_filter_blocks_meta( req+sz, "bm" );
  sz       += sub_filter_slots( req+sz, "sl", 1, 0 );
  sz       += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off = sub_open( tc, 1U, req, sz );

  /* The bank in flight is finished and rooted, and nothing is
     delivered for it: the subscription is eligible from the next new
     bank. */
  core_txn_simple( 10UL, 10UL, 1UL, 0xA2U );
  core_slot_txns( 10UL, 500UL, 2UL );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* The next bank is delivered whole, in one go, when it is rooted:
     its transactions, then its summary, then its slot status. */
  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  core_txn_simple( 11UL, 11UL, 1UL, 0xB2U );
  core_slot_txns( 11UL, 501UL, 2UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz ); /* nothing at processed */

  core_oc( 11UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz ); /* nothing at confirmed either */

  core_root( 11UL );
  tc_service( tc );
  off = expect_txn( tc, 1U, off, 0xB1U, 11UL, 11UL, 0UL, "tx" );
  off = expect_txn( tc, 1U, off, 0xB2U, 11UL, 11UL, 1UL, "tx" );
  off = expect_block_meta( tc, 1U, off, 11UL, 11UL, 2UL, "bm" );
  off = expect_slot_update( tc, 1U, off, 11UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 11L, "sl" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* The buffer forgot the bank once it was served. */
  FD_TEST( !fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) ) );
  FD_TEST( !fd_dragon_buf_bank( fd_dragon_rpc_buf( g_rpc ), 11UL ) );

  tc_close( tc );
  test_server_delete( server );
}

/* A confirmed subscription is served at confirmation, and a finalized
   one at rooting, from the same stored messages. */

static void
test_defer_levels( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  ulong sz   = sub_filter_txn( req, "c", &all );
  sz        += pb_varint_field( req+sz, 6U, 1UL ); /* confirmed */
  ulong off1 = sub_open( tc, 1U, req, sz );

  /* The finalized subscription asks for both the full transaction and
     the lightweight status, so the store holds two messages for it and
     delivers both. */
  sub_txn_filter_t status = { .status = 1 };
  sz         = sub_filter_txn( req, "f", &all );
  sz        += sub_filter_txn( req+sz, "fst", &status );
  sz        += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off3 = sub_open( tc, 3U, req, sz );

  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  core_slot_txns( 10UL, 500UL, 1UL );
  tc_service( tc );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  core_oc( 10UL );
  tc_service( tc );
  off1 = expect_txn( tc, 1U, off1, 0xA1U, 10UL, 10UL, 0UL, "c" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  core_root( 10UL );
  tc_service( tc );
  off3 = expect_txn( tc, 3U, off3, 0xA1U, 10UL, 10UL, 0UL, "f" );
  off3 = expect_txn_status( tc, 3U, off3, 0xA1U, 10UL, 10UL, 0UL, 0, "fst" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* Replacing the filter set clears what the store holds for the client
   and starts it at the next new bank. */

static void
test_defer_filter_update( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  ulong sz  = sub_filter_txn( req, "old", &all );
  sz       += pb_varint_field( req+sz, 6U, 2UL );
  ulong off = sub_open( tc, 1U, req, sz );

  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  tc_service( tc );
  FD_TEST( fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) )==1UL );

  /* The new filter set is not the one the buffered message was matched
     against, so the bank is not served to this client. */
  sz  = sub_filter_txn( req, "new", &all );
  sz += pb_varint_field( req+sz, 6U, 2UL );
  tc_msg( tc, 1U, req, sz, 0 );
  tc_flush( tc );

  core_slot_txns( 10UL, 500UL, 1UL );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* The next bank is delivered under the new name. */
  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  core_slot_txns( 11UL, 501UL, 1UL );
  core_root( 11UL );
  tc_service( tc );
  off = expect_txn( tc, 1U, off, 0xB1U, 11UL, 11UL, 0UL, "new" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A client that goes away leaves its bits in the store, and its slot
   is held back until the banks it had messages for have drained. */

/* A client slot that a subscriber left is handed to the next client
   at once, and the banks the old client had messages buffered for are
   not the new client's: it is eligible from the next new bank. */

static void
test_defer_slot_reuse( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  ulong sz = sub_filter_txn( req, "gone", &all );
  sz      += pb_varint_field( req+sz, 6U, 2UL );
  sub_open( tc, 1U, req, sz );

  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  tc_service( tc );
  FD_TEST( fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) )==1UL );

  /* The client gives up on the call. */
  tc_frame( tc, FD_H2_FRAME_TYPE_RST_STREAM, 0U, 1U, "\0\0\0\0", 4UL );
  tc_flush( tc );

  /* A new subscription takes the slot the old one left, whose bit the
     buffered message carries. */
  sz  = sub_filter_txn( req, "new", &all );
  sz += pb_varint_field( req+sz, 6U, 2UL );
  ulong off = sub_open( tc, 3U, req, sz );

  /* The bank the old client had a message for is served, and nothing
     goes to the new client: the message is not its. */
  core_slot_txns( 10UL, 500UL, 1UL );
  core_root( 10UL );
  tc_service( tc );
  FD_TEST( off==tc_stream( tc, 3U )->data_sz );

  /* A third client, at processed, is served as it arrives. */
  sz  = sub_filter_txn( req, "third", &all );
  ulong off5 = sub_open( tc, 5U, req, sz );
  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  tc_service( tc );
  off5 = expect_txn( tc, 5U, off5, 0xB1U, 11UL, 11UL, 0UL, "third" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A bank that did not account for its records is not served at the
   deferred levels, and the processed level is unaffected. */

static void
test_defer_incomplete( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .records_gate = 1 };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  ulong sz   = sub_filter_txn( req, "p", &all );
  sz        += sub_filter_slots( req+sz, "sl", 0, 0 );
  ulong off1 = sub_open( tc, 1U, req, sz );

  sz         = sub_filter_txn( req, "f", &all );
  sz        += sub_filter_slots( req+sz, "slf", 0, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  /* The bank says it executed two transactions but only one record
     arrived, so it never seals. */
  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  core_sysvars( 10UL, 10UL );
  core_slot_txns( 10UL, 500UL, 2UL );
  core_oc  ( 10UL );
  core_root( 10UL );
  tc_service( tc );

  /* Processed saw the transaction and the processed status. */
  off1 = expect_txn( tc, 1U, off1, 0xA1U, 10UL, 10UL, 0UL, "p" );
  off1 = expect_slot_update( tc, 1U, off1, 10UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 10L, "sl" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* The finalized subscription saw the processed status of the bank,
     because a plain slots filter passes every commitment, and nothing
     else: no transaction, no summary, no finalized status. */
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 10L, "slf" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  /* A bank that does account for everything is served. */
  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  core_sysvars( 11UL, 11UL );
  core_slot_txns( 11UL, 501UL, 1UL );
  core_root( 11UL );
  tc_service( tc );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_PROCESSED, 11L, "slf" );
  off3 = expect_txn( tc, 3U, off3, 0xB1U, 11UL, 11UL, 0UL, "f" );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 11L, "slf" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A ring too small for a bank has overwritten the bank's first entries
   by the time it is served: the subscriptions that wanted its content
   are ended, the slot status goes out to everyone else, and the
   processed level is unaffected. */

static void
test_defer_budget( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .buf_bytes = 16384UL };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};
  ulong sz   = sub_filter_txn( req, "p", &all );
  ulong off1 = sub_open( tc, 1U, req, sz );

  sz         = sub_filter_txn( req, "f", &all );
  sz        += sub_filter_slots( req+sz, "slf", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  /* A finalized subscription to slot statuses only. */
  sz         = sub_filter_slots( req, "sl5", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off5 = sub_open( tc, 5U, req, sz );

  /* The ring holds a few dozen of these, so a slot of a hundred and
     twenty laps it. */
  for( ulong i=0UL; i<120UL; i++ ) core_txn_simple( 10UL, 10UL, i, 0xC0U+(uint)i );
  core_slot_txns( 10UL, 500UL, 120UL );
  core_root( 10UL );
  tc_service_all( tc );

  FD_TEST( fd_dragon_buf_metrics( fd_dragon_rpc_buf( g_rpc ) )->overrun_cnt==1UL );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->degrade_cnt );

  /* The processed subscription saw every transaction. */
  for( ulong i=0UL; i<120UL; i++ ) off1 = expect_txn( tc, 1U, off1, 0xC0U+(uint)i, 10UL, 10UL, i, "p" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* The finalized subscription that wanted the bank's content got
     none of it and was ended, since it cannot be given the bank
     whole; the one that watches statuses saw the slot finalized. */
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );
  FD_TEST( !strcmp( tc_stream( tc, 3U )->grpc_status, "13" ) );
  FD_TEST( !strcmp( tc_stream( tc, 3U )->grpc_message, "content of slot 10 at finalized was lost" ) );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->content_lost_cnt==1UL );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->content_lost_close_cnt==1UL );
  off5 = expect_slot_update( tc, 5U, off5, 10UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 10L, "sl5" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  /* The ring has come round, so a new subscription is served the next
     bank. */
  sz         = sub_filter_txn( req, "f", &all );
  sz        += sub_filter_slots( req+sz, "slf", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off7 = sub_open( tc, 7U, req, sz );
  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  core_slot_txns( 11UL, 501UL, 1UL );
  core_root( 11UL );
  tc_service( tc );
  off7 = expect_txn( tc, 7U, off7, 0xB1U, 11UL, 11UL, 0UL, "f" );
  off7 = expect_slot_update( tc, 7U, off7, 11UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 11L, "slf" );
  FD_TEST( off7==tc_stream( tc, 7U )->data_sz );
  off5 = expect_slot_update( tc, 5U, off5, 11UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 11L, "sl5" );
  FD_TEST( off5==tc_stream( tc, 5U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* With deferred delivery off, a subscription that asks for one of the
   levels it would need is refused. */

static void
test_defer_disabled( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 65536UL, .no_deferred = 1 };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  FD_TEST( !fd_dragon_rpc_buf( g_rpc ) );

  static uchar req[ 1024 ];
  sub_txn_filter_t all = {0};
  req_opt_t opt2 = { .path = ROUTE( "Subscribe" ) };

  ulong sz = sub_filter_txn( req, "c", &all );
  sz      += pb_varint_field( req+sz, 6U, 1UL );
  tc_request( tc, 1U, &opt2 );
  tc_msg( tc, 1U, req, sz, 0 );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "3", "commitment confirmed not supported by this server" );

  sz  = sub_filter_txn( req, "f", &all );
  sz += pb_varint_field( req+sz, 6U, 2UL );
  tc_request( tc, 3U, &opt2 );
  tc_msg( tc, 3U, req, sz, 0 );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "3", "commitment finalized not supported by this server" );

  /* A subscription at processed is served as usual. */
  sz = sub_filter_txn( req, "p", &all );
  ulong off = sub_open( tc, 5U, req, sz );
  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  tc_service( tc );
  off = expect_txn( tc, 5U, off, 0xA1U, 10UL, 10UL, 0UL, "p" );
  FD_TEST( off==tc_stream( tc, 5U )->data_sz );

  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->deferred_reject_cnt==2UL );

  tc_close( tc );
  test_server_delete( server );
}

/* A cuckoo account filter selects transactions by the accounts it
   probably holds, alongside the explicit account_include list. */

static void
test_txn_cuckoo( void ) {
  fd_dragon_filter_set_t set[1];
  char                   err[ FD_DRAGON_ERR_MAX ];
  ulong                  names_seen = 0UL;

  /* The client's filter over two of the three keys below */
  uchar key[ 3 ][ 32 ];
  for( ulong i=0UL; i<3UL; i++ ) fd_memset( key[ i ], (int)( 0x40+i ), 32UL );

  static ushort           build_mem[ 4UL*64UL ];
  fd_dragon_cuckoo_t      build[1];
  fd_dragon_cuckoo_init( build, FD_DRAGON_CUCKOO_DEFAULT_SEED, build_mem, 64UL );
  FD_TEST( fd_dragon_cuckoo_insert( build, key[ 0 ], 32UL ) );
  FD_TEST( fd_dragon_cuckoo_insert( build, key[ 1 ], 32UL ) );
  uchar data[ 64UL*FD_DRAGON_CUCKOO_BUCKET_SZ ];
  fd_dragon_cuckoo_encode( build, data );

  uchar cuckoo_msg[ sizeof(data)+16UL ];
  ulong cuckoo_msg_sz = pb_bytes_field( cuckoo_msg, 1U, data, sizeof(data) );

  uchar value[ sizeof(cuckoo_msg)+16UL ];
  ulong value_sz = pb_bytes_field( value, 7U, cuckoo_msg, cuckoo_msg_sz );

  uchar entry[ sizeof(value)+32UL ];
  ulong entry_sz = pb_bytes_field( entry, 1U, "cu", 2UL );
  entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );

  uchar buf[ sizeof(entry)+32UL ];
  ulong sz = pb_bytes_field( buf, 3U, entry, entry_sz );

  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name_cnt==1UL );
  FD_TEST( set->name[ 0 ].cuckoo_bucket_cnt==64UL );
  FD_TEST( set->name[ 0 ].cuckoo_seed==FD_DRAGON_CUCKOO_DEFAULT_SEED );
  FD_TEST( !set->name[ 0 ].include_cnt );

  uchar sig[ 64 ];
  fd_memset( sig, 0, 64UL );
  FD_TEST(  fd_dragon_txn_match( set, set->name+0, sig, 0, 0, (uchar const (*)[32])key[ 0 ], 1UL ) );
  FD_TEST(  fd_dragon_txn_match( set, set->name+0, sig, 0, 0, (uchar const (*)[32])key[ 1 ], 1UL ) );
  FD_TEST( !fd_dragon_txn_match( set, set->name+0, sig, 0, 0, (uchar const (*)[32])key[ 2 ], 1UL ) );
  /* one member among several keys is a hit */
  FD_TEST(  fd_dragon_txn_match( set, set->name+0, sig, 0, 0, (uchar const (*)[32])key, 3UL ) );

  /* A filter whose data field holds no whole bucket is one empty
     bucket, which matches nothing but does not match everything. */
  cuckoo_msg_sz = pb_bytes_field( cuckoo_msg, 1U, data, 3UL );
  value_sz = pb_bytes_field( value, 7U, cuckoo_msg, cuckoo_msg_sz );
  entry_sz  = pb_bytes_field( entry, 1U, "cu", 2UL );
  entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
  sz = pb_bytes_field( buf, 3U, entry, entry_sz );
  names_seen = 0UL;
  FD_TEST( !fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( set->name[ 0 ].cuckoo_bucket_cnt==1UL );
  FD_TEST( !fd_dragon_txn_match( set, set->name+0, sig, 0, 0, (uchar const (*)[32])key, 3UL ) );

  /* A malformed address is refused the way agave's parser reports
     it. */
  uchar value2[ 64 ];
  ulong value2_sz = pb_bytes_field( value2, 3U, "notbase58!", 10UL );
  entry_sz = pb_bytes_field( entry, 1U, "bad", 3UL );
  entry_sz += pb_bytes_field( entry+entry_sz, 2U, value2, value2_sz );
  sz = pb_bytes_field( buf, 3U, entry, entry_sz );
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "Invalid Base58 string" ) );

  /* More addresses than the server keeps */
  static uchar big[ 64UL<<10 ];
  ulong        big_sz = 0UL;
  for( ulong i=0UL; i<FD_DRAGON_FILTER_ACCT_MAX+1UL; i++ ) {
    uchar key[ 32 ];
    char  b58[ 64 ];
    fd_memset( key, (int)( i & 0xFFUL ), 32UL );
    key[ 31 ] = (uchar)( i>>8 );
    fd_base58_encode_32( key, NULL, b58 );
    big_sz += pb_bytes_field( big+big_sz, 3U, b58, strlen( b58 ) );
  }
  static uchar big_entry[ 80UL<<10 ];
  ulong        big_entry_sz  = pb_bytes_field( big_entry, 1U, "many", 4UL );
  big_entry_sz += pb_bytes_field( big_entry+big_entry_sz, 2U, big, big_sz );
  static uchar req[ 96UL<<10 ];
  sz = pb_bytes_field( req, 3U, big_entry, big_entry_sz );
  FD_TEST( fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, req, sz, err, sizeof(err) ) );
  FD_TEST( !strcmp( err, "Max amount of Pubkeys reached, only 256 allowed" ) );
}

/* A bank whose records arrive after its commitment advanced is served
   when they arrive, not dropped: the core owes the status until the
   bank seals. */

static void
test_defer_late_record( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .records_gate = 1 };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_txn_filter_t all = {0};

  ulong sz   = sub_filter_txn( req, "c", &all );
  sz        += sub_filter_slots( req+sz, "slc", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 1UL ); /* confirmed */
  ulong off1 = sub_open( tc, 1U, req, sz );

  sz         = sub_filter_txn( req, "f", &all );
  sz        += sub_filter_slots( req+sz, "slf", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off3 = sub_open( tc, 3U, req, sz );

  /* A block of one transaction whose record has not arrived, confirmed
     and then rooted in that state. */
  core_sysvars( 10UL, 10UL );
  core_slot_txns( 10UL, 500UL, 1UL );
  core_oc  ( 10UL );
  tc_service( tc );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* The record completes the bank, and the confirmed subscription is
     served the block and then its status. */
  core_txn_simple( 10UL, 10UL, 0UL, 0xA1U );
  tc_service( tc );
  off1 = expect_txn( tc, 1U, off1, 0xA1U, 10UL, 10UL, 0UL, "c" );
  off1 = expect_slot_update( tc, 1U, off1, 10UL, (int)geyser_SlotStatus_SLOT_CONFIRMED, 10L, "slc" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  core_root( 10UL );
  tc_service( tc );
  off3 = expect_txn( tc, 3U, off3, 0xA1U, 10UL, 10UL, 0UL, "f" );
  off3 = expect_slot_update( tc, 3U, off3, 10UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 10L, "slf" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  /* The next block is confirmed and rooted before its record arrives,
     so both subscriptions are served when it does, the confirmed one
     first. */
  core_sysvars( 11UL, 11UL );
  core_slot_txns( 11UL, 501UL, 1UL );
  core_oc  ( 11UL );
  core_root( 11UL );
  tc_service( tc );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  core_txn_simple( 11UL, 11UL, 0UL, 0xB1U );
  tc_service( tc );
  off1 = expect_txn( tc, 1U, off1, 0xB1U, 11UL, 11UL, 0UL, "c" );
  off1 = expect_slot_update( tc, 1U, off1, 11UL, (int)geyser_SlotStatus_SLOT_CONFIRMED, 11L, "slc" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  off3 = expect_txn( tc, 3U, off3, 0xB1U, 11UL, 11UL, 0UL, "f" );
  off3 = expect_slot_update( tc, 3U, off3, 11UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 11L, "slf" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  /* Nothing is claimed on a bank: the buffer holds everything a bank
     is served from. */
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  tc_close( tc );
  test_server_delete( server );
}

/* Accounts ***********************************************************/

/* test_write_version is how the geyser core orders the writes of one
   slot: the phase, then the position in the phase, then the position
   in the record. */

static ulong
test_write_version( ulong phase,
                    ulong index,
                    ulong sub ) {
  return ( phase<<60 ) | ( ( index & 0x0FFFFFFFFFFFFFUL )<<8 ) | ( sub & 0xFFUL );
}

/* core_txn_write reports one committed transaction that wrote one
   account: its commit record, naming the account, then the account
   record with the post state.  The transaction's addresses are two
   fixed ones and the account written, so a filter can name it.
   truncated reports an account record that names the account and
   carries no data, as when account reporting is off. */

static void
core_txn_write( ulong         bank_seq,
                ulong         slot,
                ulong         index,
                uint          sig_byte,
                uint          key_byte,
                ulong         lamports,
                uint          owner_byte,
                int           executable,
                uchar const * data,
                ulong         data_sz,
                int           truncated ) {
  static uchar payload[ FD_TXN_MTU ];
  static uchar keys[ 3 ][ 32 ];
  static ulong pre [ 3 ];
  static ulong post[ 3 ];
  static uchar writable[ 3 ] = { 1, 1, 1 };

  uchar key_bytes[ 3 ] = { 0x20, 0x21, (uchar)key_byte };
  ulong payload_sz = txn_payload( payload, sig_byte, key_bytes, 3UL );

  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( keys[ i ], key_bytes[ i ], 32UL );
    pre [ i ] = 100UL+i;
    post[ i ] = 100UL+i;
  }

  fd_event_internal_commit_touched_t touched[1] = {{
    .key_idx    = 2U,
    .executable = (uint)!!executable,
    .lamports   = lamports,
    .data_sz    = data_sz
  }};
  fd_memset( touched[ 0 ].owner, (int)owner_byte, 32UL );

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );
  ev->bank_seq             = bank_seq;
  ev->slot                 = slot;
  ev->index_in_slot        = index;
  ev->commit_index_in_slot = index;
  ev->accounts_included    = 1;
  ev->exec_err_idx         = UINT_MAX;
  ev->custom_err           = UINT_MAX;
  ev->rent_err_account_idx = UINT_MAX;
  ev->execution_fee        = 5000UL;
  ev->compute_units_consumed = 1000UL+index;
  ev->cost_units           = 720UL;
  ev->payload_cnt          = payload_sz;
  ev->acct_addr_cnt        = 3U;
  ev->keys_cnt             = 3UL;
  ev->pre_lamports_cnt     = 3UL;
  ev->post_lamports_cnt    = 3UL;
  ev->is_writable_cnt      = 3UL;
  ev->touched_cnt          = 1UL;
  fd_memset( ev->signature, (int)sig_byte, 64UL );

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])keys,
    .pre_lamports  = pre,
    .post_lamports = post,
    .is_writable   = writable,
    .logs          = NULL,
    .trace         = NULL,
    .trace_accts   = NULL,
    .trace_data    = NULL,
    .return_data   = NULL,
    .touched       = touched
  };
  FD_TEST( !fd_geyser_core_commit_record( g_core, &parts ) );

  /* The account record behind it. */
  fd_event_internal_runtime_write_touched_t wtouched[1] = {{
    .key_idx    = 0U,
    .executable = (uint)!!executable,
    .lamports   = lamports,
    .data_off   = 0UL,
    .data_sz    = truncated ? 0UL : data_sz
  }};
  fd_memset( wtouched[ 0 ].owner, (int)owner_byte, 32UL );

  fd_event_internal_runtime_write_t wev[1];
  fd_memset( wev, 0, sizeof(fd_event_internal_runtime_write_t) );
  wev->bank_seq             = bank_seq;
  wev->slot                 = slot;
  wev->phase                = 1U;
  fd_memcpy( wev->signature, ev->signature, 64UL );
  wev->commit_index_in_slot = index;
  wev->touched_idx          = 0U;
  wev->accounts_included    = !truncated;
  wev->keys_cnt             = 1UL;
  wev->touched_cnt          = 1UL;
  wev->account_data_cnt     = truncated ? 0UL : data_sz;

  fd_event_internal_runtime_write_parts_t wparts = {
    .prefix       = wev,
    .keys         = (uchar const (*)[ 32UL ])(keys+2),
    .touched      = wtouched,
    .account_data = data
  };
  FD_TEST( !fd_geyser_core_runtime_write_record( g_core, &wparts ) );
}

/* core_write_acct reports one account the runtime wrote outside a
   transaction, which is a write with no signature. */

static void
core_write_acct( ulong         bank_seq,
                 ulong         slot,
                 uint          phase,
                 ulong         write_seq,
                 uint          key_byte,
                 ulong         lamports,
                 uint          owner_byte,
                 uchar const * data,
                 ulong         data_sz ) {
  static uchar acct_data[ 1024 ];
  uchar        keys[ 1 ][ 32 ];

  fd_memset( keys[ 0 ], (int)key_byte, 32UL );
  FD_TEST( data_sz<=sizeof(acct_data) );
  if( data_sz ) fd_memcpy( acct_data, data, data_sz );

  fd_event_internal_runtime_write_touched_t touched[1] = {{
    .key_idx    = 0U,
    .executable = 0U,
    .lamports   = lamports,
    .data_off   = 0UL,
    .data_sz    = data_sz
  }};
  fd_memset( touched[ 0 ].owner, (int)owner_byte, 32UL );

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );
  ev->bank_seq          = bank_seq;
  ev->slot              = slot;
  ev->phase             = phase;
  ev->accounts_included = 1;
  ev->write_seq         = write_seq;
  ev->keys_cnt          = 1UL;
  ev->touched_cnt       = 1UL;
  ev->account_data_cnt  = data_sz;

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = acct_data
  };
  FD_TEST( !fd_geyser_core_runtime_write_record( g_core, &parts ) );
}

/* core_drop asks for a bank's reference back, as replay does when its
   bank pool is full. */

static void
core_drop( ulong bank_idx ) {
  fd_geyser_core_drop_bank_ref( g_core, bank_idx, g_seq++ );
}

/* Request builders ***************************************************/

struct sub_acct_filter {
  uchar const * account;      /* one byte per address, repeated to 32 */
  ulong         account_cnt;
  uchar const * owner;
  ulong         owner_cnt;
  int           has_txn_sig;
  int           txn_sig;
  int           has_datasize;
  ulong         datasize;
  int           token_state;
  uint          lamports_cmp; /* 0 none, else the field of the cmp oneof */
  ulong         lamports_val;
  uint          memcmp_kind;  /* 0 none, 2 bytes, 3 base58, 4 base64 */
  ulong         memcmp_off;
  uchar const * memcmp_data;
  ulong         memcmp_data_sz;
};

typedef struct sub_acct_filter sub_acct_filter_t;

static ulong
sub_filter_accounts( uchar *                   p,
                     char const *              name,
                     sub_acct_filter_t const * f ) {
  uchar value[ 2048 ];
  ulong value_sz = 0UL;

  struct { uchar const * list; ulong cnt; uint field; } const lists[ 2 ] = {
    { f->account, f->account_cnt, 2U },
    { f->owner,   f->owner_cnt,   3U }
  };
  for( ulong l=0UL; l<2UL; l++ ) {
    for( ulong i=0UL; i<lists[ l ].cnt; i++ ) {
      uchar key[ 32 ];
      char  b58[ 64 ];
      fd_memset( key, lists[ l ].list[ i ], 32UL );
      fd_base58_encode_32( key, NULL, b58 );
      value_sz += pb_bytes_field( value+value_sz, lists[ l ].field, b58, strlen( b58 ) );
    }
  }

  /* Each state predicate is one element of the filters list. */
  if( f->has_datasize ) {
    uchar one[ 32 ];
    ulong one_sz = pb_varint_field( one, 2U, f->datasize );
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  if( f->token_state ) {
    uchar one[ 32 ];
    ulong one_sz = pb_varint_field( one, 3U, 1UL );
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  if( f->lamports_cmp ) {
    uchar cmp[ 32 ];
    ulong cmp_sz = pb_varint_field( cmp, f->lamports_cmp, f->lamports_val );
    uchar one[ 64 ];
    ulong one_sz = pb_bytes_field( one, 4U, cmp, cmp_sz );
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  if( f->memcmp_kind ) {
    uchar mc[ 512 ];
    ulong mc_sz = 0UL;
    if( f->memcmp_off ) mc_sz += pb_varint_field( mc+mc_sz, 1U, f->memcmp_off );
    if( f->memcmp_kind==2U ) {
      mc_sz += pb_bytes_field( mc+mc_sz, 2U, f->memcmp_data, f->memcmp_data_sz );
    } else if( f->memcmp_kind==3U ) {
      char b58[ 64 ];
      FD_TEST( f->memcmp_data_sz==32UL );
      fd_base58_encode_32( f->memcmp_data, NULL, b58 );
      mc_sz += pb_bytes_field( mc+mc_sz, 3U, b58, strlen( b58 ) );
    } else {
      char b64[ 256 ];
      ulong b64_sz = fd_base64_encode( b64, f->memcmp_data, f->memcmp_data_sz );
      mc_sz += pb_bytes_field( mc+mc_sz, 4U, b64, b64_sz );
    }
    uchar one[ 576 ];
    ulong one_sz = pb_bytes_field( one, 1U, mc, mc_sz );
    value_sz += pb_bytes_field( value+value_sz, 4U, one, one_sz );
  }
  if( f->has_txn_sig ) value_sz += pb_varint_field( value+value_sz, 5U, (ulong)!!f->txn_sig );

  uchar entry[ 2304 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, name, strlen( name ) );
  if( value_sz ) entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );

  return pb_bytes_field( p, 1U /* accounts */, entry, entry_sz );
}

struct sub_blocks_filter {
  uchar const * include;
  ulong         include_cnt;
  int           has_include_txns;
  int           include_txns;
  int           include_accts;
  int           include_entries;
};

typedef struct sub_blocks_filter sub_blocks_filter_t;

static ulong
sub_filter_blocks( uchar *                     p,
                   char const *                name,
                   sub_blocks_filter_t const * f ) {
  uchar value[ 2048 ];
  ulong value_sz = 0UL;

  for( ulong i=0UL; i<f->include_cnt; i++ ) {
    uchar key[ 32 ];
    char  b58[ 64 ];
    fd_memset( key, f->include[ i ], 32UL );
    fd_base58_encode_32( key, NULL, b58 );
    value_sz += pb_bytes_field( value+value_sz, 1U, b58, strlen( b58 ) );
  }
  if( f->has_include_txns ) value_sz += pb_varint_field( value+value_sz, 2U, (ulong)!!f->include_txns );
  if( f->include_accts    ) value_sz += pb_varint_field( value+value_sz, 3U, 1UL );
  if( f->include_entries  ) value_sz += pb_varint_field( value+value_sz, 4U, 1UL );

  uchar entry[ 2304 ];
  ulong entry_sz = pb_bytes_field( entry, 1U, name, strlen( name ) );
  if( value_sz ) entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );

  return pb_bytes_field( p, 4U /* blocks */, entry, entry_sz );
}

/* sub_data_slice writes one accounts_data_slice element. */

static ulong
sub_data_slice( uchar * p,
                ulong   offset,
                ulong   length ) {
  uchar value[ 32 ];
  ulong value_sz = 0UL;
  if( offset ) value_sz += pb_varint_field( value+value_sz, 1U, offset );
  if( length ) value_sz += pb_varint_field( value+value_sz, 2U, length );
  return pb_bytes_field( p, 7U /* accounts_data_slice */, value, value_sz );
}

/* Reading account and block updates **********************************/

/* tb_filters collects the filter names an update carries. */

static ulong
tb_filters( uchar const * buf,
            ulong         sz,
            char          name[][ 64 ],
            ulong         max ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<max; i++ ) {
    uchar const * body;
    ulong         body_sz;
    if( !tb_field( buf, sz, 1U, i, NULL, &body, &body_sz ) ) break;
    FD_TEST( body_sz<64UL );
    fd_memcpy( name[ cnt ], body, body_sz );
    name[ cnt ][ body_sz ] = '\0';
    cnt++;
  }
  return cnt;
}

struct tb_acct {
  uchar const * pubkey;
  ulong         lamports;
  uchar const * owner;
  ulong         executable;
  ulong         rent_epoch;
  uchar const * data;
  ulong         data_sz;
  ulong         write_version;
  int           has_sig;
  uchar const * sig;
  ulong         slot;
  ulong         bank_id;
  int           is_startup;
};

typedef struct tb_acct tb_acct_t;

/* tb_acct_read reads the fields of a geyser.SubscribeUpdateAccount out
   of its body. */

static void
tb_acct_read( uchar const * body,
              ulong         body_sz,
              tb_acct_t *   out ) {
  fd_memset( out, 0, sizeof(tb_acct_t) );

  ulong         info_sz;
  uchar const * info = tb_sub( body, body_sz, 1U, &info_sz );

  ulong v;
  FD_TEST( tb_field( info, info_sz, 1U, 0UL, NULL, &out->pubkey, &v ) && v==32UL );
  if( tb_field( info, info_sz, 2U, 0UL, &v, NULL, NULL ) ) out->lamports = v;
  FD_TEST( tb_field( info, info_sz, 3U, 0UL, NULL, &out->owner, &v ) && v==32UL );
  if( tb_field( info, info_sz, 4U, 0UL, &v, NULL, NULL ) ) out->executable = v;
  FD_TEST( tb_field( info, info_sz, 5U, 0UL, &out->rent_epoch, NULL, NULL ) );
  if( tb_field( info, info_sz, 6U, 0UL, NULL, &out->data, &out->data_sz ) ) {}
  if( tb_field( info, info_sz, 7U, 0UL, &v, NULL, NULL ) ) out->write_version = v;
  out->has_sig = tb_field( info, info_sz, 8U, 0UL, NULL, &out->sig, &v );
  if( out->has_sig ) FD_TEST( v==64UL );

  if( tb_field( body, body_sz, 2U, 0UL, &v, NULL, NULL ) ) out->slot       = v;
  if( tb_field( body, body_sz, 3U, 0UL, &v, NULL, NULL ) ) out->is_startup = (int)v;
  if( tb_field( body, body_sz, 4U, 0UL, &v, NULL, NULL ) ) out->bank_id    = v;
}

/* acct_at reads the next update of a subscription as an account
   update, and returns the offset behind it. */

static ulong
acct_at( tc_t *         tc,
         uint           stream_id,
         ulong          off,
         tb_acct_t *    acct,
         char           names[][ 64 ],
         ulong *        name_cnt,
         uchar const ** raw,
         ulong *        raw_sz ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  if( FD_UNLIKELY( off>=s->data_sz ) ) FD_LOG_ERR(( "no update at offset %lu of %lu", off, s->data_sz ));
  ulong next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );

  ulong         body_sz;
  uchar const * body = tb_sub( msg, msg_sz, 2U /* account */, &body_sz );
  tb_acct_read( body, body_sz, acct );

  /* Every update carries the server's wall clock. */
  FD_TEST( tb_field( msg, msg_sz, 11U, 0UL, NULL, NULL, NULL ) );

  if( names && name_cnt ) *name_cnt = tb_filters( msg, msg_sz, names, 8UL );
  if( raw    ) *raw    = body;
  if( raw_sz ) *raw_sz = body_sz;
  return next;
}

/* expect_account checks the next update of a subscription against the
   state an account was left in. */

static ulong
expect_account( tc_t *        tc,
                uint          stream_id,
                ulong         off,
                uint          key_byte,
                ulong         slot,
                ulong         bank_id,
                ulong         lamports,
                uint          owner_byte,
                uchar const * data,
                ulong         data_sz,
                ulong         write_version,
                int           has_sig,
                uint          sig_byte,
                char const *  filter_name ) {
  tb_acct_t acct;
  char      names[ 8 ][ 64 ];
  ulong     name_cnt = 0UL;
  ulong     next     = acct_at( tc, stream_id, off, &acct, names, &name_cnt, NULL, NULL );

  uchar expect_key[ 32 ];
  fd_memset( expect_key, (int)key_byte, 32UL );
  FD_TEST( fd_memeq( acct.pubkey, expect_key, 32UL ) );

  uchar expect_owner[ 32 ];
  fd_memset( expect_owner, (int)owner_byte, 32UL );
  FD_TEST( fd_memeq( acct.owner, expect_owner, 32UL ) );

  FD_TEST( acct.lamports==lamports );
  FD_TEST( acct.rent_epoch==ULONG_MAX );
  FD_TEST( !acct.is_startup );
  FD_TEST( acct.slot==slot );
  FD_TEST( acct.bank_id==bank_id );
  FD_TEST( acct.write_version==write_version );
  FD_TEST( acct.data_sz==data_sz );
  if( data_sz ) FD_TEST( fd_memeq( acct.data, data, data_sz ) );
  FD_TEST( !!acct.has_sig==!!has_sig );
  if( has_sig ) FD_TEST( acct.sig[ 0 ]==(uchar)sig_byte );

  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], filter_name ) );
  return next;
}

struct tb_block {
  ulong slot;
  ulong bank_id;
  ulong executed_txn_cnt;
  ulong updated_acct_cnt;
  ulong entries_cnt;
  ulong txn_cnt;
  ulong acct_cnt;
};

typedef struct tb_block tb_block_t;

/* block_at reads the next update of a subscription as a block. */

static ulong
block_at( tc_t *        tc,
          uint          stream_id,
          ulong         off,
          tb_block_t *  blk,
          char          names[][ 64 ],
          ulong *       name_cnt,
          uchar const ** body_out,
          ulong *       body_sz_out ) {
  tc_stream_t * s = tc_stream( tc, stream_id );
  uchar         flag;
  uchar const * msg;
  ulong         msg_sz;
  if( FD_UNLIKELY( off>=s->data_sz ) ) FD_LOG_ERR(( "no update at offset %lu of %lu", off, s->data_sz ));
  ulong next = tc_msg_at( s, off, &flag, &msg, &msg_sz );
  FD_TEST( !flag );

  ulong         body_sz;
  uchar const * body = tb_sub( msg, msg_sz, 5U /* block */, &body_sz );

  fd_memset( blk, 0, sizeof(tb_block_t) );
  ulong v;
  if( tb_field( body, body_sz,  1U, 0UL, &v, NULL, NULL ) ) blk->slot             = v;
  if( tb_field( body, body_sz,  9U, 0UL, &v, NULL, NULL ) ) blk->executed_txn_cnt = v;
  if( tb_field( body, body_sz, 10U, 0UL, &v, NULL, NULL ) ) blk->updated_acct_cnt = v;
  if( tb_field( body, body_sz, 12U, 0UL, &v, NULL, NULL ) ) blk->entries_cnt      = v;
  if( tb_field( body, body_sz, 14U, 0UL, &v, NULL, NULL ) ) blk->bank_id          = v;

  while( tb_field( body, body_sz,  6U, blk->txn_cnt,  NULL, NULL, NULL ) ) blk->txn_cnt++;
  while( tb_field( body, body_sz, 11U, blk->acct_cnt, NULL, NULL, NULL ) ) blk->acct_cnt++;

  /* A block carries the rewards as an empty message, no entries and no
     block time. */
  FD_TEST( tb_field( body, body_sz, 3U, 0UL, NULL, NULL, NULL ) );
  FD_TEST( !tb_field( body, body_sz, 4U, 0UL, NULL, NULL, NULL ) );
  FD_TEST( !tb_field( body, body_sz, 13U, 0UL, NULL, NULL, NULL ) );

  if( names && name_cnt ) *name_cnt = tb_filters( msg, msg_sz, names, 8UL );
  if( body_out    ) *body_out    = body;
  if( body_sz_out ) *body_sz_out = body_sz;
  return next;
}

/* Accounts at processed, and the encoding shared by clients ***********/

static void
test_acct_processed( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};

  /* Two clients that slice the account data the same way, and one that
     slices it differently. */
  ulong sz   = sub_filter_accounts( req, "a", &all );
  ulong off1 = sub_open( tc, 1U, req, sz );
  ulong off3 = sub_open( tc, 3U, req, sz );

  sz        += sub_data_slice( req+sz, 1UL, 2UL );
  ulong off5 = sub_open( tc, 5U, req, sz );

  uchar data[ 8 ] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
  core_txn_write( 10UL, 10UL, 0UL, 0xA1U, 0x40U, 500UL, 0x60U, 0, data, sizeof(data), 0 );
  tc_service_all( tc );

  ulong wv = test_write_version( 1UL, 0UL, 0UL );

  uchar const * raw1;
  ulong         raw1_sz;
  tb_acct_t     acct;
  char          names[ 8 ][ 64 ];
  ulong         name_cnt;
  ulong         next1 = acct_at( tc, 1U, off1, &acct, names, &name_cnt, &raw1, &raw1_sz );
  FD_TEST( acct.lamports==500UL && acct.write_version==wv );
  FD_TEST( acct.data_sz==sizeof(data) && fd_memeq( acct.data, data, sizeof(data) ) );
  FD_TEST( acct.has_sig && acct.sig[ 0 ]==0xA1U );

  /* The second client sliced the data the same way, so the bytes of
     the account message are the ones the first client got. */
  uchar         raw3_buf[ 512 ];
  fd_memcpy( raw3_buf, raw1, raw1_sz );
  uchar const * raw3;
  ulong         raw3_sz;
  ulong next3 = acct_at( tc, 3U, off3, &acct, names, &name_cnt, &raw3, &raw3_sz );
  FD_TEST( raw3_sz==raw1_sz && fd_memeq( raw3, raw3_buf, raw1_sz ) );

  /* The third client asked for two bytes of the data, so its message
     is a different encoding. */
  ulong next5 = expect_account( tc, 5U, off5, 0x40U, 10UL, 10UL, 500UL, 0x60U,
                                data+1UL, 2UL, wv, 1, 0xA1U, "a" );

  FD_TEST( next1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( next3==tc_stream( tc, 3U )->data_sz );
  FD_TEST( next5==tc_stream( tc, 5U )->data_sz );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->acct_update_cnt==3UL );

  /* Nothing was read at a fork: a processed subscriber is served from
     the record. */
  FD_TEST( !g_acct_read_cnt );

  tc_close( tc );
  test_server_delete( server );
}

/* Every account filter predicate, positive and negative.  One
   subscription is replaced with each filter set in turn, which is what
   a request does (§2.3 of the design), and one bank's write is fed to
   each. */

static void
test_acct_filters( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* An SPL token account: 165 bytes whose state byte is initialized. */
  static uchar token[ 165 ];
  token[ 108 ] = 1;
  token[ 0   ] = 0x77;

  uchar const acct_list [ 1 ] = { 0x40 };
  uchar const other_list[ 1 ] = { 0x41 };
  uchar const owner_list[ 1 ] = { 0x60 };

  uchar mc32[ 32 ];
  fd_memset( mc32, 0x99, 32UL );

  struct {
    char const *      name;
    sub_acct_filter_t f;
    int               match;
  } const cases[] = {
    { "any",        { 0 },                                                                            1 },
    { "acct",       { .account = acct_list,  .account_cnt = 1UL },                                    1 },
    { "acct_no",    { .account = other_list, .account_cnt = 1UL },                                    0 },
    { "owner",      { .owner = owner_list, .owner_cnt = 1UL },                                        1 },
    { "owner_no",   { .owner = other_list, .owner_cnt = 1UL },                                        0 },
    { "size",       { .has_datasize = 1, .datasize = 165UL },                                         1 },
    { "size_no",    { .has_datasize = 1, .datasize = 164UL },                                         0 },
    { "token",      { .token_state = 1 },                                                             1 },
    { "lam_eq",     { .lamports_cmp = 1U, .lamports_val = 500UL },                                    1 },
    { "lam_eq_no",  { .lamports_cmp = 1U, .lamports_val = 501UL },                                    0 },
    { "lam_ne",     { .lamports_cmp = 2U, .lamports_val = 501UL },                                    1 },
    { "lam_ne_no",  { .lamports_cmp = 2U, .lamports_val = 500UL },                                    0 },
    { "lam_lt",     { .lamports_cmp = 3U, .lamports_val = 501UL },                                    1 },
    { "lam_lt_no",  { .lamports_cmp = 3U, .lamports_val = 500UL },                                    0 },
    { "lam_gt",     { .lamports_cmp = 4U, .lamports_val = 499UL },                                    1 },
    { "lam_gt_no",  { .lamports_cmp = 4U, .lamports_val = 500UL },                                    0 },
    { "sig",        { .has_txn_sig = 1, .txn_sig = 1 },                                               1 },
    { "sig_no",     { .has_txn_sig = 1, .txn_sig = 0 },                                               0 },
    { "mc_bytes",   { .memcmp_kind = 2U, .memcmp_off = 0UL, .memcmp_data = token, .memcmp_data_sz = 1UL }, 1 },
    { "mc_bytes_no",{ .memcmp_kind = 2U, .memcmp_off = 1UL, .memcmp_data = token, .memcmp_data_sz = 1UL }, 0 },
    { "mc_b58",     { .memcmp_kind = 3U, .memcmp_off = 8UL, .memcmp_data = mc32,  .memcmp_data_sz = 32UL }, 1 },
    { "mc_b58_no",  { .memcmp_kind = 3U, .memcmp_off = 9UL, .memcmp_data = mc32,  .memcmp_data_sz = 32UL }, 0 },
    { "mc_b64",     { .memcmp_kind = 4U, .memcmp_off = 8UL, .memcmp_data = mc32,  .memcmp_data_sz = 32UL }, 1 },
    { "mc_b64_no",  { .memcmp_kind = 4U, .memcmp_off = 7UL, .memcmp_data = mc32,  .memcmp_data_sz = 32UL }, 0 },
    { "two",        { .account = acct_list, .account_cnt = 1UL, .owner = owner_list, .owner_cnt = 1UL,
                      .has_datasize = 1, .datasize = 165UL },                                         1 },
    { "two_no",     { .account = acct_list, .account_cnt = 1UL, .owner = other_list, .owner_cnt = 1UL }, 0 }
  };

  /* The account the record writes: a token account state with the
     memcmp pattern at offset 8. */
  static uchar data[ 165 ];
  fd_memcpy( data, token, sizeof(token) );
  fd_memset( data+8UL, 0x99, 32UL );

  static uchar req[ 4096 ];
  ulong sz  = sub_filter_accounts( req, cases[ 0 ].name, &cases[ 0 ].f );
  ulong off = sub_open( tc, 1U, req, sz );

  ulong cnt = sizeof(cases)/sizeof(cases[0]);
  for( ulong i=0UL; i<cnt; i++ ) {
    if( i ) {
      sz = sub_filter_accounts( req, cases[ i ].name, &cases[ i ].f );
      tc_msg( tc, 1U, req, sz, 0 );
      tc_flush( tc );
      tc_service_all( tc );
      FD_TEST( off==tc_stream( tc, 1U )->data_sz );
    }

    core_txn_write( 10UL+i, 10UL+i, 0UL, 0xB0U, 0x40U, 500UL, 0x60U, 0, data, sizeof(data), 0 );
    tc_service_all( tc );

    tc_stream_t * s = tc_stream( tc, 1U );
    if( cases[ i ].match ) {
      if( FD_UNLIKELY( off==s->data_sz ) ) FD_LOG_ERR(( "filter %s did not match", cases[ i ].name ));
      off = expect_account( tc, 1U, off, 0x40U, 10UL+i, 10UL+i, 500UL, 0x60U,
                            data, sizeof(data), test_write_version( 1UL, 0UL, 0UL ), 1, 0xB0U,
                            cases[ i ].name );
      FD_TEST( off==s->data_sz );
    } else {
      if( FD_UNLIKELY( off!=s->data_sz ) ) FD_LOG_ERR(( "filter %s matched", cases[ i ].name ));
    }
  }

  tc_close( tc );
  test_server_delete( server );
}

/* A finalized subscriber is served one update per account the block
   wrote, with the state the bank's fork holds and the write version of
   the last write to it. */

static void
test_acct_finalized( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all );
  sz       += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off = sub_open( tc, 1U, req, sz );

  /* Three writes to one account in one bank, and one to another. */
  uchar data[ 4 ] = { 1, 2, 3, 4 };
  core_txn_write( 11UL, 11UL, 0UL, 0xC1U, 0x40U, 100UL, 0x60U, 0, data, 1UL, 0 );
  core_txn_write( 11UL, 11UL, 1UL, 0xC2U, 0x40U, 200UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 11UL, 11UL, 2UL, 0xC3U, 0x40U, 300UL, 0x60U, 0, data, 3UL, 0 );
  core_txn_write( 11UL, 11UL, 3UL, 0xC4U, 0x41U, 900UL, 0x60U, 0, data, 4UL, 0 );

  /* Nothing is claimed on the bank, so replay's reference is back as
     soon as the bank seals. */
  core_slot_txns( 11UL, 511UL, 4UL );
  tc_service_all( tc );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  core_oc  ( 11UL );
  core_root( 11UL );
  tc_service_all( tc );

  /* One update per account: the last write, with its version and
     signature. */
  off = expect_account( tc, 1U, off, 0x40U, 11UL, 11UL, 300UL, 0x60U, data, 3UL,
                        test_write_version( 1UL, 2UL, 0UL ), 1, 0xC3U, "a" );
  off = expect_account( tc, 1U, off, 0x41U, 11UL, 11UL, 900UL, 0x60U, data, 4UL,
                        test_write_version( 1UL, 3UL, 0UL ), 1, 0xC4U, "a" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  /* Nothing was read at the bank's fork. */
  FD_TEST( !g_acct_read_cnt );

  /* The bank was served, so the buffer forgot it. */
  FD_TEST( !fd_dragon_buf_bank( fd_dragon_rpc_buf( g_rpc ), 11UL ) );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  tc_close( tc );
  test_server_delete( server );
}

/* An account the block left as it found it is still an account the
   block wrote, and a filter that the last write no longer matches
   takes the account out. */

static void
test_acct_dedup( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];

  /* One client takes everything, one only accounts of 500 lamports. */
  sub_acct_filter_t all = {0};
  ulong sz   = sub_filter_accounts( req, "a", &all );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off1 = sub_open( tc, 1U, req, sz );

  sub_acct_filter_t rich = { .lamports_cmp = 1U, .lamports_val = 500UL };
  sz         = sub_filter_accounts( req, "r", &rich );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  uchar data[ 2 ] = { 7, 8 };

  /* Ten lamports in and ten lamports out: the account ends where it
     started and is still reported. */
  core_txn_write( 12UL, 12UL, 0UL, 0xD1U, 0x40U, 110UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 12UL, 12UL, 1UL, 0xD2U, 0x40U, 100UL, 0x60U, 0, data, 2UL, 0 );

  /* Matched the lamports filter on the first write, not on the last,
     so the entry is no longer that client's. */
  core_txn_write( 12UL, 12UL, 2UL, 0xD3U, 0x41U, 500UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 12UL, 12UL, 3UL, 0xD4U, 0x41U, 400UL, 0x60U, 0, data, 2UL, 0 );

  core_slot_txns( 12UL, 512UL, 4UL );
  core_oc  ( 12UL );
  core_root( 12UL );
  tc_service_all( tc );

  off1 = expect_account( tc, 1U, off1, 0x40U, 12UL, 12UL, 100UL, 0x60U, data, 2UL,
                         test_write_version( 1UL, 1UL, 0UL ), 1, 0xD2U, "a" );
  off1 = expect_account( tc, 1U, off1, 0x41U, 12UL, 12UL, 400UL, 0x60U, data, 2UL,
                         test_write_version( 1UL, 3UL, 0UL ), 1, 0xD4U, "a" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  /* The lamports client is served nothing: neither account ends at 500
     lamports. */
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A write the runtime made outside a transaction carries no
   signature, at processed and at finalized. */

static void
test_acct_runtime_write( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];

  /* The processed client asks for writes with no signature, the
     finalized one takes everything. */
  sub_acct_filter_t nosig = { .has_txn_sig = 1, .txn_sig = 0 };
  ulong sz   = sub_filter_accounts( req, "w", &nosig );
  ulong off1 = sub_open( tc, 1U, req, sz );

  sub_acct_filter_t all = {0};
  sz         = sub_filter_accounts( req, "a", &all );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  uchar data[ 3 ] = { 9, 9, 9 };
  core_write_acct( 13UL, 13UL, 0U, 0UL, 0x42U, 42UL, 0x61U, data, 3UL );
  tc_service_all( tc );

  off1 = expect_account( tc, 1U, off1, 0x42U, 13UL, 13UL, 42UL, 0x61U, data, 3UL,
                         test_write_version( 0UL, 0UL, 0UL ), 0, 0U, "w" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  core_slot_txns( 13UL, 513UL, 0UL );
  core_oc  ( 13UL );
  core_root( 13UL );
  tc_service_all( tc );

  off3 = expect_account( tc, 3U, off3, 0x42U, 13UL, 13UL, 42UL, 0x61U, data, 3UL,
                         test_write_version( 0UL, 0UL, 0UL ), 0, 0U, "a" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* No bank is ever claimed: a buffered subscriber is served from the
   buffer, so replay has its reference back as soon as the bank
   seals. */

static void
test_acct_claim( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];

  /* A finalized transaction subscriber */
  sub_txn_filter_t txns = {0};
  ulong sz  = sub_filter_txn( req, "t", &txns );
  sz       += pb_varint_field( req+sz, 6U, 2UL );
  ulong off = sub_open( tc, 1U, req, sz );

  core_txn_write( 14UL, 14UL, 0UL, 0xE1U, 0x40U, 100UL, 0x60U, 0, NULL, 0UL, 0 );
  core_slot_txns( 14UL, 514UL, 1UL );
  tc_service_all( tc );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  core_oc  ( 14UL );
  core_root( 14UL );
  tc_service_all( tc );
  FD_TEST( off<tc_stream( tc, 1U )->data_sz ); /* the transaction was served */
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  tc_close( tc );
  test_server_delete( server );
}

/* A bank whose reference replay takes back is gone: the buffer forgets
   it, its statuses go out without content, and the subscription that
   wanted the content is ended. */

static void
test_acct_drop_bank_ref( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all );
  sz       += pb_varint_field( req+sz, 6U, 2UL );
  ulong off = sub_open( tc, 1U, req, sz );

  uchar data[ 2 ] = { 3, 4 };
  core_txn_write( 15UL, 15UL, 0UL, 0xF1U, 0x40U, 100UL, 0x60U, 0, data, 2UL, 0 );
  core_slot_txns( 15UL, 515UL, 1UL );
  tc_service_all( tc );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );
  FD_TEST( fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) )==1UL );

  /* Replay wants the reference back, so the bank is gone and its
     entries with it. */
  core_drop( 15UL % TEST_BANK_IDX_MAX );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );
  FD_TEST( !fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) ) );

  core_oc  ( 15UL );
  core_root( 15UL );
  tc_service_all( tc );

  /* Nothing was delivered and nothing was read; the levels the bank
     reached are reported, and the subscription that wanted its
     content is ended. */
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );
  FD_TEST( !g_acct_read_cnt );
  FD_TEST( !strcmp( tc_stream( tc, 1U )->grpc_status, "13" ) );

  tc_close( tc );
  test_server_delete( server );
}

/* An account record without data names an account a transaction wrote
   without what it holds: nothing is served for it at any level, and
   the write is counted as skipped for each. */

static void
test_acct_truncated( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz   = sub_filter_accounts( req, "p", &all );
  ulong off1 = sub_open( tc, 1U, req, sz );

  sz         = sub_filter_accounts( req, "f", &all );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  uchar data[ 5 ] = { 5, 5, 5, 5, 5 };
  core_txn_write( 16UL, 16UL, 0UL, 0x11U, 0x40U, 700UL, 0x60U, 0, data, 5UL, 1 );
  core_slot_txns( 16UL, 516UL, 1UL );
  tc_service_all( tc );

  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->acct_skipped_cnt==2UL );

  core_oc  ( 16UL );
  core_root( 16UL );
  tc_service_all( tc );

  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A ring too small for the accounts of a bank has overwritten the
   bank's first entries by the time it is served, so the subscription
   that wanted them is ended. */

static void
test_acct_budget( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .buf_bytes = 16384UL };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all );
  sz       += pb_varint_field( req+sz, 6U, 2UL );
  ulong off = sub_open( tc, 1U, req, sz );

  /* Every write is a new account, so the entries lap the ring. */
  for( ulong i=0UL; i<256UL; i++ ) {
    core_txn_write( 17UL, 17UL, i, 0x21U, (uint)i, 100UL+i, 0x60U, 0, NULL, 0UL, 0 );
  }
  core_slot_txns( 17UL, 517UL, 4096UL );
  core_oc  ( 17UL );
  core_root( 17UL );
  tc_service_all( tc );

  FD_TEST( fd_dragon_buf_metrics( fd_dragon_rpc_buf( g_rpc ) )->overrun_cnt==1UL );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );
  FD_TEST( !strcmp( tc_stream( tc, 1U )->grpc_status, "13" ) );
  FD_TEST( !fd_geyser_core_ref_held_cnt( g_core ) );

  tc_close( tc );
  test_server_delete( server );
}

/* Blocks *************************************************************/

static void
test_blocks( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 1048576UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];

  /* A block of everything at finalized. */
  sub_blocks_filter_t whole = { .include_accts = 1 };
  ulong sz   = sub_filter_blocks( req, "b", &whole );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off1 = sub_open( tc, 1U, req, sz );

  /* A block of the transactions and accounts of one address only. */
  uchar const include[ 1 ] = { 0x41 };
  sub_blocks_filter_t one = { .include = include, .include_cnt = 1UL, .include_accts = 1 };
  sz         = sub_filter_blocks( req, "one", &one );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  /* A block with neither transactions nor accounts, at processed. */
  sub_blocks_filter_t bare = { .has_include_txns = 1, .include_txns = 0 };
  sz         = sub_filter_blocks( req, "bare", &bare );
  ulong off5 = sub_open( tc, 5U, req, sz );

  uchar data[ 2 ] = { 1, 2 };
  core_txn_write( 20UL, 20UL, 0UL, 0x31U, 0x40U, 100UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 20UL, 20UL, 1UL, 0x32U, 0x41U, 200UL, 0x60U, 0, data, 2UL, 0 );

  core_slot_txns( 20UL, 520UL, 2UL );
  tc_service_all( tc );

  /* The processed block goes out when the bank seals. */
  tb_block_t blk;
  char       names[ 8 ][ 64 ];
  ulong      name_cnt;
  ulong      next5 = block_at( tc, 5U, off5, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.slot==20UL && blk.bank_id==20UL );
  FD_TEST( blk.executed_txn_cnt==2UL );
  FD_TEST( blk.updated_acct_cnt==2UL );
  FD_TEST( !blk.txn_cnt && !blk.acct_cnt && !blk.entries_cnt );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "bare" ) );
  FD_TEST( next5==tc_stream( tc, 5U )->data_sz );

  /* Nothing at finalized yet. */
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  core_oc  ( 20UL );
  core_root( 20UL );
  tc_service_all( tc );

  ulong next1 = block_at( tc, 1U, off1, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.slot==20UL && blk.bank_id==20UL );
  FD_TEST( blk.txn_cnt==2UL );
  FD_TEST( blk.acct_cnt==2UL );
  FD_TEST( blk.updated_acct_cnt==2UL );
  FD_TEST( blk.executed_txn_cnt==2UL );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "b" ) );
  FD_TEST( next1==tc_stream( tc, 1U )->data_sz );

  /* The account set narrows the block to the one transaction that
     names the address and the one account it wrote, and the count of
     accounts the block updated stays the bank's. */
  ulong next3 = block_at( tc, 3U, off3, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.txn_cnt==1UL );
  FD_TEST( blk.acct_cnt==1UL );
  FD_TEST( blk.updated_acct_cnt==2UL );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "one" ) );
  FD_TEST( next3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A deferred subscription that asks for everything is served a sealed
   bank in one order: its accounts and its transactions, then the
   block, then the block summary, then the slot status. */

static void
test_defer_order( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 1048576UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t   accts = {0};
  sub_txn_filter_t    txns  = {0};
  sub_blocks_filter_t blks  = { .include_accts = 1 };
  ulong sz   = sub_filter_accounts   ( req,    "ac", &accts );
  sz        += sub_filter_txn        ( req+sz, "tx", &txns  );
  sz        += sub_filter_blocks     ( req+sz, "bl", &blks  );
  sz        += sub_filter_blocks_meta( req+sz, "bm" );
  sz        += sub_filter_slots      ( req+sz, "sl", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off  = sub_open( tc, 1U, req, sz );

  uchar data[ 2 ] = { 3, 4 };
  core_txn_write( 30UL, 30UL, 0UL, 0x71U, 0x72U, 300UL, 0x60U, 0, data, 2UL, 0 );
  core_slot_txns( 30UL, 530UL, 1UL );
  core_oc  ( 30UL );
  core_root( 30UL );
  tc_service_all( tc );

  /* The content in the order it arrived: the transaction, then the
     account it wrote. */
  off = expect_txn( tc, 1U, off, 0x71U, 30UL, 30UL, 0UL, "tx" );
  off = expect_account( tc, 1U, off, 0x72U, 30UL, 30UL, 300UL, 0x60U, data, 2UL,
                        test_write_version( 1UL, 0UL, 0UL ), 1, 0x71U, "ac" );

  tb_block_t blk;
  char       names[ 8 ][ 64 ];
  ulong      name_cnt;
  off = block_at( tc, 1U, off, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.slot==30UL && blk.bank_id==30UL );
  FD_TEST( blk.txn_cnt==1UL && blk.acct_cnt==1UL );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "bl" ) );

  off = expect_block_meta( tc, 1U, off, 30UL, 30UL, 1UL, "bm" );
  off = expect_slot_update( tc, 1U, off, 30UL, (int)geyser_SlotStatus_SLOT_FINALIZED,
                            30L, "sl" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* An update larger than what one message may be is dropped and
   counted, and the subscription survives: nothing about the size says
   the client is slow. */

static void
test_acct_oversize( void ) {
  /* A queue of the smallest size the server accepts, so that one
     account of a few hundred bytes is already too large. */
  test_server_opt_t opt = { .tx_ring_sz = 1024UL };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all );
  ulong off = sub_open( tc, 1U, req, sz );

  static uchar data[ 1024 ];
  fd_memset( data, 0x5A, sizeof(data) );
  core_txn_write( 30UL, 30UL, 0UL, 0x51U, 0x40U, 100UL, 0x60U, 0, data, sizeof(data), 0 );
  tc_service_all( tc );

  FD_TEST( off==tc_stream( tc, 1U )->data_sz );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->acct_oversize_cnt==1UL );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt );

  /* The subscription is still there, and an account that fits is
     served. */
  core_txn_write( 30UL, 30UL, 1UL, 0x52U, 0x41U, 200UL, 0x60U, 0, data, 8UL, 0 );
  tc_service_all( tc );
  off = expect_account( tc, 1U, off, 0x41U, 30UL, 30UL, 200UL, 0x60U, data, 8UL,
                        test_write_version( 1UL, 1UL, 0UL ), 1, 0x52U, "a" );
  FD_TEST( off==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* An account far larger than a subscriber's send queue is delivered
   whole: the transport takes it into a large send slot and drains it
   under flow control, rather than dropping it. */

static void
test_acct_large( void ) {
  /* The mainnet account bound, which is what the tile's default
     max_message_bytes is sized for. */
  ulong const acct_sz  = 10UL<<20;
  ulong const queue_sz =  4UL<<20;
  ulong const msg_max  = 12UL<<20;

  /* Buffers this size do not belong in the regions the other tests
     share. */
  ulong  smem_sz = 64UL<<20;
  ulong  rmem_sz = 64UL<<20;
  void * smem    = aligned_alloc( FD_GRPC_SERVER_ALIGN, smem_sz );
  void * rmem    = aligned_alloc( FD_DRAGON_RPC_ALIGN,  rmem_sz );
  uchar * data   = aligned_alloc( 128UL, acct_sz );
  uchar * rx     = aligned_alloc( 128UL, msg_max+(1UL<<20) );
  FD_TEST( smem && rmem && data && rx );
  for( ulong i=0UL; i<acct_sz; i++ ) data[ i ] = (uchar)( i*7UL + i/1021UL );

  test_server_opt_t opt = {
    .tx_ring_sz = queue_sz,
    .max_msg_sz         = msg_max,
    .msg_max_bytes      = msg_max,
    .max_stream_cnt     = 1UL,
    .server_mem         = smem, .server_mem_sz = smem_sz,
    .rpc_mem            = rmem, .rpc_mem_sz    = rmem_sz
  };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all );
  ulong off = sub_open( tc, 1U, req, sz );

  /* The stream keeps more than the shared pool holds */
  tc_stream_t * s = tc_stream( tc, 1U );
  fd_memcpy( rx, s->data, s->data_sz );
  s->data     = rx;
  s->data_cap = msg_max+(1UL<<20);

  core_txn_write( 40UL, 40UL, 0UL, 0x71U, 0x40U, 900UL, 0x60U, 0, data, acct_sz, 0 );
  tc_service_all( tc );

  /* The initial window is 64 KiB, so the update is still going out */
  FD_TEST( s->data_sz>off );
  FD_TEST( s->data_sz-off<=65535UL );
  FD_TEST( !fd_grpc_server_metrics( server )->tx_too_slow_ring_cnt );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->acct_oversize_cnt );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt );

  /* Opening the window delivers the rest of it */
  for( ulong i=0UL; i<64UL; i++ ) {
    tc_window_update( tc, 1U, 1U<<20 );
    tc_window_update( tc, 0U, 1U<<20 );
    tc_flush( tc );
    tc_service_all( tc );
    if( s->data_sz>=off+5UL+acct_sz ) break;
  }

  tb_acct_t acct;
  char      names[ 8 ][ 64 ];
  ulong     name_cnt;
  ulong     next = acct_at( tc, 1U, off, &acct, names, &name_cnt, NULL, NULL );
  FD_TEST( next==s->data_sz );
  FD_TEST( acct.lamports==900UL );
  FD_TEST( acct.data_sz==acct_sz );
  FD_TEST( fd_memeq( acct.data, data, acct_sz ) );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "a" ) );
  FD_TEST( fd_dragon_rpc_metrics( g_rpc )->acct_update_cnt==1UL );

  /* The slot went back to the pool once the message was out */
  FD_TEST( !fd_grpc_server_metrics( server )->tx_too_slow_refs_cnt );

  tc_close( tc );
  test_server_delete( server );
  free( smem ); free( rmem ); free( data ); free( rx );
}

/* A subscription that takes both accounts and transactions is not
   disconnected by one account too large for its queue: the account
   goes out through a large send slot and the transactions that follow
   go out behind it.  With no slot to be had, that one update is
   dropped and the subscription carries on. */

static void
test_acct_large_order( void ) {
  ulong const acct_sz  = 10UL<<20;
  ulong const queue_sz =  4UL<<20;
  ulong const msg_max  = 12UL<<20;

  ulong  smem_sz = 64UL<<20;
  ulong  rmem_sz = 64UL<<20;
  void * smem    = aligned_alloc( FD_GRPC_SERVER_ALIGN, smem_sz );
  void * rmem    = aligned_alloc( FD_DRAGON_RPC_ALIGN,  rmem_sz );
  uchar * data   = aligned_alloc( 128UL, acct_sz );
  ulong   rx_sz  = 3UL*msg_max;
  uchar * rx     = aligned_alloc( 128UL, rx_sz );
  FD_TEST( smem && rmem && data && rx );
  for( ulong i=0UL; i<acct_sz; i++ ) data[ i ] = (uchar)( i*3UL + i/1021UL );

  test_server_opt_t opt = {
    .tx_ring_sz = queue_sz,
    .max_msg_sz         = msg_max,
    .msg_max_bytes      = msg_max,
    .max_stream_cnt     = 1UL,
    .server_mem         = smem, .server_mem_sz = smem_sz,
    .rpc_mem            = rmem, .rpc_mem_sz    = rmem_sz
  };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* One subscription over both accounts and transactions */
  static uchar req[ 4096 ];
  sub_acct_filter_t all_acct = {0};
  sub_txn_filter_t  all_txn  = {0};
  ulong sz  = sub_filter_accounts( req, "a", &all_acct );
  /**/  sz += sub_filter_txn( req+sz, "t", &all_txn );
  ulong off = sub_open( tc, 1U, req, sz );

  tc_stream_t * s = tc_stream( tc, 1U );
  fd_memcpy( rx, s->data, s->data_sz );
  s->data     = rx;
  s->data_cap = rx_sz;

  /* The account that needs a slot, then two transactions behind it */
  core_txn_write( 50UL, 50UL, 0UL, 0x81U, 0x40U, 900UL, 0x60U, 0, data, acct_sz, 0 );
  core_txn_simple( 50UL, 50UL, 1UL, 0x82U );
  core_txn_simple( 50UL, 50UL, 2UL, 0x83U );
  tc_service_all( tc );

  FD_TEST( !fd_grpc_server_metrics( server )->tx_too_slow_ring_cnt );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt );

  for( ulong i=0UL; i<64UL; i++ ) {
    tc_window_update( tc, 1U, 1U<<20 );
    tc_window_update( tc, 0U, 1U<<20 );
    tc_flush( tc );
    tc_service_all( tc );
  }

  /* The account first, then the two transactions, in the order they
     were reported */
  tb_acct_t acct;
  char      names[ 8 ][ 64 ];
  ulong     name_cnt;
  off = expect_txn( tc, 1U, off, 0x81U, 50UL, 50UL, 0UL, "t" );
  off = acct_at( tc, 1U, off, &acct, names, &name_cnt, NULL, NULL );
  FD_TEST( acct.data_sz==acct_sz && fd_memeq( acct.data, data, acct_sz ) );
  off = expect_txn( tc, 1U, off, 0x82U, 50UL, 50UL, 1UL, "t" );
  off = expect_txn( tc, 1U, off, 0x83U, 50UL, 50UL, 2UL, "t" );
  FD_TEST( off==s->data_sz );

  /* A second large account needs no slot of its own: it is staged in
     the ring behind the first and goes out in order. */
  core_txn_write( 51UL, 51UL, 0UL, 0x84U, 0x41U, 901UL, 0x60U, 0, data, acct_sz, 0 );
  core_txn_write( 51UL, 51UL, 1UL, 0x85U, 0x42U, 902UL, 0x60U, 0, data, acct_sz, 0 );
  core_txn_simple( 51UL, 51UL, 2UL, 0x86U );
  tc_service_all( tc );

  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->lagged_close_cnt );
  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->acct_oversize_cnt );

  for( ulong i=0UL; i<64UL; i++ ) {
    tc_window_update( tc, 1U, 1U<<20 );
    tc_window_update( tc, 0U, 1U<<20 );
    tc_flush( tc );
    tc_service_all( tc );
  }
  off = expect_txn( tc, 1U, off, 0x84U, 51UL, 51UL, 0UL, "t" );
  off = acct_at( tc, 1U, off, &acct, names, &name_cnt, NULL, NULL );
  FD_TEST( acct.lamports==901UL );
  off = expect_txn( tc, 1U, off, 0x85U, 51UL, 51UL, 1UL, "t" );
  off = acct_at( tc, 1U, off, &acct, names, &name_cnt, NULL, NULL );
  FD_TEST( acct.lamports==902UL );
  off = expect_txn( tc, 1U, off, 0x86U, 51UL, 51UL, 2UL, "t" );
  FD_TEST( off==s->data_sz );
  FD_TEST( !tc_stream( tc, 1U )->end_stream ); /* the subscription is alive */

  tc_close( tc );
  test_server_delete( server );
  free( smem ); free( rmem ); free( data ); free( rx );
}

/* Two blocks filters that carry the accounts and an accounts
   subscription at the same level are all served from the same
   buffered entries, and nothing is read at the bank's fork. */

static void
test_blocks_one_read( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 1048576UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];

  /* One client takes the accounts of every bank at finalized and the
     whole block; another takes a block of one address. */
  sub_acct_filter_t   all   = {0};
  sub_blocks_filter_t whole = { .include_accts = 1 };
  ulong sz   = sub_filter_accounts( req, "a", &all );
  sz        += sub_filter_blocks( req+sz, "b", &whole );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off1 = sub_open( tc, 1U, req, sz );

  uchar const include[ 1 ] = { 0x41 };
  sub_blocks_filter_t one = { .include = include, .include_cnt = 1UL, .include_accts = 1 };
  sz         = sub_filter_blocks( req, "one", &one );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  uchar data[ 2 ] = { 1, 2 };
  core_txn_write( 21UL, 21UL, 0UL, 0x41U, 0x40U, 100UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 21UL, 21UL, 1UL, 0x42U, 0x41U, 200UL, 0x60U, 0, data, 2UL, 0 );
  core_txn_write( 21UL, 21UL, 2UL, 0x43U, 0x42U, 300UL, 0x60U, 0, data, 2UL, 0 );

  core_slot_txns( 21UL, 521UL, 3UL );
  core_oc  ( 21UL );
  g_acct_read_cnt = 0UL;
  core_root( 21UL );
  tc_service_all( tc );

  /* The bank was served and forgotten, and nothing was read at its
     fork: the blocks are built from the buffer. */
  FD_TEST( fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) )==0UL );
  FD_TEST( !g_acct_read_cnt );

  /* Each client got what it asked for. */
  tb_acct_t  acct;
  tb_block_t blk;
  char       names[ 8 ][ 64 ];
  ulong      name_cnt;
  for( ulong i=0UL; i<3UL; i++ ) {
    off1 = acct_at( tc, 1U, off1, &acct, names, &name_cnt, NULL, NULL );
    FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "a" ) );
  }
  off1 = block_at( tc, 1U, off1, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.txn_cnt==3UL && blk.acct_cnt==3UL && blk.updated_acct_cnt==3UL );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "b" ) );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  off3 = block_at( tc, 3U, off3, &blk, names, &name_cnt, NULL, NULL );
  FD_TEST( blk.txn_cnt==1UL && blk.acct_cnt==1UL && blk.updated_acct_cnt==3UL );
  FD_TEST( name_cnt==1UL && !strcmp( names[ 0 ], "one" ) );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A blocks subscription needs the store, so a server without it
   refuses one. */

static void
test_blocks_disabled( void ) {
  test_server_opt_t opt = { .tx_ring_sz = 262144UL, .no_deferred = 1 };
  fd_grpc_server_t * server = test_server_new_opt( &opt );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 512 ];
  sub_blocks_filter_t blocks = {0};
  ulong sz = sub_filter_blocks( req, "b", &blocks );

  req_opt_t ropt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 1U, &ropt );
  tc_msg( tc, 1U, req, sz, 0 );
  tc_flush( tc );

  tc_stream_t * s = tc_stream( tc, 1U );
  FD_TEST( !strcmp( s->grpc_status, "3" ) );
  FD_TEST( !strcmp( s->grpc_message, "blocks are not supported by this server" ) );

  tc_close( tc );
  test_server_delete( server );
}

/* The server holds a bounded number of blocks filters across all its
   subscriptions: a request past it is refused, and a subscription that
   replaces its own filters does not count them twice. */

static void
test_blocks_cap( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 1048576UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_blocks_filter_t whole = { .include_accts = 1 };
  ulong sz = 0UL;
  for( ulong i=0UL; i<6UL; i++ ) {
    char name[ 4 ] = { 'b', (char)( '0'+i ), 0, 0 };
    sz += sub_filter_blocks( req+sz, name, &whole );
  }
  ulong base = sz;
  sz += pb_varint_field( req+sz, 6U, 2UL );
  sub_open( tc, 1U, req, sz );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  /* Six held, three more is past the cap */
  sz = 0UL;
  for( ulong i=0UL; i<3UL; i++ ) {
    char name[ 4 ] = { 'c', (char)( '0'+i ), 0, 0 };
    sz += sub_filter_blocks( req+sz, name, &whole );
  }
  req_opt_t ropt = { .path = ROUTE( "Subscribe" ) };
  tc_request( tc, 3U, &ropt );
  tc_msg( tc, 3U, req, sz, 0 );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 3U )->grpc_status, "8" ) );
  FD_TEST( !strcmp( tc_stream( tc, 3U )->grpc_message, "max blocks subscription limit exceeded" ) );

  /* The first subscription replaces its six with eight */
  sz = base;
  for( ulong i=6UL; i<8UL; i++ ) {
    char name[ 4 ] = { 'b', (char)( '0'+i ), 0, 0 };
    sz += sub_filter_blocks( req+sz, name, &whole );
  }
  sz += pb_varint_field( req+sz, 6U, 2UL );
  tc_msg( tc, 1U, req, sz, 0 );
  tc_flush( tc );
  FD_TEST( !tc_stream( tc, 1U )->end_stream );

  /* Nine on their own can never be served */
  sz = 0UL;
  for( ulong i=0UL; i<9UL; i++ ) {
    char name[ 4 ] = { 'd', (char)( '0'+i ), 0, 0 };
    sz += sub_filter_blocks( req+sz, name, &whole );
  }
  tc_request( tc, 5U, &ropt );
  tc_msg( tc, 5U, req, sz, 0 );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 5U )->grpc_status, "3" ) );

  /* Closing the subscription frees its share */
  tc_frame( tc, FD_H2_FRAME_TYPE_RST_STREAM, 0U, 1U, "\0\0\0\0", 4UL );
  tc_flush( tc );
  sz = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) {
    char name[ 4 ] = { 'e', (char)( '0'+i ), 0, 0 };
    sz += sub_filter_blocks( req+sz, name, &whole );
  }
  sub_open( tc, 7U, req, sz );
  FD_TEST( !tc_stream( tc, 7U )->end_stream );

  tc_close( tc );
  test_server_delete( server );
}

/* test_filter_fuzz feeds the request decoder bytes that are shaped
   like a SubscribeRequest but filled at random, which is the shape a
   client controls end to end: the account filters carry base58 and
   base64 of arbitrary length, and their decoders are the layer's
   own. */

static void
test_filter_fuzz( void ) {
  fd_dragon_filter_set_t set[1];
  char                   err[ FD_DRAGON_ERR_MAX ];
  fd_rng_t               rng[1];
  fd_rng_new( rng, 0U, 0UL );

  static uchar buf[ 4096 ];
  for( ulong iter=0UL; iter<200000UL; iter++ ) {
    ulong sz = fd_rng_ulong_roll( rng, sizeof(buf) );
    for( ulong i=0UL; i<sz; i++ ) buf[ i ] = fd_rng_uchar( rng );

    /* Every third round starts from a well formed accounts filter and
       corrupts one byte of it, which reaches deeper into the
       decoders. */
    if( iter%3UL==0UL ) {
      uchar mc[ 256 ];
      ulong mc_sz = pb_varint_field( mc, 1U, fd_rng_ulong( rng ) );
      char  txt[ 200 ];
      ulong txt_sz = fd_rng_ulong_roll( rng, sizeof(txt) );
      for( ulong i=0UL; i<txt_sz; i++ ) txt[ i ] = (char)( 0x20+fd_rng_uchar( rng )%0x5FU );
      mc_sz += pb_bytes_field( mc+mc_sz, 2U+fd_rng_uint_roll( rng, 3U ), txt, txt_sz );

      uchar one[ 384 ];
      ulong one_sz = pb_bytes_field( one, 1U, mc, mc_sz );
      uchar value[ 512 ];
      ulong value_sz = pb_bytes_field( value, 4U, one, one_sz );
      uchar entry[ 640 ];
      ulong entry_sz = pb_bytes_field( entry, 1U, "f", 1UL );
      entry_sz += pb_bytes_field( entry+entry_sz, 2U, value, value_sz );
      sz = pb_bytes_field( buf, 1U+fd_rng_uint_roll( rng, 5U ), entry, entry_sz );
      if( iter%2UL ) buf[ fd_rng_ulong_roll( rng, sz ) ] ^= (uchar)( 1U<<fd_rng_uint_roll( rng, 8U ) );
    }

    ulong names_seen = 0UL;
    fd_dragon_filter_decode( set, g_limits, g_cuckoo, G_CUCKOO_ENTRY_MAX, &names_seen, buf, sz, err, sizeof(err) );
  }
}

/* An x-token that authenticated one call must not authenticate the
   next call to land on the same stream slot. */

static void
test_auth_slot_reuse( void ) {
  fd_grpc_server_t * server = test_server_new( "s3cret", 65536UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A field block with a valid token but no content-type is answered
     415 and never reaches the handler. */
  uchar block[ 256 ]; ulong o = 0UL;
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 );
  block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 );
  o += HDR_LIT( block+o, ":path", ROUTE( "GetVersion" ) );
  o += HDR_LIT( block+o, ":authority", "localhost" );
  o += HDR_LIT( block+o, "te", "trailers" );
  o += HDR_LIT( block+o, "x-token", "s3cret" );
  tc_frame( tc, FD_H2_FRAME_TYPE_HEADERS,
            FD_H2_FLAG_END_HEADERS|FD_H2_FLAG_END_STREAM, 1U, block, o );
  tc_flush( tc );
  FD_TEST( !strcmp( tc_stream( tc, 1U )->status, "415" ) );

  /* The next call on the same connection reuses the slot. */
  req_opt_t none = { .path = ROUTE( "GetVersion" ), .end_stream = 1 };
  tc_request( tc, 3U, &none );
  tc_flush( tc );
  tc_expect_trailers( tc, 3U, "16", "No valid auth token" );

  /* So does the first call of the next connection on that slot. */
  tc_close( tc );
  tc_open( tc, server, g_rpc );
  tc_request( tc, 1U, &none );
  tc_flush( tc );
  tc_expect_trailers( tc, 1U, "16", "No valid auth token" );

  tc_close( tc );
  test_server_delete( server );
}

/* A data slice whose offset and length sum past 2^64 selects nothing
   rather than copying from outside the account. */

static void
test_slice_wrap( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  sub_acct_filter_t all = {0};
  ulong sz   = sub_filter_accounts( req, "a", &all );
  sz        += sub_data_slice( req+sz, 8UL, ULONG_MAX-7UL );
  ulong off1 = sub_open( tc, 1U, req, sz );

  uchar data[ 8 ] = { 0,1,2,3,4,5,6,7 };
  core_txn_write( 10UL, 10UL, 0UL, 0xA1U, 0x40U, 500UL, 0x60U, 0, data, sizeof(data), 0 );
  tc_service_all( tc );

  tb_acct_t     acct;
  char          names[ 8 ][ 64 ];
  ulong         name_cnt;
  uchar const * raw;
  ulong         raw_sz;
  acct_at( tc, 1U, off1, &acct, names, &name_cnt, &raw, &raw_sz );
  FD_TEST( !acct.data_sz );

  tc_close( tc );
  test_server_delete( server );
}

/* A memcmp predicate whose offset and length sum past 2^64 matches
   nothing rather than reading before the account. */

static void
test_memcmp_wrap( void ) {
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  static uchar req[ 2048 ];
  static uchar mc[ 1 ] = { 0xAB };
  sub_acct_filter_t f = {0};
  f.memcmp_kind    = 2U;
  f.memcmp_off     = ULONG_MAX;
  f.memcmp_data    = mc;
  f.memcmp_data_sz = 1UL;
  ulong sz = sub_filter_accounts( req, "b", &f );
  sub_open( tc, 1U, req, sz );

  uchar data[ 8 ] = { 0,1,2,3,4,5,6,7 };
  core_txn_write( 10UL, 10UL, 0UL, 0xA1U, 0x40U, 500UL, 0x60U, 0, data, sizeof(data), 0 );
  tc_service_all( tc );

  FD_TEST( !fd_dragon_rpc_metrics( g_rpc )->acct_update_cnt );

  tc_close( tc );
  test_server_delete( server );
}

/* Filters at send **************************************************/

/* With the filters at send every transaction and account write is
   buffered whole, whoever is subscribed, and a subscription is served
   every bank the buffer holds, including one already in flight when
   it was installed, under the filters it has when the bank is served,
   with the account data sliced then. */

static void
test_send_mode( void ) {
  g_filter_at = FD_DRAGON_FILTER_AT_SEND;
  fd_grpc_server_t * server = test_server_new( NULL, 262144UL );
  tc_t * tc = g_tc;
  tc_open( tc, server, g_rpc );

  /* A transaction and its account write, before anyone subscribes. */
  uchar data[ 4 ] = { 1, 2, 3, 4 };
  core_txn_write( 60UL, 60UL, 0UL, 0xA1U, 0x40U, 100UL, 0x60U, 0, data, 4UL, 0 );
  FD_TEST( fd_dragon_buf_entry_cnt( fd_dragon_rpc_buf( g_rpc ) )==2UL );

  static uchar req[ 2048 ];
  sub_acct_filter_t all_acct = {0};
  sub_txn_filter_t  all_txn  = {0};
  ulong sz   = sub_filter_accounts( req, "a", &all_acct );
  sz        += sub_filter_txn( req+sz, "t", &all_txn );
  sz        += sub_filter_slots( req+sz, "sl", 1, 0 );
  sz        += pb_varint_field( req+sz, 6U, 2UL ); /* finalized */
  ulong off1 = sub_open( tc, 1U, req, sz );

  /* A second write to the same account, and a client that slices the
     data and takes only accounts of at least 150 lamports. */
  core_txn_write( 60UL, 60UL, 1UL, 0xA2U, 0x40U, 150UL, 0x60U, 0, data, 4UL, 0 );

  sub_acct_filter_t rich = { .lamports_cmp = 4U /* gt */, .lamports_val = 120UL };
  sz         = sub_filter_accounts( req, "r", &rich );
  sz        += sub_data_slice( req+sz, 1UL, 2UL );
  sz        += pb_varint_field( req+sz, 6U, 2UL );
  ulong off3 = sub_open( tc, 3U, req, sz );

  core_slot_txns( 60UL, 560UL, 2UL );
  core_oc  ( 60UL );
  core_root( 60UL );
  tc_service_all( tc );

  /* The first client is served the whole bank in arrival order, the
     account deduplicated to its last write; the second is served the
     slice of the last write, which passes its filter where the first
     did not. */
  off1 = expect_txn( tc, 1U, off1, 0xA1U, 60UL, 60UL, 0UL, "t" );
  off1 = expect_txn( tc, 1U, off1, 0xA2U, 60UL, 60UL, 1UL, "t" );
  off1 = expect_account( tc, 1U, off1, 0x40U, 60UL, 60UL, 150UL, 0x60U, data, 4UL,
                         test_write_version( 1UL, 1UL, 0UL ), 1, 0xA2U, "a" );
  off1 = expect_slot_update( tc, 1U, off1, 60UL, (int)geyser_SlotStatus_SLOT_FINALIZED, 60L, "sl" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  off3 = expect_account( tc, 3U, off3, 0x40U, 60UL, 60UL, 150UL, 0x60U, data+1, 2UL,
                         test_write_version( 1UL, 1UL, 0UL ), 1, 0xA2U, "r" );
  FD_TEST( off3==tc_stream( tc, 3U )->data_sz );

  /* Nothing was read at the fork, and the bank is forgotten. */
  FD_TEST( !g_acct_read_cnt );
  FD_TEST( !fd_dragon_buf_bank( fd_dragon_rpc_buf( g_rpc ), 60UL ) );

  /* A filter replaced while a bank is in flight applies to that bank
     when it is served. */
  core_txn_simple( 61UL, 61UL, 0UL, 0xB1U );
  sz  = sub_filter_txn( req, "t2", &all_txn );
  sz += pb_varint_field( req+sz, 6U, 2UL );
  tc_msg( tc, 1U, req, sz, 0 );
  tc_flush( tc );
  core_slot_txns( 61UL, 561UL, 1UL );
  core_root( 61UL );
  tc_service_all( tc );
  off1 = expect_txn( tc, 1U, off1, 0xB1U, 61UL, 61UL, 0UL, "t2" );
  FD_TEST( off1==tc_stream( tc, 1U )->data_sz );

  tc_close( tc );
  test_server_delete( server );
  g_filter_at = FD_DRAGON_FILTER_AT_INGEST;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_filter_decode();
  test_ping();
  test_get_version();
  test_health_check();
  test_health_watch();
  test_unary_slots();
  test_is_blockhash_valid();
  test_subscribe_slots();
  test_subscribe_slots_replace();
  test_replay_info();
  test_unimplemented();
  test_auth();
  test_auth_slot_reuse();
  test_subscribe_ping();
  test_subscribe_from_slot();
  test_subscribe_filters();
  test_subscribe_lagged();
  test_subscribe_lagged_no_reap();
  test_shutdown();
  test_txn_processed();
  test_txn_filters();
  test_txn_failed_err();
  test_txn_cuckoo();
  test_block_meta();
  test_defer_delivery();
  test_defer_levels();
  test_defer_filter_update();
  test_defer_slot_reuse();
  test_defer_incomplete();
  test_defer_late_record();
  test_defer_budget();
  test_defer_disabled();
  test_acct_processed();
  test_slice_wrap();
  test_memcmp_wrap();
  test_acct_filters();
  test_acct_finalized();
  test_acct_dedup();
  test_acct_runtime_write();
  test_acct_claim();
  test_acct_drop_bank_ref();
  test_acct_truncated();
  test_acct_budget();
  test_blocks();
  test_defer_order();
  test_acct_oversize();
  test_acct_large();
  test_acct_large_order();
  test_blocks_one_read();
  test_blocks_disabled();
  test_blocks_cap();
  test_filter_fuzz();
  test_send_mode();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
