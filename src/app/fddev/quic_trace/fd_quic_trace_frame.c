#include "fd_quic_trace.h"
#include "../../../waltz/quic/fd_quic_proto.c"
#include "../../../waltz/quic/templ/fd_quic_frame.h"

#define FRAME_STUB(name) \
  static ulong \
  fd_quic_trace_##name##_frame( \
      void *                     context FD_PARAM_UNUSED,    \
      fd_quic_##name##_frame_t * frame   FD_PARAM_UNUSED,    \
      uchar const *              p       FD_PARAM_UNUSED,    \
      ulong                      p_sz    FD_PARAM_UNUSED ) { \
    return 0UL; \
  }

static ulong
fd_quic_trace_padding_frame(
    void *                    context FD_PARAM_UNUSED,
    fd_quic_padding_frame_t * frame   FD_PARAM_UNUSED,
    uchar const *             p,
    ulong                     p_sz ) {
  ulong pad_sz;
  for( pad_sz=0UL; pad_sz<p_sz && p[0]==0; p++, pad_sz++ ) {}
  return pad_sz;
}

FRAME_STUB( ping )

static ulong
fd_quic_trace_ack_frame(
    void *                context FD_PARAM_UNUSED,
    fd_quic_ack_frame_t * frame,
    uchar const *         p,
    ulong                 p_sz ) {
  uchar const * p_begin = p;
  uchar const * p_end   = p + p_sz;

  for( ulong j=0UL; j < frame->ack_range_count; j++ ) {
    if( FD_UNLIKELY( p_end <= p ) ) return FD_QUIC_PARSE_FAIL;

    fd_quic_ack_range_frag_t ack_range[1];
    ulong rc = fd_quic_decode_ack_range_frag( ack_range, p, (ulong)( p_end - p ) );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;
    p += rc;
  }

  if( frame->type & 1U ) {
    fd_quic_ecn_counts_frag_t ecn_counts[1];
    ulong rc = fd_quic_decode_ecn_counts_frag( ecn_counts, p, (ulong)( p_end - p ) );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;
    p += rc;
  }

  return (ulong)( p - p_begin );
}

FRAME_STUB( reset_stream )
FRAME_STUB( stop_sending )

static ulong
fd_quic_trace_crypto_frame(
    void *                    context FD_PARAM_UNUSED,
    fd_quic_crypto_frame_t *  frame,
    uchar const *             p       FD_PARAM_UNUSED,
    ulong                     p_sz ) {
  if( FD_UNLIKELY( frame->length > p_sz ) ) return FD_QUIC_PARSE_FAIL;
  return frame->length;
}

FRAME_STUB( new_token )

static ulong
fd_quic_trace_stream_8_frame(
    fd_quic_trace_frame_ctx_t * context,
    fd_quic_stream_8_frame_t *  data,
    uchar const *               p FD_PARAM_UNUSED,
    ulong                       p_sz ) {
  printf( "ts=%20ld conn_id=%016lx src_ip=%08x src_port=%5hu pktnum=%8lu sid=%8lu off=   0 (i) len=%4lu (i) fin=%i\n",
          fd_log_wallclock(),
          context->conn_id,
          fd_uint_bswap( context->src_ip ),
          context->src_port,
          context->pkt_num,
          data->stream_id,
          p_sz,
          data->type&1 );
  return p_sz;
}

static ulong
fd_quic_trace_stream_a_frame(
    fd_quic_trace_frame_ctx_t * context,
    fd_quic_stream_a_frame_t *  data,
    uchar const *               p FD_PARAM_UNUSED,
    ulong                       p_sz ) {
  if( data->length > p_sz ) return FD_QUIC_PARSE_FAIL;
  printf( "ts=%20ld conn_id=%016lx src_ip=%08x src_port=%5hu pktnum=%8lu sid=%8lu off=   0 (i) len=%4lu (e) fin=%i\n",
          fd_log_wallclock(),
          context->conn_id,
          fd_uint_bswap( context->src_ip ),
          context->src_port,
          context->pkt_num,
          data->stream_id,
          data->length,
          data->type&1 );
  return data->length;
}

static ulong
fd_quic_trace_stream_c_frame(
    fd_quic_trace_frame_ctx_t * context,
    fd_quic_stream_c_frame_t *  data,
    uchar const *               p FD_PARAM_UNUSED,
    ulong                       p_sz ) {
  printf( "ts=%20ld conn_id=%016lx src_ip=%08x src_port=%5hu pktnum=%8lu sid=%8lu off=%4lu (e) len=%4lu (i) fin=%i\n",
          fd_log_wallclock(),
          context->conn_id,
          fd_uint_bswap( context->src_ip ),
          context->src_port,
          context->pkt_num,
          data->stream_id,
          data->offset,
          p_sz,
          data->type&1 );
  return p_sz;
}

static ulong
fd_quic_trace_stream_e_frame(
    fd_quic_trace_frame_ctx_t * context,
    fd_quic_stream_e_frame_t *  data,
    uchar const *               p    FD_PARAM_UNUSED,
    ulong                       p_sz FD_PARAM_UNUSED ) {
  if( data->length > p_sz ) return FD_QUIC_PARSE_FAIL;
  printf( "ts=%20ld conn_id=%016lx src_ip=%08x src_port=%5hu pktnum=%8lu sid=%8lu off=%4lu (e) len=%4lu (e) fin=%i\n",
          fd_log_wallclock(),
          context->conn_id,
          fd_uint_bswap( context->src_ip ),
          context->src_port,
          context->pkt_num,
          data->stream_id,
          data->offset,
          data->length,
          data->type&1 );
  return data->length;
}

FRAME_STUB( max_data )
FRAME_STUB( max_stream_data )
FRAME_STUB( max_streams )
FRAME_STUB( data_blocked )
FRAME_STUB( stream_data_blocked )
FRAME_STUB( streams_blocked )
FRAME_STUB( new_conn_id )
FRAME_STUB( retire_conn_id )
FRAME_STUB( path_challenge )
FRAME_STUB( path_response )

static ulong
fd_quic_trace_conn_close_0_frame(
    void *                         context FD_PARAM_UNUSED,
    fd_quic_conn_close_0_frame_t * frame,
    uchar const *                  p       FD_PARAM_UNUSED,
    ulong                          p_sz ) {
  if( FD_UNLIKELY( frame->reason_phrase_length > p_sz ) ) return FD_QUIC_PARSE_FAIL;
  return frame->reason_phrase_length;
}

static ulong
fd_quic_trace_conn_close_1_frame(
    void *                         context FD_PARAM_UNUSED,
    fd_quic_conn_close_1_frame_t * frame,
    uchar const *                  p       FD_PARAM_UNUSED,
    ulong                          p_sz ) {
  if( FD_UNLIKELY( frame->reason_phrase_length > p_sz ) ) return FD_QUIC_PARSE_FAIL;
  return frame->reason_phrase_length;
}

FRAME_STUB( handshake_done )

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                   \
  static ulong fd_quic_trace1_##NAME(                                     \
      void *        const ctx,                                            \
      uchar const * const buf,                                            \
      ulong         const buf_sz                                          \
  ) {                                                                     \
    fd_quic_##NAME##_t frame[1] = {0};                                    \
    uchar const *       p0 = buf;                                         \
    uchar const * const p1 = buf+buf_sz;                                  \
    ulong               rc;                                               \
                                                                          \
    rc = fd_quic_decode_##NAME( frame, p0, (ulong)(p1-p0) );              \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;\
    p0 += rc;                                                             \
                                                                          \
    rc = fd_quic_trace_##NAME( ctx, frame, p0, (ulong)(p1-p0) );          \
    if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;\
    p0 += rc;                                                             \
                                                                          \
    return (ulong)(p0-buf);                                               \
  }
#include "../../../waltz/quic/templ/fd_quic_dft.h"
#include "../../../waltz/quic/templ/fd_quic_frames_templ.h"
#include "../../../waltz/quic/templ/fd_quic_undefs.h"

static ulong
fd_quic_trace_frame( fd_quic_trace_frame_ctx_t * context,
                     uchar const *               data,
                     ulong                       data_sz ) {
  if( FD_UNLIKELY( data_sz<1UL ) ) return FD_QUIC_PARSE_FAIL;

  /* Frame ID is technically a varint but it's sufficient to look at the
     first byte. */
  uint id = data[0];
  if( !fd_quic_frame_type_allowed( context->pkt_type, id ) ) {
    FD_LOG_HEXDUMP_NOTICE(( "Frame not allowed", data, data_sz ));
    return FD_QUIC_PARSE_FAIL;
  }

  switch( id ) {
# define F(T,MID,NAME,...) \
  case T: return fd_quic_trace1_##NAME##_frame( context, data, data_sz );
FD_QUIC_FRAME_TYPES(F)
# undef F
  default:
    FD_LOG_HEXDUMP_NOTICE(( "Failed to parse frame", data, data_sz ));
    return FD_QUIC_PARSE_FAIL;
  }
}

void
fd_quic_trace_frames( fd_quic_trace_frame_ctx_t * context,
                      uchar const * data,
                      ulong         data_sz ) {
  while( data_sz ) {
    ulong ret = fd_quic_trace_frame( context, data, data_sz );
    if( ret==FD_QUIC_PARSE_FAIL ) return;
    if( FD_UNLIKELY( ret>data_sz ) ) return;
    data    += ret;
    data_sz -= ret;
  }
}
