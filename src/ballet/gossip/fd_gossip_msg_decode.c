#include "fd_gossip_msg.h"
#include "fd_gossip_validation.h"
#include "../../util/binparse/fd_bin_parse.h"
#include "../../util/binparse/fd_slice.h"
#include "fd_gossip_crds.h"
#include "fd_gossip_vector_utils.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

fd_gossip_msg_t *
fd_gossip_parse_msg( fd_bin_parse_ctx_t * ctx ) {

  /* Ensure the input payload is not larger than MTU (1232), because this shouldn't be possible. */
  if( FD_UNLIKELY( fd_bin_parse_input_blob_size( ctx )>FD_GOSSIP_MTU ) ) {
    FD_LOG_WARNING(( "message longer than MTU; programming error, since networking code should not allow this." ));
    return 0;
  }

  uint msg_id;
  if( !fd_bin_parse_read_u32( ctx, &msg_id ) ) {
    FD_LOG_WARNING(( "failed to read `msg_id` from slice" ));
    return NULL;
  }

  void * msg_out = fd_bin_parse_get_cur_dst( ctx );
  ulong dst_sz_remaining = fd_bin_parse_dst_size_remaining( ctx );

  int parse_status = 0;
  ulong data_out_sz = 0;

  switch( msg_id ) {
  case FD_GOSSIP_MSG_ID_PULL_REQ:
    parse_status = fd_gossip_parse_pull_request_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  case FD_GOSSIP_MSG_ID_PULL_RESP:
    parse_status = fd_gossip_parse_pull_response_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  case FD_GOSSIP_MSG_ID_PUSH:
    parse_status = fd_gossip_parse_push_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  case FD_GOSSIP_MSG_ID_PRUNE:
    parse_status = fd_gossip_parse_prune_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  case FD_GOSSIP_MSG_ID_PING:
    parse_status = fd_gossip_parse_ping_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  case FD_GOSSIP_MSG_ID_PONG:
    parse_status = fd_gossip_parse_pong_msg( ctx, msg_out, dst_sz_remaining, &data_out_sz );
    break;

  default:
    FD_LOG_WARNING(( "invalid gossip message type" ));
    break;
  }

  if( !parse_status ) {
    FD_LOG_WARNING(( "error parsing gossip msg" ));
    fd_bin_parse_update_state_failed( ctx );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_bin_parse_was_entire_input_blob_consumed( ctx ) ) ) {
    FD_LOG_WARNING(( "entire input blob was not consumed during parsing" ));
    fd_bin_parse_update_state_failed( ctx );
    return NULL;
  }

  fd_bin_parse_update_state_succeeded( ctx, data_out_sz );
  return (fd_gossip_msg_t *)msg_out;
}

int
fd_gossip_parse_pull_request_msg( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      ) {
  FD_LOG_DEBUG(( "parsing pull req msg" ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_pull_req_t ) ) ) {
    return 0;
  }
  
  fd_gossip_pull_req_t * msg = (fd_gossip_pull_req_t *)out_buf;
  msg->msg_id = FD_GOSSIP_MSG_ID_PULL_REQ;

  uchar *ptr = (uchar *)out_buf + sizeof( fd_gossip_pull_req_t );

  /* 1. deserialize CRDS filter */
  /* 1a. deserialize bloom */
  ulong nelems = 0;
  if( !fd_bin_parse_decode_vector( ctx, 8, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error decoding u64 vector" ));
    return 0;
  }

  /* setup vector struct for this data */
  msg->crds_filter.bloom.keys.num_objs = nelems;
  msg->crds_filter.bloom.keys.offset = CUR_DATA_OFFSET;

  ADVANCE_DST_PTR( nelems*8 );

  /* deserialize bit vec */
  if( !fd_bin_parse_decode_option_vector( ctx, 8, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error decoding option vector for bitvec64" ));
    return 0;
  }

  /* this is an optional vector; no data in this case. */
  if( nelems==0 ) {
    msg->crds_filter.bloom.bits.bits.num_objs = 0;
    msg->crds_filter.bloom.bits.bits.offset = 0;
  } else {
    /* setup vector struct for this data */
    msg->crds_filter.bloom.bits.bits.num_objs = nelems;
    msg->crds_filter.bloom.bits.bits.offset = CUR_DATA_OFFSET;
    ADVANCE_DST_PTR( nelems * 8);
  }

  if( !fd_bin_parse_read_u64( ctx, &(msg->crds_filter.bloom.bits.len) ) ) {
    FD_LOG_WARNING(( "error parsing bloom bitvec `Len`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(msg->crds_filter.bloom.num_bits_set) ) ) {
    FD_LOG_WARNING(( "error parsing bloom `num_bits_set`" ));
    return 0;
  }

  /* 1b. deserialize mask */
  if( !fd_bin_parse_read_u64( ctx, &(msg->crds_filter.mask) ) ) {
    FD_LOG_WARNING(( "error decoding CRDS filter `mask`" ));
    return 0;
  }

  /* 1c. deserialize mask_bits */
  if( !fd_bin_parse_read_u32( ctx, &(msg->crds_filter.mask_bits) ) ) {
    FD_LOG_WARNING(( "error decoding CRDS filter `mask_bits`" ));
    return 0;
  }

  /* 2. deserialize CRDS object */
  ulong crds_obj_sz = 0;
  if( !fd_gossip_parse_crds_obj( ctx, DST_CUR, DST_BYTES_REMAINING, &crds_obj_sz ) ) {
    FD_LOG_WARNING(( "error parsing CRDS object" ));
    return 0;
  }

  msg->value.num_objs = 1;
  msg->value.offset = CUR_DATA_OFFSET;
  ADVANCE_DST_PTR( crds_obj_sz );

  *obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_pull_response_msg( fd_bin_parse_ctx_t * ctx,
                                   void               * out_buf,
                                   ulong                out_buf_sz,
                                   ulong              * obj_sz      ) {

  FD_LOG_DEBUG(( "parsing pull resp msg " ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_pull_response_t ) ) ) {
    return 0;
  }
  
  fd_gossip_pull_response_t * msg = (fd_gossip_pull_response_t *)out_buf;
  msg->msg_id = FD_GOSSIP_MSG_ID_PULL_RESP;

  /* pubkey */
  if( !fd_bin_parse_read_pubkey( ctx, &(msg->pubkey) ) ) {
    FD_LOG_WARNING(( "failed to parse `pubkey`" ));
    return 0;
  }

  ulong num_values = 0;
  if( !fd_bin_parse_read_u64( ctx, &num_values ) ) {
    FD_LOG_WARNING(( "error parsing num_values (CRDS) "));
    return 0;
  }

  /* TODO(smcio): although the boundedness of the logic below will ultimately kicks out 
     overly large `num_values` u64 vector sizes, it might still be worth logging such
     anomalies case in the interests of completeness/debugging purposes/audit.
     If so, determine an upper limit upon which to trigger a log event. */

  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_pull_response_t );
  ulong crds_obj_sz = 0;
  msg->values.num_objs = 0;

  for( ulong count = 0; count<num_values; count++ ) {
    if( !fd_gossip_parse_crds_obj( ctx, DST_CUR, DST_BYTES_REMAINING, &crds_obj_sz ) ) {
      FD_LOG_WARNING(( "error parsing CRDS object" ));
      return 0;
    }

    /* If this is the first CRDS object in the 'vector', put the offset
       of it into the CRDS vector descriptor.
       using this offset and the number of CRDS objects we have, we're able
       to walk through all of the objects in sequence. */
    if( count==0 ) {
      msg->values.offset = CUR_DATA_OFFSET;
    }

    msg->values.num_objs++;
    ADVANCE_DST_PTR( crds_obj_sz );
  }

  *obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_prune_msg( fd_bin_parse_ctx_t * ctx,
                           void               * out_buf,
                           ulong                out_buf_sz,
                           ulong              * obj_sz      ) {

  FD_LOG_DEBUG(( "parsing prune msg " ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_prune_msg_t ) ) ) {
    return 0;
  }

  fd_gossip_prune_msg_t * msg = (fd_gossip_prune_msg_t *)out_buf;
  msg->msg_id = FD_GOSSIP_MSG_ID_PRUNE;

  if( !fd_bin_parse_read_pubkey( ctx, &(msg->pubkey ) ) ) {
    FD_LOG_WARNING(( "error reading `pubkey`" ));
    return 0;
  }

  if( !fd_bin_parse_read_pubkey( ctx, &(msg->data.pubkey ) ) ) {
    FD_LOG_WARNING(( "error reading PruneData `pubkey`" ));
    return 0;
  }

  if( memcmp( msg->pubkey.pubkey, msg->data.pubkey.pubkey, 32 ) ) {
    FD_LOG_WARNING(( "pubkeys in prune message do not match" ));
    return 0;
  }
  
  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_prune_msg_t );
  ulong nelems = 0;

  /* parse `prunes` - vec<Pubkey> */
  if( !fd_bin_parse_decode_vector( ctx, 32, DST_CUR, DST_BYTES_REMAINING, &nelems ) ) {
    FD_LOG_WARNING(( "error parsing PruneData `prunes` vector" ));
    return 0;
  }

  /* setup vector struct for this data */
  msg->data.prunes.num_objs = nelems;
  msg->data.prunes.offset = CUR_DATA_OFFSET;

  ADVANCE_DST_PTR( nelems*32 );

  if( !fd_bin_parse_read_blob_of_size( ctx, 64, &(msg->data.signature) ) ) {
    FD_LOG_WARNING(( "failed to parse `signature`" ));
    return 0;
  }

  if( !fd_bin_parse_read_pubkey( ctx, &(msg->data.destination ) ) ) {
    FD_LOG_WARNING(( "error reading PruneData `destination`" ));
    return 0;
  }

  if( !fd_bin_parse_read_u64( ctx, &(msg->data.wallclock ) ) ) {
    FD_LOG_WARNING(( "error reading PruneData `wallclock`" ));
    return 0;
  }

  CHECK_WALLCLOCK( msg->data.wallclock );
  
  *obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_push_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      ) {
  
  FD_LOG_DEBUG(( "parsing push msg " ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_push_msg_t ) ) ) {
    return 0;
  }
  
  fd_gossip_push_msg_t * msg = (fd_gossip_push_msg_t *)out_buf;
  msg->msg_id = FD_GOSSIP_MSG_ID_PUSH;

  /* pubkey */
  if( !fd_bin_parse_read_pubkey( ctx, &(msg->pubkey) ) ) {
    FD_LOG_WARNING(( "failed to parse `pubkey`" ));
    return 0;
  }

  ulong num_values = 0;
  if( !fd_bin_parse_read_u64( ctx, &num_values ) ) {
    FD_LOG_WARNING(( "error parsing num_values "));
    return 0;
  }

  /* TODO(smcio): although the boundedness of the logic below will ultimately kicks out 
     overly large `num_values` u64 vector sizes, it might still be worth logging such
     anomalies case in the interests of completeness/debugging purposes/audit.
     If so, determine an upper limit upon which to trigger a log event. */
  
  uchar * ptr = (uchar *)out_buf + sizeof( fd_gossip_push_msg_t );
  ulong crds_obj_sz = 0;
  msg->values.num_objs = 0;

  for( ulong count = 0; count<num_values; count++ ) {
    if( !fd_gossip_parse_crds_obj( ctx, DST_CUR, DST_BYTES_REMAINING, &crds_obj_sz ) ) {
      FD_LOG_WARNING(( "error parsing CRDS object" ));
      return 0;
    }

    /* If this is the first CRDS object in the 'vector', put the offset
       of it into the CRDS vector descriptor. */
    if( count==0 ) {
      msg->values.offset = CUR_DATA_OFFSET;
    }

    msg->values.num_objs++;
    ADVANCE_DST_PTR( crds_obj_sz );
  }

  *obj_sz = TOTAL_DATA_OUT_SZ;
  return 1;
}

int
fd_gossip_parse_ping_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      ) {

  FD_LOG_DEBUG(( "parsing ping resp msg " ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_ping_msg_t) ) ) {
    return 0;
  }

  fd_gossip_ping_msg_t * msg = (fd_gossip_ping_msg_t *)out_buf;

  if( !fd_bin_parse_read_pubkey( ctx, &(msg->from) ) ) {
    FD_LOG_WARNING(( "failed to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_blob_of_size( ctx, 32, &(msg->token) ) ) {
    FD_LOG_WARNING(( "failed to parse `token`" ));
    return 0;
  }

  if( !fd_bin_parse_read_blob_of_size( ctx, 64, &(msg->signature) ) ) {
    FD_LOG_WARNING(( "failed to parse `signature`" ));
    return 0;
  }

  *obj_sz = sizeof( fd_gossip_msg_t );
  return 1;
}

int
fd_gossip_parse_pong_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      ) {

  FD_LOG_DEBUG(( "parsing pull pong msg " ));

  if( FD_UNLIKELY( out_buf_sz<sizeof( fd_gossip_pong_msg_t ) ) ) {
    return 0;
  }

  fd_gossip_pong_msg_t * msg = (fd_gossip_pong_msg_t *)out_buf;

  if( !fd_bin_parse_read_pubkey( ctx, &(msg->from) ) ) {
    FD_LOG_WARNING(( "failed to parse `from`" ));
    return 0;
  }

  if( !fd_bin_parse_read_blob_of_size( ctx, 32, &(msg->token) ) ) {
    FD_LOG_WARNING(( "failed to parse `token`" ));
    return 0;
  }

  if( !fd_bin_parse_read_blob_of_size( ctx, 64, &(msg->signature) ) ) {
    FD_LOG_WARNING(( "failed to parse `signature`" ));
    return 0;
  }

  *obj_sz = sizeof( fd_gossip_msg_t );
  return 1;
}

