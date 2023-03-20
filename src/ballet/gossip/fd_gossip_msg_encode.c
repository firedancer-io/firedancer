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

void *
fd_gossip_encode_msg( fd_bin_parse_ctx_t * ctx,
                      ulong              * data_out_sz ) {

  /* Defensive sanity checks to ensure that the parse context buffer is in a consistent 
     state. Failing these checks indicate a programming error such as a) forgetting
     to call fd_bin_parse_set_input_blob_size() to setup the next blob size to parse,
     b) calling fd_bin_parse_set_input_blob_size() with a parse blob size larger than
     the actual total slice itself.
     Because these are errors that should never occur without major programming errors, 
     we log the condition with the ERR loglevel, which also aborts the validator program. */
  if( FD_UNLIKELY( !fd_bin_parse_is_state_ok_to_begin_parse( ctx ) ) ) {
    FD_LOG_ERR(( "inconsistent parse context buffer state; likely a programming error (such as misuse of fd_bin_parse_set_input_blob_size() )" ));
  }

  fd_gossip_msg_t * msg = (fd_gossip_msg_t *)fd_bin_parse_get_cur_src( ctx );
  void * blob_out = fd_bin_parse_get_cur_dst( ctx );
  int encode_status = 0;

  switch( msg->msg_id ) {
  case FD_GOSSIP_MSG_ID_PULL_REQ:
    encode_status = fd_gossip_encode_pull_req_msg( ctx );
    break;

  case FD_GOSSIP_MSG_ID_PULL_RESP:
    encode_status = fd_gossip_encode_pull_resp_msg( ctx );
    break;

  case FD_GOSSIP_MSG_ID_PUSH:
    encode_status = fd_gossip_encode_push_msg( ctx );
    break;

  case FD_GOSSIP_MSG_ID_PRUNE:
    encode_status = fd_gossip_encode_prune_msg( ctx );
    break;

  case FD_GOSSIP_MSG_ID_PING:
    encode_status = fd_gossip_encode_ping_msg( ctx );
    break;

  case FD_GOSSIP_MSG_ID_PONG:
    encode_status = fd_gossip_encode_pong_msg( ctx );
    break;
  }

  if( FD_UNLIKELY( !encode_status ) ) {
    FD_LOG_WARNING(( "error serializing message" ));
    fd_bin_parse_update_state_encode_failed( ctx );
    return NULL;
  }

  fd_bin_parse_update_state_encode_succeeded( ctx );
  *data_out_sz = fd_bin_parse_bytes_written_during_this_parse( ctx );
  return blob_out;
}

int
fd_gossip_encode_pull_resp_msg( fd_bin_parse_ctx_t * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_pull_response_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be pong msg" ));
    return 0;
  }

  fd_gossip_pull_response_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PULL_RESP ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  /* write out pubkey */
  if( !fd_bin_parse_write_pubkey( ctx, &(msg->pubkey) ) ) {
    FD_LOG_WARNING(( "unable to serialize `pubkey` to output buffer" ));
    return 0;
  }

  /* serialize out the `values` CRDS vector */

  if( !fd_bin_parse_write_u64( ctx, msg->values.num_objs ) ) {
    FD_LOG_WARNING(( "error writing out CRDS vector size to blob" ));
    return 0;
  }

  uchar * in_buf = (void *)((uchar *)msg + msg->values.offset);
  uchar * ptr = in_buf;
  ulong in_buf_sz = fd_bin_parse_src_blob_size_remaining( ctx );
  ulong bytes_consumed = 0;

  ulong num_objs = msg->values.num_objs;
  for( ulong count = 0; count < num_objs; count++ ) {

    if( !fd_gossip_encode_crds_obj( ctx, SRC_CUR, SRC_BYTES_REMAINING, &bytes_consumed ) ) {
      FD_LOG_WARNING(( "error serializing out CRDS object" ));
      return 0;
    }

    ADVANCE_SRC_PTR( bytes_consumed );
  }

  return 1;
}

int
fd_gossip_encode_ping_msg( fd_bin_parse_ctx_t   * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_ping_msg_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be ping msg" ));
    return 0;
  }

  fd_gossip_ping_msg_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PING ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  /* write out pubkey */
  if( !fd_bin_parse_write_pubkey( ctx, &(msg->from) ) ) {
    FD_LOG_WARNING(( "unable to serialize `pubkey` to output buffer" ));
    return 0;
  }

  /* write out token */
  if( !fd_bin_parse_write_blob_of_size( ctx, &(msg->token), 32 ) ) {
    FD_LOG_WARNING(( "unable to serialize `token` to output buffer" ));
    return 0;
  }

  /* write out signature */
  if( !fd_bin_parse_write_blob_of_size( ctx, &(msg->signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to output buffer" ));
    return 0;
  }

  return 1;
}

int
fd_gossip_encode_pong_msg( fd_bin_parse_ctx_t * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_pong_msg_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be pong msg" ));
    return 0;
  }

  fd_gossip_pong_msg_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PONG ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  /* write out pubkey */
  if( !fd_bin_parse_write_pubkey( ctx, &(msg->from) ) ) {
    FD_LOG_WARNING(( "unable to serialize `pubkey` to output buffer" ));
    return 0;
  }

  /* write out hash */
  if( !fd_bin_parse_write_blob_of_size( ctx, &(msg->hash), 32 ) ) {
    FD_LOG_WARNING(( "unable to serialize `hash` to output buffer" ));
    return 0;
  }

  /* write out signature */
  if( !fd_bin_parse_write_blob_of_size( ctx, &(msg->signature), 64 ) ) {
    FD_LOG_WARNING(( "unable to serialize `signature` to output buffer" ));
    return 0;
  }

  return 1;
}

int
fd_gossip_encode_push_msg( fd_bin_parse_ctx_t * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_push_msg_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be pong msg" ));
    return 0;
  }

  fd_gossip_push_msg_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PUSH ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  /* write out pubkey */
  if( !fd_bin_parse_write_pubkey( ctx, &(msg->pubkey) ) ) {
    FD_LOG_WARNING(( "unable to serialize `pubkey` to output buffer" ));
    return 0;
  }

  /* serialize out the `values` CRDS vector */

  if( !fd_bin_parse_write_u64( ctx, msg->values.num_objs ) ) {
    FD_LOG_WARNING(( "error writing out CRDS vector size to blob" ));
    return 0;
  }

  uchar * in_buf = (void *)((uchar *)msg + msg->values.offset);
  uchar * ptr = in_buf;
  ulong in_buf_sz = fd_bin_parse_src_blob_size_remaining( ctx );
  ulong bytes_consumed = 0;

  ulong num_objs = msg->values.num_objs;
  for( ulong count = 0; count < num_objs; count++ ) {

    if( !fd_gossip_encode_crds_obj( ctx, SRC_CUR, SRC_BYTES_REMAINING, &bytes_consumed ) ) {
      FD_LOG_WARNING(( "error serializing out CRDS object" ));
      return 0;
    }

    ADVANCE_SRC_PTR( bytes_consumed );
  }

  return 1;
}

int
fd_gossip_encode_prune_msg( fd_bin_parse_ctx_t * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_prune_msg_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be prune msg" ));
    return 0;
  }

  fd_gossip_prune_msg_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PRUNE ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  /* write out pubkey */
  if( !fd_bin_parse_write_pubkey( ctx, &(msg->pubkey) ) ) {
    FD_LOG_WARNING(( "unable to serialize `pubkey` to output buffer" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey( ctx, &(msg->data.pubkey) ) ) {
    FD_LOG_WARNING(( "unable to serialize `data.pubkey` to output buffer" ));
    return 0;
  }

  /* serialize out the `prunes` pubkey vector */
  if( !fd_bin_parse_write_u64( ctx, msg->data.prunes.num_objs ) ) {
    FD_LOG_WARNING(( "unable to write `prunes` vector size to blob" ));
    return 0;
  }
  
  fd_pubkey_t *pubkey = (fd_pubkey_t *)((uchar *)msg + msg->data.prunes.offset);

  for( ulong count = 0; count < msg->data.prunes.num_objs; count++, pubkey++ ) {
    if( !fd_bin_parse_write_pubkey( ctx, pubkey ) ) {
      FD_LOG_WARNING(( "error writing `pubkey` in prunes vector out to blob" ));
      return 0;
    }
  }

  if( !fd_bin_parse_write_blob_of_size( ctx, &(msg->data.signature ), 64 ) ) {
    FD_LOG_WARNING(( "unable to write `signature` to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_pubkey( ctx, &(msg->data.destination) ) ) {
    FD_LOG_WARNING(( "error writing `destination` out to blob" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, msg->data.wallclock ) ) {
    FD_LOG_WARNING(( "error writing out `wallclock` to blob" ));
    return 0;
  }

  return 1;
}

int
fd_gossip_encode_pull_req_msg( fd_bin_parse_ctx_t * ctx ) {

  ulong src_sz_remaining = fd_bin_parse_total_src_size_remaining( ctx );
  if( FD_UNLIKELY( src_sz_remaining<sizeof( fd_gossip_pull_req_t ) ) ) {
    FD_LOG_WARNING(( "input struct too small to be pong msg" ));
    return 0;
  }

  fd_gossip_pull_req_t * msg = fd_bin_parse_get_cur_src( ctx );

  if( !fd_bin_parse_write_u32( ctx, FD_GOSSIP_MSG_ID_PULL_REQ ) ) {
    FD_LOG_WARNING(( "unable to encode `msg_id` to buffer" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, msg->crds_filter.bloom.keys.num_objs ) ) {
    FD_LOG_WARNING(( "error writing out `crds_filter.bloom.keys` vector length" ));
    return 0;
  }

  /* serialize out the `keys` u64 vector */

  uchar * in_buf = (void *)((uchar *)msg + msg->crds_filter.bloom.keys.offset);
  uchar * ptr = in_buf;
  ulong in_buf_sz = fd_bin_parse_src_blob_size_remaining( ctx );
  ulong bytes_consumed = 0;

  for( ulong count=0; count<msg->crds_filter.bloom.keys.num_objs; count++ ) {
    if( !fd_bin_parse_write_blob_of_size( ctx, SRC_CUR, 8 ) ) {
      FD_LOG_WARNING(( "error writing `crds_filter.bloom.keys` u64 vector out to blob" ));
      return 0;
    }
    ADVANCE_SRC_PTR( 8 );
  }

  if( !msg->crds_filter.bloom.bits.bits.num_objs ) {
    if( !fd_bin_parse_write_u8( ctx, 0 ) ) {
      FD_LOG_WARNING(( "error writing out Optional bloom vector tag" ));
      return 0;
    }
  } else {
      if( !fd_bin_parse_write_u8( ctx, 1 ) ) {
        FD_LOG_WARNING(( "error writing out Optional `bloom` vector tag" ));
        return 0;
      }

      if( !fd_bin_parse_write_u64( ctx, msg->crds_filter.bloom.bits.bits.num_objs ) ) {
        FD_LOG_WARNING(( "error writing out Optional `bloom` vector size" ));
        return 0;
      }

      ulong * value_ptr = (ulong *)((uchar *)msg + msg->crds_filter.bloom.bits.bits.offset);
      for( ulong count = 0; count<msg->crds_filter.bloom.bits.bits.num_objs; count++, value_ptr++ ) {
        if( !fd_bin_parse_write_u64( ctx, *value_ptr ) ) {
          FD_LOG_WARNING(( "error writing out `bloom` u64 bitvec" ));
          return 0;
        }
      }
  }

  if( !fd_bin_parse_write_u64( ctx, msg->crds_filter.bloom.bits.len ) ) {
    FD_LOG_WARNING(( "error writing out `bloom` len" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, msg->crds_filter.bloom.num_bits_set ) ) {
    FD_LOG_WARNING(( "error writing out `bloom.num_bits_set`" ));
    return 0;
  }

  if( !fd_bin_parse_write_u64( ctx, msg->crds_filter.mask ) ) {
    FD_LOG_WARNING(( "error writing out `crds_filter.mask`" ));
    return 0;
  }

  if( !fd_bin_parse_write_u32( ctx, msg->crds_filter.mask_bits ) ) {
    FD_LOG_WARNING(( "error writing out `crds_filter.mask_bits`" ));
    return 0;
  }

  in_buf = (void *)((uchar *)msg + msg->value.offset);
  ptr = in_buf;
  in_buf_sz = fd_bin_parse_src_blob_size_remaining( ctx );
  bytes_consumed = 0;
  
  if( !fd_gossip_encode_crds_obj( ctx, SRC_CUR, SRC_BYTES_REMAINING, &bytes_consumed ) ) {
    FD_LOG_WARNING(( "error serializing out CRDS object" ));
    return 0;
  }

  ADVANCE_SRC_PTR( bytes_consumed );
  return 1;
}
