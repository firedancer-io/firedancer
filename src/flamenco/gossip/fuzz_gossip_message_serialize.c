#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_gossip_message.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  return 0;
}

static fd_gossip_message_t msg;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size>1234UL ) ) return -1;
  if( FD_UNLIKELY( size<4UL   ) ) return -1;

  ushort ser_rand = (ushort)( (uint)data[ 0UL ] | ((uint)data[ 1UL ]<<8) );
  ulong  ser_buf_sz = (ulong)( ser_rand % 5U ? 1232UL : (ser_rand % 1233U) );

  int ok = fd_gossip_message_deserialize( &msg, data+2UL, size-2UL );
  if( FD_UNLIKELY( !ok ) ) {
    FD_FUZZ_MUST_BE_COVERED;
    return 0;
  }

  fd_gossip_value_t * values     = NULL;
  ulong               values_len = 0UL;

  if( msg.tag==FD_GOSSIP_MESSAGE_PUSH ) {
    values     = msg.push->values;
    values_len = msg.push->values_len;
  } else if( msg.tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) {
    values     = msg.pull_response->values;
    values_len = msg.pull_response->values_len;
  }

  for( ulong i=0UL; i<values_len; i++ ) {
    fd_gossip_value_t * v = &values[ i ];

    if( FD_LIKELY( v->tag!=FD_GOSSIP_VALUE_VOTE            &&
                   v->tag!=FD_GOSSIP_VALUE_NODE_INSTANCE   &&
                   v->tag!=FD_GOSSIP_VALUE_DUPLICATE_SHRED &&
                   v->tag!=FD_GOSSIP_VALUE_SNAPSHOT_HASHES &&
                   v->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) continue;

    uchar ser_buf[ 1232UL ];
    long ser_len = fd_gossip_value_serialize( v, ser_buf, ser_buf_sz );
    if( FD_UNLIKELY( ser_len<0L ) ) {
      FD_FUZZ_MUST_BE_COVERED;
      continue;
    }

    uchar wrapped[ 1232UL ];
    ulong hdr = 4UL+32UL+8UL;
    if( FD_UNLIKELY( hdr+(ulong)ser_len > sizeof(wrapped) ) ) continue;
    FD_STORE( uint,  wrapped, FD_GOSSIP_MESSAGE_PUSH );
    memset( wrapped+4UL, 0, 32UL );
    FD_STORE( ulong, wrapped+36UL, 1UL );
    memcpy( wrapped+hdr, ser_buf, (ulong)ser_len );

    fd_gossip_message_t msg2[1];
    memset( msg2, 0, sizeof(fd_gossip_message_t) );
    int ok2 = fd_gossip_message_deserialize( msg2, wrapped, hdr+(ulong)ser_len );

    if( FD_UNLIKELY( !ok2 ) ) {
      FD_LOG_ERR(( "ROUND-TRIP FAIL: value tag=%u serialized %ld bytes but deserialize rejected", v->tag, ser_len ));
    }

    fd_gossip_value_t * v2 = &msg2->push->values[ 0 ];

    if( FD_UNLIKELY( v->tag!=v2->tag ) ) FD_LOG_ERR(( "ROUND-TRIP FAIL: tag mismatch %u vs %u", v->tag, v2->tag ));
    if( FD_UNLIKELY( memcmp( v->signature, v2->signature, 64UL ) ) ) FD_LOG_ERR(( "ROUND-TRIP FAIL: signature mismatch for tag=%u", v->tag ));
    if( FD_UNLIKELY( memcmp( v->origin, v2->origin, 32UL ) ) ) FD_LOG_ERR(( "ROUND-TRIP FAIL: origin mismatch for tag=%u", v->tag ));
    if( FD_UNLIKELY( v->wallclock!=v2->wallclock ) ) FD_LOG_ERR(( "ROUND-TRIP FAIL: wallclock mismatch for tag=%u (%lu vs %lu)", v->tag, v->wallclock, v2->wallclock ));

    switch( v->tag ) {
    case FD_GOSSIP_VALUE_NODE_INSTANCE:
      if( FD_UNLIKELY( v->node_instance->timestamp!=v2->node_instance->timestamp ||
                       v->node_instance->token!=v2->node_instance->token ) ) {
        FD_LOG_ERR(( "ROUND-TRIP FAIL: node_instance field mismatch" ));
      }
      break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      if( FD_UNLIKELY( v->duplicate_shred->index!=v2->duplicate_shred->index ||
                       v->duplicate_shred->slot!=v2->duplicate_shred->slot ||
                       v->duplicate_shred->num_chunks!=v2->duplicate_shred->num_chunks ||
                       v->duplicate_shred->chunk_index!=v2->duplicate_shred->chunk_index ||
                       v->duplicate_shred->chunk_len!=v2->duplicate_shred->chunk_len ||
                       memcmp( v->duplicate_shred->chunk, v2->duplicate_shred->chunk, v->duplicate_shred->chunk_len ) ) ) {
        FD_LOG_ERR(( "ROUND-TRIP FAIL: duplicate_shred field mismatch" ));
      }
      break;
    case FD_GOSSIP_VALUE_SNAPSHOT_HASHES:
      if( FD_UNLIKELY( v->snapshot_hashes->full_slot!=v2->snapshot_hashes->full_slot ||
                       memcmp( v->snapshot_hashes->full_hash, v2->snapshot_hashes->full_hash, 32UL ) ||
                       v->snapshot_hashes->incremental_len!=v2->snapshot_hashes->incremental_len ) ) {
        FD_LOG_ERR(( "ROUND-TRIP FAIL: snapshot_hashes header mismatch" ));
      }
      for( ulong j=0UL; j<v->snapshot_hashes->incremental_len; j++ ) {
        if( FD_UNLIKELY( v->snapshot_hashes->incremental[j].slot!=v2->snapshot_hashes->incremental[j].slot ||
                         memcmp( v->snapshot_hashes->incremental[j].hash, v2->snapshot_hashes->incremental[j].hash, 32UL ) ) ) {
          FD_LOG_ERR(( "ROUND-TRIP FAIL: snapshot_hashes incremental[%lu] mismatch", j ));
        }
      }
      break;
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      for( ulong j=0UL; j<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; j++ ) {
        if( FD_UNLIKELY( v->contact_info->sockets[j].port!=v2->contact_info->sockets[j].port ) ) {
          FD_LOG_ERR(( "ROUND-TRIP FAIL: contact_info socket[%lu] port mismatch (%u vs %u)", j,
                       v->contact_info->sockets[j].port, v2->contact_info->sockets[j].port ));
        }
        if( v->contact_info->sockets[j].port ) {
          if( FD_UNLIKELY( v->contact_info->sockets[j].is_ipv6!=v2->contact_info->sockets[j].is_ipv6 ) ) {
            FD_LOG_ERR(( "ROUND-TRIP FAIL: contact_info socket[%lu] is_ipv6 mismatch", j ));
          }
          if( !v->contact_info->sockets[j].is_ipv6 ) {
            if( FD_UNLIKELY( v->contact_info->sockets[j].ip4!=v2->contact_info->sockets[j].ip4 ) ) {
              FD_LOG_ERR(( "ROUND-TRIP FAIL: contact_info socket[%lu] ip4 mismatch", j ));
            }
          } else {
            if( FD_UNLIKELY( memcmp( v->contact_info->sockets[j].ip6, v2->contact_info->sockets[j].ip6, 16UL ) ) ) {
              FD_LOG_ERR(( "ROUND-TRIP FAIL: contact_info socket[%lu] ip6 mismatch", j ));
            }
          }
        }
      }
      break;
    case FD_GOSSIP_VALUE_VOTE:
      if( FD_UNLIKELY( v->vote->index!=v2->vote->index ||
                       v->vote->transaction_len!=v2->vote->transaction_len ||
                       memcmp( v->vote->transaction, v2->vote->transaction, v->vote->transaction_len ) ) ) {
        FD_LOG_ERR(( "ROUND-TRIP FAIL: vote field mismatch" ));
      }
      break;
    }
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
