#include "fd_gossip.h"
#include "fd_gossip_types.h"
#include "fd_gossip_msg.h"

#include "fd_crds.h"
#include "fd_active_set.h"
#include "fd_prune_finder.h"
#include "fd_ping_tracker.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];

  fd_gossip_metrics_t metrics[1];

  // fd_crds_t *         crds;
  // fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  fd_sha512_t         sha512[1];

  /* Callbacks */
  fd_gossip_sign_fn sign_fn;
  void *            sign_ctx;

  fd_gossip_send_fn send_fn;
  void *            send_ctx;
};

ulong
fd_gossip_align( void ) {
  return fd_ping_tracker_align();
}

ulong
fd_gossip_footprint( ulong max_values ) {
  (void) max_values;
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  // l = FD_LAYOUT_APPEND( l, fd_crds_align(), fd_crds_footprint( max_values ) );
  // l = FD_LAYOUT_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
}

void *
fd_gossip_new( void *                shmem,
               fd_rng_t *            rng,
               ulong                 max_values FD_PARAM_UNUSED,
               int                   has_expected_shred_version,
               ushort                expected_shred_version,
               ulong                 entrypoints_cnt,
               fd_ip4_port_t const * entrypoints,
               uchar const *         identity_pubkey,
               fd_gossip_send_fn     send_fn,
               void *                send_ctx,
               fd_gossip_sign_fn     sign_fn,
               void *                sign_ctx,
               long                  now ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_ERR(( "NULL shmem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shmem" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_t * gossip = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  void * ping_tracker  = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );

  fd_ping_tracker_new( ping_tracker, rng );

  fd_sha512_init( gossip->sha512 );
  gossip->send_fn          = send_fn;
  gossip->send_ctx         = send_ctx;
  gossip->sign_fn          = sign_fn;
  gossip->sign_ctx         = sign_ctx;

  fd_gossip_set_expected_shred_version( gossip, has_expected_shred_version, expected_shred_version );
  fd_gossip_set_identity( gossip, identity_pubkey );

  for( ulong i=0UL; i<entrypoints_cnt; i++ ) {
    fd_ping_tracker_entrypoint_track( ping_tracker, now, &entrypoints[i] );
  }

  return gossip;
}

fd_gossip_t *
fd_gossip_join( void * shgossip ) {
  if( FD_UNLIKELY( !shgossip ) ) {
    FD_LOG_ERR(( "NULL shgossip" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shgossip, fd_gossip_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shgossip" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shgossip );
  fd_gossip_t * gossip = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  void * ping_tracker  = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );

  gossip->ping_tracker = fd_ping_tracker_join( ping_tracker );
  /* No need to join fd_sha512? */

  return gossip;
}

static int
parse_message( uchar const *         data,
               ulong                 data_sz,
               fd_gossip_message_t * message ) {
  ulong decoded_sz = fd_gossip_msg_parse( message, data, data_sz );
  if( FD_UNLIKELY( !decoded_sz ) ) return FD_GOSSIP_RX_PARSE_ERR;
  return FD_GOSSIP_RX_OK;
}

static int
verify_signatures( fd_gossip_message_t const *  message,
                   uchar const *                payload,
                   fd_sha512_t *                sha ) {

  /* Optimize for CRDS composites (push/pull) that don't have an outer signable
     data */
  if( FD_UNLIKELY( message->signable_sz != 0 ) ) {
    /* TODO: Special case for prune */
    int err = fd_ed25519_verify( payload+message->signable_data_offset,
                                 message->signable_sz,
                                 message->signature,
                                 message->pubkey,
                                 sha );
    if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) return err;
  }

  /* Verify CRDS entries */
  for( ulong i=0UL; i<message->crds_cnt; i++ ) {
    int err = fd_ed25519_verify( payload + message->crds[i].offset+64UL,
                                 message->crds[i].sz-64UL,
                                 message->crds[i].crd_val.signature,
                                 message->crds[i].crd_val.key->pubkey,
                                 sha );

    /* Full message must be dropped if any one value fails verify */
    if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) return err;
  }

  return FD_GOSSIP_RX_OK;
}

// static int
// rx_pull_request( fd_gossip_t *                    gossip,
//                  fd_gossip_pull_request_t const * pull_request,
//                  long                             now ) {
//   /* TODO: Implement data budget? */

//   fd_gossip_crds_data_t const * data = pull_request->value->data;
//   if( FD_UNLIKELY( data->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_NOT_CONTACT_INFO;

//   fd_gossip_contact_info_t const * contact_info = data->contact_info;
//   if( FD_UNLIKELY( !memcmp( data->contact_info->pubkey, gossip->identity_pubkey, 32UL ) ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_LOOPBACK;

//   if( FD_UNLIKELY( !is_valid_address( node ) ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_INVALID_ADDRESS;

//   fd_gossip_crds_filter_t const * filter = pull_request->filter;

//   /* TODO: Jitter? */
//   long clamp_wallclock_lower_nanos = now - 15L*1000L*1000L*1000L;
//   long clamp_wallclock_upper_nanos = now + 15L*1000L*1000L*1000L;
//   if( FD_UNLIKELY( contact_info->wallclock<clamp_wallclock_lower_nanos || contact_info->wallclock>clamp_wallclock_upper_nanos ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_WALLCLOCK;

//   ulong packet_sz = 0UL;
//   uchar packet[ 1232UL ];

//   for( fd_crds_iter_t it=fd_crds_mask_iter_init( gossip->crds, mask, mask_bits ); !fd_crds_mask_iter_done( it ); it=fd_crds_mask_iter_next(it) ) {
//     fd_crds_value_t * candidate = fd_crds_mask_iter_value( it );

//     /* TODO: Add jitter here? */
//     if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock ) ) continue;

//     ulong serialized_sz;
//     error = serialize_crds_value_into_packet( candidate, packet, 1232UL-packet_sz, &serialized_sz );
//     if( FD_LIKELY( !error ) ) {
//       packet_sz += serialized_sz;
//     } else {
//       /* CRDS value can't fit into the packet anymore, just ship what
//          we have now and start a new one. */
//       gossip->tx_fn( gossip->tx_ctx, packet, packet_sz );
//       packet_sz = 0UL;
//     }
//   }

//   /* TODO: Send packet if there's anything leftover */

//   return 0;
// }

// static int
// rx_pull_response( fd_gossip_t *                     gossip,
//                   fd_gossip_pull_response_t const * pull_response,
//                   long                              now ) {
//   /* TODO: use epoch_duration and make timeouts ... ? */

//   for( ulong i=0UL; i<pull_response->values_len; i++ ) {
//     int upserts = fd_crds_upserts( gossip->crds, pull_response->values[ i ] );

//     if( FD_UNLIKELY( !upserts ) ) {
//       failed_inserts_append( gossip, pull_response->values[ i ] );
//       continue;
//     }

//     /* TODO: Is this jittered in Agave? */
//     long accept_after_nanos;
//     if( FD_UNLIKELY( !memcmp( pull_response->sender_pubkey, gossip->identity_pubkey, 32UL ) ) ) {
//       accept_after_nanos = 0L;
//     } else if( stake( pull_response->sender_pubkey ) ) {
//       accept_after_nanos = now-15L*1000L*1000L*1000L;
//     } else {
//       accept_after_nanos = now-432000L*1000L*1000L*1000L;
//     }

//     if( FD_LIKELY( accept_after_nanos<=fd_crds_value_wallclock( pull_response->values[ i ] ) ) ) {
//       fd_crds_insert( gossip->crds, pull_response->values[ i ], now );
//       fd_crds_update_record_timestamp( pull_response->sender_pubkey, now );
//     } else if( fd_crds_has_contact_info( pull_response->sender_pubkey ) ) {
//       fd_crds_insert( gossip->crds, pull_response->values[ i ], now );
//     } else {
//       failed_inserts_append( gossip, pull_response->values[ i ] );
//     }
//   }

//   return 0;
// }

// static int
// rx_push( fd_gossip_t *            gossip,
//          fd_gossip_push_t const * push,
//          long                     now ) {
//   uchar const * relayer_pubkey = push->sender_pubkey;

//   for( ulong i=0UL; i<push->values_len; i++ ) {
//     fd_gossip_crds_value_t * value = push->values[ i ];
//     if( FD_UNLIKELY( value->timestamp<now-30L*1000L*1000L*1000L || value->timestamp>now+30L*1000L*1000L*1000L ) ) continue;

//     uchar const * origin_pubkey = fd_crds_value_pubkey( value );

//     int error = fd_crds_insert( gossip->crds, value, now );
//     ulong num_duplicates = 0UL;
//     if( FD_UNLIKELY( error>0 ) )      num_duplicates = (ulong)error;
//     else if( FD_UNLIKELY( error<0 ) ) num_duplicates = ULONG_MAX;

//     fd_prune_finder_record( gossip->prune_finder, origin_pubkey, relayer_pubkey, num_duplicates );
//   }

//   return 0;
// }

static int
rx_prune( fd_gossip_t *             gossip,
          fd_gossip_prune_t const * prune,
          long                      now ) {
  if( FD_UNLIKELY( now-FD_MILLI_TO_NANOSEC(500L)>(long)prune->wallclock_nanos ) ) return FD_GOSSIP_RX_PRUNE_ERR_STALE;
  else if( FD_UNLIKELY( !!memcmp( gossip->identity_pubkey, prune->destination, 32UL ) ) ) return FD_GOSSIP_RX_PRUNE_ERR_DESTINATION;

  ulong identity_stake = 0UL; /* FIXME */
  for( ulong i=0UL; i<prune->prunes_len; i++ ) {
    ulong origin_stake = 0UL; /* FIXME */

    fd_active_set_prune( gossip->active_set,
                         gossip->identity_pubkey,
                         identity_stake,
                         prune->from,
                         prune->destination,
                         prune->prunes[ i ],
                         origin_stake );
  }
  return FD_GOSSIP_RX_OK;
}

static int
rx_ping( fd_gossip_t *           gossip,
         fd_gossip_ping_pong_t * ping,
         fd_ip4_port_t *         peer_address,
         long                    now ) {
  /* Construct and send the pong response */
  uchar payload[ 1232UL ];
  ulong i = fd_gossip_init_msg_payload( payload, 1232UL, FD_GOSSIP_MESSAGE_PONG );

  fd_memcpy( payload+i, gossip->identity_pubkey, 32UL )               ; i+=32UL     ; /* Pubkey */
  fd_ping_tracker_hash_ping_token( payload+i, ping->token )           ; i+=32UL     ; /* Hash  */
  gossip->sign_fn( gossip->sign_ctx, payload+i, 32UL, payload+i+32UL ); i+=32UL+64UL; /* Signature (performed on hash) */

  gossip->send_fn( gossip->send_ctx, payload, i, peer_address, (ulong)now );
  return FD_GOSSIP_RX_OK;
}

static int
rx_pong( fd_gossip_t *           gossip,
         fd_gossip_ping_pong_t * pong,
         fd_ip4_port_t *         peer_address,
         long now ) {
  fd_ping_tracker_register( gossip->ping_tracker,
                             pong->from,
                             0UL, /* FIXME: Get stake */
                             peer_address,
                             pong->hash,
                             now );
  return 0;
}

/* FIXME: This feels like it should be higher up the rx processing stack (i.e., tile level)*/
static int
strip_network_hdrs( uchar const *   data,
                    ulong           data_sz,
                    uchar ** const  payload,
                    ulong *         payload_sz,
                    fd_ip4_port_t * peer_address ) {
  fd_eth_hdr_t const * eth = (fd_eth_hdr_t const *)data;
  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)( (ulong)eth + sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp = (fd_udp_hdr_t const *)( (ulong)ip4 + FD_IP4_GET_LEN( *ip4 ) );

  if( FD_UNLIKELY( (ulong)udp+sizeof(fd_udp_hdr_t) > (ulong)eth+data_sz ) )
    FD_LOG_ERR(( "Malformed UDP header" ));
  ulong udp_sz = fd_ushort_bswap( udp->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) ) )
    FD_LOG_ERR(( "Malformed UDP header" ));
  ulong payload_sz_ = udp_sz-sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( (ulong)payload+payload_sz_>(ulong)eth+data_sz ) )
    FD_LOG_ERR(( "Malformed UDP payload" ));

  *payload     = (uchar *)( (ulong)udp + sizeof(fd_udp_hdr_t) );
  *payload_sz  = payload_sz_;

  peer_address->addr = ip4->saddr;
  peer_address->port = udp->net_sport;
  return FD_GOSSIP_RX_OK;
}

int
fd_gossip_rx( fd_gossip_t * gossip,
              uchar const * data,
              ulong         data_sz,
              long          now ) {

  uchar *       gossip_payload;
  ulong         gossip_payload_sz;
  fd_ip4_port_t peer_address[1];

  int error = strip_network_hdrs( data,
                                  data_sz,
                                  &gossip_payload,
                                  &gossip_payload_sz,
                                  peer_address );
  if( FD_UNLIKELY( error ) ) return error;

  fd_gossip_message_t message[ 1 ];
  ulong decode_sz = fd_gossip_msg_parse( message, gossip_payload, gossip_payload_sz );
  if( FD_UNLIKELY( !!decode_sz ) ) return FD_GOSSIP_RX_PARSE_ERR;

  error = verify_signatures( message, data, gossip->sha512 );
  if( FD_UNLIKELY( error ) ) return error;

  // error = filter_shred_version( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  // error = check_duplicate_instance( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  /* TODO: This should verify ping tracker active for pull request */
  // error = verify_gossip_address( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  /* TODO: Implement traffic shaper / bandwidth limiter */

  switch( message->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      // error = rx_pull_request( gossip, message->pull_request );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      // error = rx_pull_response( gossip, message->pull_response );
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      // error = rx_push( gossip, message->push );
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      error = rx_prune( gossip, message->prune, now );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      error = rx_ping( gossip, message->piong, peer_address, now );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      error = rx_pong( gossip, message->piong, peer_address, now );
      break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %d", message->tag ));
      break;
  }

  return error;
}

static void
purge_failed_inserts( fd_gossip_t * gossip,
                      long          now ) {
  long cutoff_nanos = now-20L*1000L*1000L*1000L;
  while( gossip->failed_inserts_len ) {
    ulong ts = gossip->failed_inserts[ gossip->failed_inserts_idx ]->timestamp;
    if( FD_UNLIKELY( ts>=cutoff_nanos ) ) break;

    gossip->failed_inserts_idx++;
    gossip->failed_inserts_len--;
  }
}

static void
tx_ping( fd_gossip_t * gossip,
         long          now ) {
  uchar const * peer_pubkey;
  uchar const * ping_token;
  fd_ip4_port_t const * peer_address;
  while( fd_ping_tracker_pop_request( gossip->ping_tracker,
                                      now,
                                      &peer_pubkey,
                                      &peer_address,
                                      &ping_token ) ) {

    /* Construct and send ping message */
    uchar payload[ 1232UL ];
    ulong i = fd_gossip_init_msg_payload( payload, 1232UL, FD_GOSSIP_MESSAGE_PING );

    fd_memcpy( payload+i, gossip->identity_pubkey, 32UL )               ; i+=32UL     ; /* Pubkey */
    fd_memcpy( payload+i, ping_token, 32UL )                            ;             ; /* Ping token */
    gossip->sign_fn( gossip->sign_ctx, payload+i, 32UL, payload+i+32UL ); i+=32UL+64UL; /* Signature (on token) */

    gossip->send_fn( gossip->send_ctx, payload, i, peer_address, (ulong)now );
  }
}

static void
tx_push( fd_gossip_t * gossip,
         long          now ) {
  ulong num_pushes = 0UL;

  for( fd_crds_since_iter_t it=fd_crds_since_iter_init( gossip->crds, gossip->crds_cursor ); !fd_crds_since_iter_end( it ); it=fd_crds_since_iter_next(it) ) {
    fd_crds_value_t * value = fd_crds_since_iter_value( it );

    if( FD_UNLIKELY( fd_crds_value_wallclock( value )<now-30L*1000L*1000L*1000L || fd_crds_value_wallclock( value )>now+30L*1000L*1000L*1000L ) ) continue;

    uchar const * origin_pubkey = fd_crds_value_pubkey( value );
    ulong         origin_stake  = stake( gossip, origin_pubkey );

    int retain;
    int ignore_prunes_if_peer_is_origin;
    switch( value->tag ) {
      case FD_GOSSIP_CRDS_VALUE_CONTACT_INFO:
      case FD_GOSSIP_CRDS_VALUE_LEGACY_CONTACT_INFO:
      case FD_GOSSIP_CRDS_VALUE_VOTE:
      case FD_GOSSIP_CRDS_VALUE_EPOCH_SLOTS:
      case FD_GOSSIP_CRDS_VALUE_LEGACY_SNAPSHOT_HASHES:
      case FD_GOSSIP_CRDS_VALUE_SNAPSHOT_HASHES:
      case FD_GOSSIP_CRDS_VALUE_VERSION:
      case FD_GOSSIP_CRDS_VALUE_ACCOUNT_HASHES:
      case FD_GOSSIP_CRDS_VALUE_NODE_INSTANCE:
        ignore_prunes_if_peer_is_origin = 1;
        retain = 1;
        break;
      case FD_GOSSIP_CRDS_VALUE_LOWEST_SLOT:
      case FD_GOSSIP_CRDS_VALUE_LEGACY_VERSION:
      case FD_GOSSIP_CRDS_VALUE_DUPLICATE_SHRED:
      case FD_GOSSIP_CRDS_VALUE_RESTART_HEAVIEST_FORK:
      case FD_GOSSIP_CRDS_VALUE_RESTART_LAST_VOTED_FORK_SLOTS:
        ignore_prunes_if_peer_is_origin = 0;
        retain = stake_len( gossip )<500UL || origin_stake>=1000000000UL;
        break;
      default:
        FD_LOG_CRIT(( "Unknown CRDS value type %d", value->tag ));
        break;
    }

    if( FD_UNLIKELY( !retain ) ) continue;

    ulong nodes[ 12UL ];
    ulong nodes_len = fd_active_set_nodes( gossip->active_set,
                                           gossip->identity_pubkey,
                                           gossip->identity_stake,
                                           origin_pubkey,
                                           origin_stake,
                                           ignore_prunes_if_peer_is_origin,
                                           nodes );

    ulong targets_len[ 300UL ] = { 0UL };
    fd_crds_value_t * targets[ 300UL ][ 4096UL ];

    for( ulong i=0UL i<fd_ulong_min( 9UL, nodes_len ); i++ ) {
      targets[ nodes[ i ] ][ targets_len[ nodes[ i ] ] ] = value;
      targets_len[ nodes[ i ] ]++;
      num_pushes++;
      if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
    }

    if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
  }

  for( ulong i=0UL; i<300UL; i++ ) {
    fd_gossip_push_t * push = new_outgoing( gossip );

    for( ulong j=0UL; j<targets_len[ i ]; j++ ) {
      /* TODO: Serialize into minimum number of push packets */
    }
  }

  gossip->crds_cursor = fd_crds_cursor( gossip->crds );
}

static void
tx_pull_request( fd_gossip_t * gossip,
                 long          now ) {
  static const ulong MAX_FILTER_BYTES = 512UL; /* TODO: TODO: Calculate this for worst case ContactInfo */

  ulong num_items = fd_ulong_max( 512UL, fd_crds_len( gossip->crds ) + fd_crds_purged_len( gossip->crds ) + gossip->failed_inserts_len );
  double max_bits = (double)(MAX_FILTER_BYTES * 8UL);
  double max_items = ceil(max_bits / (-8.0 / log( 1.0 - exp( log( 0.1 ) / 8.0 ) )));
  double _mask_bits = ceil( log2( (double)num_items / max_items ) );
  ulong mask_bits = _mask_bits >= 0.0 ? (ulong)_mask_bits : 0UL;

  ulong mask = fd_rng_ulong( gossip->rng ) & ((1UL<<mask_bits)-1UL);

  fd_bloom_t * filter = ??; /* TODO: allocated in gossip_t */
  fd_bloom_initialize( filter, max_items );

  for( fd_crds_iter_t it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits );
       !fd_crds_mask_iter_done( it );
       it = fd_crds_mask_iter_next( it ) ) {
    fd_bloom_insert( filter, fd_crds_value_hash( fd_crds_mask_iter_value( it ) ), 32UL );
  }

  ulong shift = 64UL-mask_bits;
  for( ulong i=0UL; i<fd_crds_purged_len( gossip->crds ); i++ ) {
    /* TODO: Make the purged list also a bplus, for fast finding of matching hashes? */
    uchar const * hash = fd_crds_purged( gossip->crds, i );
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    fd_bloom_insert( filter, hash, 32UL );
  }

  for( ulong i=0UL; i<gossip->failed_inserts_len; i++ ) {
    /* TODO: Make the failed insert list also a bplus, for fast finding of matching hashes? */
    fd_crds_value_t * value = gossip->failed_inserts[ (gossip->failed_inserts_idx+i) % gossip->failed_inserts_len ];
    uchar const * hash = fd_crds_value_hash( value );
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    fd_bloom_insert( filter, hash, 32UL );
  }

  fd_ip4_port_t peer = fd_crds_sample_peer( gossip->crds );

  /* TODO: Send the pull request to the peer */
}

static inline long
next_pull_request( fd_gossip_t const * gossip,
                   long                now ) {
  /* TODO: Not always every 200 micros ... we should send less frequently
     the table is smaller.  Agave sends 1024 every 200 millis, but
     reduces 1024 to a lower amount as the table size shrinks...
     replicate this in the frequency domain. */
  /* TODO: Jitter */
  return now+200L*1000L;
}

void
fd_gossip_advance( fd_gossip_t * gossip,
                   long          now ) {
  purge_failed_inserts( gossip, now );
  fd_crds_expire( gossip->crds, now );

  tx_ping( gossip, now );
  if( FD_UNLIKELY( now>=gossip->next_pull_request ) ) {
    tx_pull_request( gossip, now );
    gossip->next_pull_request = next_pull_request( gossip, now );
  }
  if( FD_UNLIKELY( now>=gossip->next_contact_info_refresh ) ) {
    /* TODO: Frequency of this? More often if observing? */
    refresh_contact_info( gossip, now );
    gossip->next_contact_info_refresh = now+15L*500L*1000L*1000L; /* TODO: Jitter */
  }
  if( FD_UNLIKELY( now>=gossip->next_active_set_refresh ) ) {
    refresh_active_set( gossip, now );
    gossip->next_active_set_refresh = now+300L*1000L*1000L; /* TODO: Jitter */
  }
}
