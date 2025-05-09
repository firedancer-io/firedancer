#include "fd_gossip.h"
#include "fd_gossip_types.h"

#include "fd_crds.h"
#include "fd_active_set.h"
#include "fd_prune_finder.h"
#include "fd_ping_tracker.h"

static int
parse_message( uchar const *         data,
               ulong                 data_sz,
               fd_gossip_message_t * message ) {
  
  return 0;
}

static int
rx_pull_request( fd_gossip_t *                    gossip,
                 fd_gossip_pull_request_t const * pull_request,
                 long                             now ) {
  /* TODO: Implement data budget? */

  fd_gossip_crds_data_t const * data = pull_request->value->data;
  if( FD_UNLIKELY( data->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_NOT_CONTACT_INFO;

  fd_gossip_contact_info_t const * contact_info = data->contact_info;
  if( FD_UNLIKELY( !memcmp( data->contact_info->pubkey, gossip->identity_pubkey, 32UL ) ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_LOOPBACK;

  if( FD_UNLIKELY( !is_valid_address( node ) ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_INVALID_ADDRESS;

  fd_gossip_crds_filter_t const * filter = pull_request->filter;

  /* TODO: Jitter? */
  long clamp_wallclock_lower_nanos = now - 15L*1000L*1000L*1000L;
  long clamp_wallclock_upper_nanos = now + 15L*1000L*1000L*1000L;
  if( FD_UNLIKELY( contact_info->wallclock<clamp_wallclock_lower_nanos || contact_info->wallclock>clamp_wallclock_upper_nanos ) ) return FD_GOSSIP_RX_ERR_PULL_REQUEST_WALLCLOCK;

  ulong packet_sz = 0UL;
  uchar packet[ 1232UL; ];

  for( fd_crds_iter_t it=fd_crds_mask_iter_init( gossip->crds, mask, mask_bits ); !fd_crds_mask_iter_done( it ); it=fd_crds_mask_iter_next(it) ) {
    fd_crds_value_t * candidate = fd_crds_mask_iter_value( it );

    /* TODO: Add jitter here? */
    if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock ) ) continue;

    ulong serialized_sz;
    error = serialize_crds_value_into_packet( candidate, packet, 1232UL-packet_sz, &serialized_sz );
    if( FD_LIKELY( !error ) ) {
      packet_sz += serialized_sz;
    } else {
      /* CRDS value can't fit into the packet anymore, just ship what
         we have now and start a new one. */
      gossip->tx_fn( gossip->tx_ctx, packet, packet_sz );
      packet_sz = 0UL;
    }
  }

  /* TODO: Send packet if there's anything leftover */

  return 0;
}

static int
rx_pull_response( fd_gossip_t *                     gossip,
                  fd_gossip_pull_response_t const * pull_response,
                  long                              now ) {
  /* TODO: use epoch_duration and make timeouts ... ? */

  for( ulong i=0UL; i<pull_response->values_len; i++ ) {
    int upserts = fd_crds_upserts( gossip->crds, pull_response->values[ i ] );

    if( FD_UNLIKELY( !upserts ) ) {
      failed_inserts_append( gossip, pull_response->values[ i ] );
      continue;
    }

    /* TODO: Is this jittered in Agave? */
    long accept_after_nanos;
    if( FD_UNLIKELY( !memcmp( pull_response->sender_pubkey, gossip->identity_pubkey, 32UL ) ) ) {
      accept_after_nanos = 0L;
    } else if( stake( pull_response->sender_pubkey ) ) {
      accept_after_nanos = now-15L*1000L*1000L*1000L;
    } else {
      accept_after_nanos = now-432000L*1000L*1000L*1000L;
    }

    if( FD_LIKELY( accept_after_nanos<=fd_crds_value_wallclock( pull_response->values[ i ] ) ) ) {
      fd_crds_insert( gossip->crds, pull_response->values[ i ], now );
      fd_crds_update_record_timestamp( pull_response->sender_pubkey, now );
    } else if( fd_crds_has_contact_info( pull_response->sender_pubkey ) ) {
      fd_crds_insert( gossip->crds, pull_response->values[ i ], now );
    } else {
      failed_inserts_append( gossip, pull_response->values[ i ] );
    }
  }

  return 0;
}

static int
rx_push( fd_gossip_t *            gossip,
         fd_gossip_push_t const * push,
         long                     now ) {
  uchar const * relayer_pubkey = push->sender_pubkey;

  for( ulong i=0UL; i<push->values_len; i++ ) {
    fd_gossip_crds_value_t * value = push->values[ i ];
    if( FD_UNLIKELY( value->timestamp<now-30L*1000L*1000L*1000L || value->timestamp>now+30L*1000L*1000L*1000L ) ) continue;

    uchar const * origin_pubkey = fd_crds_value_pubkey( value );

    int error = fd_crds_insert( gossip->crds, value, now );
    ulong num_duplicates = 0UL;
    if( FD_UNLIKELY( error>0 ) )      num_duplicates = (ulong)error;
    else if( FD_UNLIKELY( error<0 ) ) num_duplicates = ULONG_MAX;

    fd_prune_finder_record( gossip->prune_finder, origin_pubkey, relayer_pubkey, num_duplicates );
  }

  return 0;
}

static int
rx_prune( fd_gossip_t *             gossip,
          fd_gossip_prune_t const * prune,
          long                      now ) {
  if( FD_UNLIKELY( now-500L*1000L*1000L>prune->data->wallclock ) ) return FD_GOSSIP_RX_ERR_PRUNE_TIMEOUT;
  else if( FD_UNLIKELY( !memcmp( gossip->identity_pubkey, prune->data->destination, 32UL ) ) ) return FD_GOSSIP_RX_ERR_PRUNE_DESTINATION;

  ulong identity_stake = ??;
  for( ulong i=0UL; i<prune->data->prunes_len; i++ ) {
    ulong origin_stake = ??;

    fd_active_set_prune( gossip->active_set,
                         gossip->identity_pubkey,
                         gossip->identity_stake,
                         prune->data->pubkey,
                         prune->data->destination,
                         prune->data->prunes[ i ],
                         origin_stake );
  }
}

static int
rx_ping( fd_gossip_t *      gossip,
         fd_gossip_ping_t * ping ) {
  fd_gossip_message_t * message = new_outgoing( gossip );

  message->tag = FD_GOSSIP_MESSAGE_PONG;
  fd_memcpy( message->pong->from, gossip->identity_pubkey, 32UL );
  message->pong->hash = hash_ping_token( ping->token );
  gossip->sign_fn( gossip->sign_ctx, message->pong->hash, 32UL, message->pong->signature );

  /* TODO: Send it */
}

static int
rx_pong( fd_gossip_t *      gossip,
         fd_gossip_pong_t * pong ) {
  for( ulong i=0UL; i<2UL; i++ ) {

    if( FD_LIKELY( hash_ping_token( ) ) ) {
      return FD_GOSSIP_RX_SUCCESS;
    }
  }

  return FD_GOSSIP_RX_ERR_PONG_UNMATCHED;
}

int
fd_gossip_rx( fd_gossip_t * gossip,
              uchar const * data,
              ulong         data_sz,
              long          now ) {
  fd_gossip_message_t message[ 1 ];
  int error = parse_message( data, data_sz, message );
  if( FD_UNLIKELY( error ) ) return error;

  error = verify_signatures( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  error = filter_shred_version( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  error = check_duplicate_instance( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  /* TODO: This should verify ping tracker active for pull request */
  error = verify_gossip_address( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  /* TODO: Implement traffic shaper / bandwidth limiter */

  switch( message->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      error = rx_pull_request( gossip, message->pull_request );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      error = rx_pull_response( gossip, message->pull_response );
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      error = rx_push( gossip, message->push );
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      error = rx_prune( gossip, message->prune );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      error = rx_ping( gossip, message->ping );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      error = rx_pong( gossip, message->pong );
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
  while( fd_ping_tracker_pop_request( gossip->ping_tracker, now, &peer_pubkey ) ) {
    /* TODO: Generate and send a ping message ... */
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
    fd_gossip_crds_value_t * value = gossip->failed_inserts[ (gossip->failed_inserts_idx+i) % gossip->failed_inserts_len ];
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
