#include "fd_gossip.h"
#include "fd_gossip_private.h"

#include "fd_crds.h"
#include "fd_active_set.h"
#include "fd_prune_finder.h"
#include "fd_ping_tracker.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard.h"

#define BLOOM_FILTER_MAX_BYTES          (512UL) /* TODO: Calculate for worst case contactinfo*/
#define BLOOM_FALSE_POSITIVE_RATE       (  0.1)
#define BLOOM_NUM_KEYS                  (  8.0)

struct failed_insert{
  uchar hash[32UL];
  long  wallclock_nanos; /* time when we last tried to insert */
};

typedef struct failed_insert failed_insert_t;

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  // fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  long                next_pull_request;

  fd_sha512_t         sha512[1];

  fd_ip4_port_t       entrypoints[ 16UL ];
  ulong               entrypoints_cnt;

  fd_rng_t *          rng;
  fd_bloom_t *        bloom;

  struct {
    failed_insert_t * entries;
    ulong             cursor; /* index into next entry to write to */
    ulong             cnt;
    ulong             max;
  } failed_inserts;

  /* Callbacks */
  fd_gossip_sign_fn   sign_fn;
  void *              sign_ctx;

  fd_gossip_send_fn   send_fn;
  void *              send_ctx;
};

ulong
fd_gossip_align( void ) {
  return fd_ping_tracker_align();
}

ulong
fd_gossip_footprint( ulong max_values ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  l = FD_LAYOUT_APPEND( l, fd_crds_align(), fd_crds_footprint( max_values, max_values*4 /* FIXME: figure out better numbers */ ) );
  l = FD_LAYOUT_APPEND( l, alignof(uchar),  max_values/4*sizeof(failed_insert_t) ); /* failed inserts FIXME: figure out better numbers */
  // l = FD_LAYOUT_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
}

void *
fd_gossip_new( void *                shmem,
               fd_rng_t *            rng,
               ulong                 max_values,
               int                   has_expected_shred_version,
               ushort                expected_shred_version,
               ulong                 entrypoints_cnt,
               fd_ip4_port_t const * entrypoints,
               uchar const *         identity_pubkey,
               fd_gossip_send_fn     send_fn,
               void *                send_ctx,
               fd_gossip_sign_fn     sign_fn,
               void *                sign_ctx ) {
  (void)has_expected_shred_version;
  (void)expected_shred_version;
  (void)entrypoints;
  (void)entrypoints_cnt;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_ERR(( "NULL shmem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shmem" ));
  }
  if( FD_UNLIKELY( entrypoints_cnt>16UL ) ) {
    FD_LOG_ERR(( "entrypoints_cnt %lu exceeds maximum of 16", entrypoints_cnt ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_t * gossip  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  void * crds           = FD_SCRATCH_ALLOC_APPEND( l, fd_crds_align(), fd_crds_footprint( max_values, max_values*4 ) );
  void * failed_inserts = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), max_values/4*sizeof(failed_insert_t) ); /* FIXME: figure out better numbers */
  void * ping_tracker   = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  void * bloom          = FD_SCRATCH_ALLOC_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );

  gossip->entrypoints_cnt = entrypoints_cnt;
  fd_memcpy( gossip->entrypoints, entrypoints, entrypoints_cnt*sizeof(fd_ip4_port_t) );

  fd_crds_new( crds, rng, max_values, max_values*4 );
  fd_ping_tracker_new( ping_tracker, rng );
  fd_bloom_new( bloom, rng, BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES );


  gossip->failed_inserts.entries = (failed_insert_t *)failed_inserts;
  gossip->failed_inserts.cursor  = 0UL;
  gossip->failed_inserts.cnt     = 0UL;
  gossip->failed_inserts.max     = max_values/4;

  fd_sha512_init( gossip->sha512 );
  gossip->rng = rng;

  gossip->send_fn          = send_fn;
  gossip->send_ctx         = send_ctx;
  gossip->sign_fn          = sign_fn;
  gossip->sign_ctx         = sign_ctx;

  // fd_gossip_set_expected_shred_version( gossip, has_expected_shred_version, expected_shred_version );
  // fd_gossip_set_identity( gossip, identity_pubkey );
  fd_memcpy( gossip->identity_pubkey, identity_pubkey, 32UL );

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
  void * bloom         = FD_SCRATCH_ALLOC_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );

  gossip->ping_tracker = fd_ping_tracker_join( ping_tracker );
  gossip->bloom        = fd_bloom_join( bloom );

  return gossip;
}

static int
is_entrypoint( fd_gossip_t const *   gossip,
               fd_ip4_port_t const * peer_addr ) {
  for( ulong i=0UL; i<gossip->entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( peer_addr->l==gossip->entrypoints[i].l ) ) return 1;
  }
  return 0;
}

static fd_ip4_port_t
random_entrypoint( fd_gossip_t const * gossip ) {
  ulong idx = fd_rng_ulong_roll( gossip->rng, gossip->entrypoints_cnt );
  return gossip->entrypoints[ idx ];
}

struct __attribute__((__packed__)) prune_sign_data_pre {
 uchar prefix[18UL];
 uchar origin[32UL];
 ulong prunes_len;
};

typedef struct prune_sign_data_pre prune_sign_data_pre_t;

struct __attribute__((__packed__)) prune_sign_data_post {
 uchar destination[32UL];
 ulong wallclock;
};

typedef struct prune_sign_data_post prune_sign_data_post_t;

static int
verify_prune( fd_gossip_view_prune_t const * view,
              uchar const *                  payload,
              fd_sha512_t *                  sha ) {
  uchar sign_data[1232UL];

  prune_sign_data_pre_t * pre = (prune_sign_data_pre_t *)sign_data;
  fd_memcpy( pre->prefix, "\xffSOLANA_PRUNE_DATA", 18UL );
  fd_memcpy( pre->origin, payload+view->origin_off, 32UL );
  pre->prunes_len = view->prunes_len;

  ulong prunes_arr_sz = view->prunes_len*32UL;
  fd_memcpy( sign_data+sizeof(prune_sign_data_pre_t), payload+view->prunes_off, prunes_arr_sz );

  prune_sign_data_post_t * post = (prune_sign_data_post_t *)( sign_data + sizeof(prune_sign_data_pre_t) + prunes_arr_sz );
  post->wallclock               = view->wallclock;
  fd_memcpy( post->destination, payload+view->destination_off, 32UL );

  ulong signable_data_len = sizeof(prune_sign_data_pre_t) + prunes_arr_sz + sizeof(prune_sign_data_post_t);

  int err_prefix    = fd_ed25519_verify( sign_data,
                                         signable_data_len,
                                         payload+view->signature_off,
                                         payload+view->origin_off,
                                         sha );
  int err_no_prefix = fd_ed25519_verify( sign_data+18UL,
                                         signable_data_len-18UL,
                                         payload+view->signature_off,
                                         payload+view->origin_off,
                                         sha );

  /* Either sigverify needs to pass */
  return (err_prefix && err_no_prefix) ? -1 : FD_ED25519_SUCCESS;

}

static int
verify_crds_values( fd_gossip_view_crds_value_t const * values,
                    ulong                               values_len,
                    uchar const *                       payload,
                    fd_sha512_t *                       sha ) {
  for( ulong i=0UL; i<values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &values[ i ];
    int err = fd_ed25519_verify( payload+value->signature_off+64UL, /* signable data begins after signature */
                                 value->length-64UL,                /* signable data length */
                                 payload+value->signature_off,
                                 payload+value->pubkey_off,
                                 sha );
    if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) return err;
  }
  return FD_ED25519_SUCCESS;
}

static int
verify_ping_pong( fd_gossip_view_t const * view,
                  uchar const *            payload,
                  fd_sha512_t *            sha ) {
  /* Ping/Pong messages */
  ulong signature_off, pubkey_off, signable_data_off, signable_data_len;

  if( view->tag==FD_GOSSIP_MESSAGE_PING ) {
    signature_off     = view->ping->signature_off;
    pubkey_off        = view->ping->from_off;
    signable_data_off = view->ping->token_off;
    signable_data_len = 32UL;
  } else if( view->tag==FD_GOSSIP_MESSAGE_PONG ) {
    signature_off     = view->pong->signature_off;
    pubkey_off        = view->pong->from_off;
    signable_data_off = view->pong->hash_off;
    signable_data_len = 32UL;
  } else {
    FD_LOG_ERR(( "Invalid type %u, should not reach", view->tag ));
  }

  return fd_ed25519_verify( payload+signable_data_off,
                            signable_data_len,
                            payload+signature_off,
                            payload+pubkey_off,
                            sha );
}

static int
verify_signatures( fd_gossip_view_t const * view,
                   uchar const *            payload,
                   fd_sha512_t *            sha ) {
  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      return verify_crds_values( view->pull_request->contact_info, 1UL, payload, sha );
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      return verify_crds_values( view->pull_response->crds_values, view->pull_response->crds_values_len, payload, sha );
    case FD_GOSSIP_MESSAGE_PUSH:
      return verify_crds_values( view->push->crds_values, view->push->crds_values_len, payload, sha );
    case FD_GOSSIP_MESSAGE_PRUNE:
      return verify_prune( view->prune, payload, sha );
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      return verify_ping_pong( view, payload, sha );
    default:
      return -1;
  };
}

static ulong
failed_inserts_start_idx( fd_gossip_t const * gossip ) {
  return (gossip->failed_inserts.cursor-gossip->failed_inserts.cnt+gossip->failed_inserts.max)%gossip->failed_inserts.max;
}

static void
failed_inserts_append( fd_gossip_t * gossip,
                       uchar const * hash,
                       long          now ) {
  failed_insert_t * failed_insert = &gossip->failed_inserts.entries[ gossip->failed_inserts.cursor ];
  failed_insert->wallclock_nanos  = now;
  fd_memcpy( failed_insert->hash, hash, 32UL );

  gossip->failed_inserts.cursor = (gossip->failed_inserts.cursor+1UL)%gossip->failed_inserts.max;
  gossip->failed_inserts.cnt    = fd_ulong_min( gossip->failed_inserts.cnt+1UL, gossip->failed_inserts.max );
}

static void
failed_inserts_purge( fd_gossip_t * gossip,
                      long          now ) {
  long cutoff_nanos = now-20L*1000L*1000L*1000L;
  ulong idx = failed_inserts_start_idx( gossip );
  while( gossip->failed_inserts.cnt ) {
    long ts = gossip->failed_inserts.entries[ idx ].wallclock_nanos;
    if( FD_UNLIKELY( ts>=cutoff_nanos ) ) break;

    idx = (idx+1UL)%gossip->failed_inserts.max;
    gossip->failed_inserts.cnt--;
  }
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

static int
rx_pull_response( fd_gossip_t *                          gossip,
                  fd_gossip_view_pull_response_t const * pull_response,
                  uchar const *                          payload,
                  long                                   now ) {
  /* TODO: use epoch_duration and make timeouts ... ? */

  for( ulong i=0UL; i<pull_response->crds_values_len; i++ ) {
    fd_crds_entry_t * candidate =  fd_crds_acquire( gossip->crds );

    /* Fill up with information needed for upsert */
    fd_crds_populate_preflight( &pull_response->crds_values[i],
                                payload,
                                candidate );

    int upserts = fd_crds_upserts( gossip->crds, candidate );

    if( FD_UNLIKELY( !upserts ) ) {
      failed_inserts_append( gossip, fd_crds_value_hash( candidate ), now );
      fd_crds_release( gossip->crds, candidate );
      continue;
    }

    /* TODO: Is this jittered in Agave? */
    long accept_after_nanos;
    if( FD_UNLIKELY( !memcmp( payload+pull_response->from_off, gossip->identity_pubkey, 32UL ) ) ) {
      accept_after_nanos = 0L;
    // } else if( !stake( payload+pull_response->from_off ) ) {
    //   accept_after_nanos = now-15L*1000L*1000L*1000L;
    } else {
      accept_after_nanos = now-432000L*1000L*1000L*1000L;
    }
    int error = 0;

    if( FD_LIKELY( accept_after_nanos<=pull_response->crds_values[ i ].wallclock_nanos ) ||
                   fd_crds_has_contact_info( gossip->crds,
                                             payload+pull_response->crds_values[i].pubkey_off ) ) {
      fd_crds_populate_full( gossip->crds,
                             &pull_response->crds_values[i],
                             payload,
                             now,
                             1, /* has_upsert_info */
                             candidate );
      error = fd_crds_insert( gossip->crds, candidate, 0 /* from_push_msg */ );
    } else {
      failed_inserts_append( gossip, fd_crds_value_hash( candidate ), now );
      error = 1;
    }
    if( FD_UNLIKELY( !!error ) )
      fd_crds_release( gossip->crds, candidate );
  }

  return 0;
}

static int
rx_push( fd_gossip_t *                 gossip,
         fd_gossip_view_push_t const * push,
         uchar const *                 payload,
         long                     now ) {
  uchar const * relayer_pubkey = payload+push->from_off;

  for( ulong i=0UL; i<push->crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &push->crds_values[ i ];
    /* TODO: pretty sure this is 15s now. */
    if( FD_UNLIKELY( value->wallclock_nanos<now-30L*1000L*1000L*1000L || value->wallclock_nanos>now+30L*1000L*1000L*1000L ) ) continue;

    fd_crds_entry_t * candidate = fd_crds_acquire( gossip->crds );
    /* Separate upsert check prior to insertion to save us a memcpy if not upserting.

       FIXME: Even if new value does not upsert, we still need to call crds_insert
       so that the purge table is correctly updated, but we don't need to perform
       the full population since the insert call terminates prior to any insertion
       in this case. This is pretty confusing, will need to clean up. */
    fd_crds_populate_preflight( value, payload, candidate );

    if( FD_UNLIKELY( fd_crds_upserts( gossip->crds, candidate ) ) ) {
      fd_crds_populate_full( gossip->crds,
                             value,
                             payload,
                             now,
                             1 /* has_upsert_info */,
                             candidate );
    }

    int error            = fd_crds_insert( gossip->crds, candidate, 1 /* from_push_msg */ );
    ulong num_duplicates = 0UL;
    if( FD_UNLIKELY( !!error ) ){
      fd_crds_release( gossip->crds, candidate );
      if( FD_UNLIKELY( error>0 ) )      num_duplicates = (ulong)error;
      else if( FD_UNLIKELY( error<0 ) ) num_duplicates = ULONG_MAX;
    }


    fd_prune_finder_record( gossip->prune_finder, payload+value->pubkey_off, relayer_pubkey, num_duplicates );
  }

  return 0;
}

// static int
// rx_prune( fd_gossip_t *             gossip,
//           fd_gossip_prune_t const * prune,
//           long                      now ) {
//   if( FD_UNLIKELY( now-FD_MILLI_TO_NANOSEC(500L)>(long)prune->wallclock_nanos ) ) return FD_GOSSIP_RX_PRUNE_ERR_STALE;
//   else if( FD_UNLIKELY( !!memcmp( gossip->identity_pubkey, prune->destination, 32UL ) ) ) return FD_GOSSIP_RX_PRUNE_ERR_DESTINATION;

//   ulong identity_stake = 0UL; /* FIXME */
//   for( ulong i=0UL; i<prune->prunes_len; i++ ) {
//     ulong origin_stake = 0UL; /* FIXME */

//     fd_active_set_prune( gossip->active_set,
//                          gossip->identity_pubkey,
//                          identity_stake,
//                          prune->from,
//                          prune->destination,
//                          prune->prunes[ i ],
//                          origin_stake );
//   }
//   return FD_GOSSIP_RX_OK;
// }

struct __attribute__((__packed__)) fd_gossip_pong_tx {
  uchar tag; /* FD_GOSSIP_MESSAGE_PING */
  uchar _pad[ 3UL ];

  uchar pubkey[ 32UL ];
  uchar ping_hash[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_pong_tx fd_gossip_pong_tx_t;

static int
rx_ping( fd_gossip_t *           gossip,
         fd_gossip_view_ping_t * ping,
         fd_ip4_port_t *         peer_address,
         long                    now,
         uchar const *           in_payload ) {
  /* Construct and send the pong response */
  fd_gossip_pong_tx_t out_payload[1];
  out_payload->tag = FD_GOSSIP_MESSAGE_PONG;

  fd_memcpy( out_payload->pubkey, gossip->identity_pubkey, 32UL );
  fd_ping_tracker_hash_ping_token( in_payload+ping->token_off, out_payload->ping_hash );
  gossip->sign_fn( gossip->sign_ctx, out_payload->ping_hash, 32UL, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, out_payload->signature );

  gossip->send_fn( gossip->send_ctx, (uchar *)out_payload, sizeof(fd_gossip_pong_tx_t), peer_address, (ulong)now );
  return FD_GOSSIP_RX_OK;
}

static int
rx_pong( fd_gossip_t *           gossip,
         fd_gossip_view_pong_t * pong,
         fd_ip4_port_t *         peer_address,
         long                    now,
         uchar const *           in_payload ) {
  if( FD_UNLIKELY( is_entrypoint( gossip, peer_address ) )) return 0;

  fd_ping_tracker_register( gossip->ping_tracker,
                            in_payload+pong->from_off,
                            0UL, /* FIXME: Get stake */
                            peer_address,
                            in_payload+pong->hash_off,
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

  FD_LOG_WARNING(( "fd_gossip_rx: data_sz=%lu", data_sz ));

  int error = strip_network_hdrs( data,
                                  data_sz,
                                  &gossip_payload,
                                  &gossip_payload_sz,
                                  peer_address );
  if( FD_UNLIKELY( error ) ) return error;

  fd_gossip_view_t view[ 1 ];
  ulong decode_sz = fd_gossip_msg_parse( view, gossip_payload, gossip_payload_sz );
  if( FD_UNLIKELY( !!decode_sz ) ) return FD_GOSSIP_RX_PARSE_ERR;

  error = verify_signatures( view, data, gossip->sha512 );
  if( FD_UNLIKELY( error ) ) return error;

  // error = filter_shred_version( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  // error = check_duplicate_instance( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  /* TODO: This should verify ping tracker active for pull request */
  // error = verify_gossip_address( gossip, message );
  if( FD_UNLIKELY( error ) ) return error;

  /* TODO: Implement traffic shaper / bandwidth limiter */

  switch( view->tag ) {
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
      // error = rx_prune( gossip, message->prune, now );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      error = rx_ping( gossip, view->ping, peer_address, now, data );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      error = rx_pong( gossip, view->pong, peer_address, now, data );
      break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %d", view->tag ));
      break;
  }

  return error;
}

struct __attribute__((__packed__)) fd_gossip_ping_tx {
  uchar tag; /* FD_GOSSIP_MESSAGE_PING */
  uchar _pad[ 3UL ];

  uchar pubkey[ 32UL ];
  uchar ping_token[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_ping_tx fd_gossip_ping_tx_t;

static void
tx_ping( fd_gossip_t * gossip,
         long          now ) {
  uchar const *         peer_pubkey;
  uchar const *         ping_token;
  fd_ip4_port_t const * peer_address;
  while( fd_ping_tracker_pop_request( gossip->ping_tracker,
                                      now,
                                      &peer_pubkey,
                                      &peer_address,
                                      &ping_token ) ) {

    /* Construct and send ping message */
    fd_gossip_ping_tx_t payload[ 1 ];
    payload->tag = FD_GOSSIP_MESSAGE_PING;

    fd_memcpy( payload->pubkey, gossip->identity_pubkey, 32UL );
    fd_memcpy( payload->ping_token, ping_token, 32UL );
    gossip->sign_fn( gossip->sign_ctx, payload->ping_token, 32UL, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, payload->signature );

    gossip->send_fn( gossip->send_ctx, (uchar *)payload, sizeof(fd_gossip_ping_tx_t), peer_address, (ulong)now );
  }
}

// static void
// tx_push( fd_gossip_t * gossip,
//          long          now ) {
  // ulong num_pushes = 0UL;

  // for( fd_crds_since_iter_t it=fd_crds_since_iter_init( gossip->crds, gossip->crds_cursor ); !fd_crds_since_iter_end( it ); it=fd_crds_since_iter_next(it) ) {
  //   fd_crds_value_t * value = fd_crds_since_iter_value( it );

  //   if( FD_UNLIKELY( fd_crds_value_wallclock( value )<now-30L*1000L*1000L*1000L || fd_crds_value_wallclock( value )>now+30L*1000L*1000L*1000L ) ) continue;

  //   uchar const * origin_pubkey = fd_crds_value_pubkey( value );
  //   ulong         origin_stake  = stake( gossip, origin_pubkey );

  //   int retain;
  //   int ignore_prunes_if_peer_is_origin;
  //   switch( value->tag ) {
  //     case FD_GOSSIP_CRDS_VALUE_CONTACT_INFO:
  //     case FD_GOSSIP_CRDS_VALUE_LEGACY_CONTACT_INFO:
  //     case FD_GOSSIP_CRDS_VALUE_VOTE:
  //     case FD_GOSSIP_CRDS_VALUE_EPOCH_SLOTS:
  //     case FD_GOSSIP_CRDS_VALUE_LEGACY_SNAPSHOT_HASHES:
  //     case FD_GOSSIP_CRDS_VALUE_SNAPSHOT_HASHES:
  //     case FD_GOSSIP_CRDS_VALUE_VERSION:
  //     case FD_GOSSIP_CRDS_VALUE_ACCOUNT_HASHES:
  //     case FD_GOSSIP_CRDS_VALUE_NODE_INSTANCE:
  //       ignore_prunes_if_peer_is_origin = 1;
  //       retain = 1;
  //       break;
  //     case FD_GOSSIP_CRDS_VALUE_LOWEST_SLOT:
  //     case FD_GOSSIP_CRDS_VALUE_LEGACY_VERSION:
  //     case FD_GOSSIP_CRDS_VALUE_DUPLICATE_SHRED:
  //     case FD_GOSSIP_CRDS_VALUE_RESTART_HEAVIEST_FORK:
  //     case FD_GOSSIP_CRDS_VALUE_RESTART_LAST_VOTED_FORK_SLOTS:
  //       ignore_prunes_if_peer_is_origin = 0;
  //       retain = stake_len( gossip )<500UL || origin_stake>=1000000000UL;
  //       break;
  //     default:
  //       FD_LOG_CRIT(( "Unknown CRDS value type %d", value->tag ));
  //       break;
  //   }

  //   if( FD_UNLIKELY( !retain ) ) continue;

  //   ulong nodes[ 12UL ];
  //   ulong nodes_len = fd_active_set_nodes( gossip->active_set,
  //                                          gossip->identity_pubkey,
  //                                          gossip->identity_stake,
  //                                          origin_pubkey,
  //                                          origin_stake,
  //                                          ignore_prunes_if_peer_is_origin,
  //                                          nodes );

  //   ulong targets_len[ 300UL ] = { 0UL };
  //   fd_crds_value_t * targets[ 300UL ][ 4096UL ];

  //   for( ulong i=0UL i<fd_ulong_min( 9UL, nodes_len ); i++ ) {
  //     targets[ nodes[ i ] ][ targets_len[ nodes[ i ] ] ] = value;
  //     targets_len[ nodes[ i ] ]++;
  //     num_pushes++;
  //     if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
  //   }

  //   if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
  // }

  // for( ulong i=0UL; i<300UL; i++ ) {
  //   fd_gossip_push_t * push = new_outgoing( gossip );

  //   for( ulong j=0UL; j<targets_len[ i ]; j++ ) {
  //     /* TODO: Serialize into minimum number of push packets */
  //   }
  // }

  // gossip->crds_cursor = fd_crds_cursor( gossip->crds );
// }

struct __attribute__((__packed__)) fd_gossip_pull_request_tx_1 {
  uchar tag; /* FD_GOSSIP_MESSAGE_PULL_REQUEST */
  uchar _pad[ 3UL ];

  ulong bloom_keys_len;
  ulong bloom_keys[ ];
};

struct __attribute__((__packed__)) fd_gossip_pull_request_tx_2 {
  uchar has_bits;
  ulong bloom_bits_len;
  ulong bloom_bits[ ];
};

struct __attribute__((__packed__)) fd_gossip_pull_request_tx_3 {
  ulong bloom_len;
  ulong bloom_num_bits_set;
  ulong mask;
  ulong mask_bits;

  uchar contact_info[ ];
};

typedef struct fd_gossip_pull_request_tx_1 fd_gossip_pull_request_tx_1_t;
typedef struct fd_gossip_pull_request_tx_2 fd_gossip_pull_request_tx_2_t;
typedef struct fd_gossip_pull_request_tx_3 fd_gossip_pull_request_tx_3_t;



static void
tx_pull_request( fd_gossip_t * gossip,
                 long          now ) {
  ulong total_crds_vals = fd_crds_len( gossip->crds ) + fd_crds_purged_len( gossip->crds ) + gossip->failed_inserts.cnt;
  ulong num_items       = fd_ulong_max( 512UL, total_crds_vals );

  double max_bits       = (double)(BLOOM_FILTER_MAX_BYTES*8UL);
  double max_items      = ceil(max_bits / ( -BLOOM_NUM_KEYS / log( 1.0 - exp( log( BLOOM_FALSE_POSITIVE_RATE ) / BLOOM_NUM_KEYS) )));
  double _mask_bits     = ceil( log2( (double)num_items / max_items ) );
  uint mask_bits        = _mask_bits >= 0.0 ? (uint)_mask_bits : 0UL;
  ulong mask            = fd_rng_ulong( gossip->rng ) & ((1UL<<mask_bits)-1UL);

  fd_bloom_t * filter   = gossip->bloom;
  fd_bloom_initialize( filter, (ulong)max_items+1 ); /* TODO: check cast */

  uchar iter_mem[ CRDS_MASK_ITER_SIZE ];

  for( fd_crds_mask_iter_t * it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it = fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_bloom_insert( filter, fd_crds_value_hash( fd_crds_mask_iter_value( it, gossip->crds ) ), 32UL );
  }

  ulong shift = 64UL-mask_bits;
  for( ulong i=0UL; i<fd_crds_purged_len( gossip->crds ); i++ ) {
    /* TODO: Make the purged list also a bplus, for fast finding of matching hashes? */
    uchar const * hash = fd_crds_purged( gossip->crds, i );
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    fd_bloom_insert( filter, hash, 32UL );
  }

  ulong fi_idx = failed_inserts_start_idx( gossip );
  for( ulong i=0UL; i<gossip->failed_inserts.cnt; i++ ) {
    /* TODO: Make the failed insert list also a bplus, for fast finding of matching hashes? */
    uchar const * hash = gossip->failed_inserts.entries[ fi_idx ].hash;
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    fd_bloom_insert( filter, hash, 32UL );
    fi_idx = (fi_idx+1UL)%gossip->failed_inserts.max;
  }

  fd_ip4_port_t peer = fd_crds_sample_peer( gossip->crds );
  if( FD_UNLIKELY( !peer.l )) {
    /* Choose random entrypoint */
    peer = random_entrypoint( gossip );
  }

  /* TODO: Send the pull request to the peer */
  uchar payload[ 1232UL ];

  fd_gossip_pull_request_tx_1_t * prq1 = (fd_gossip_pull_request_tx_1_t *)payload;
  prq1->tag                            = FD_GOSSIP_MESSAGE_PULL_REQUEST;
  prq1->bloom_keys_len                 = filter->keys_len;
  fd_memcpy( prq1->bloom_keys, filter->keys, filter->keys_len * sizeof(ulong) );
  ulong prq1_sz = sizeof(fd_gossip_pull_request_tx_1_t) + prq1->bloom_keys_len * sizeof(ulong);

  fd_gossip_pull_request_tx_2_t * prq2 = (fd_gossip_pull_request_tx_2_t *)(payload + prq1_sz);

  prq2->has_bits       = 1;
  prq2->bloom_bits_len = (filter->bits_len+7UL)/8UL;
  fd_memcpy( prq2->bloom_bits, filter->bits, prq2->bloom_bits_len*8UL );
  ulong prq2_sz = sizeof(fd_gossip_pull_request_tx_2_t) + prq2->bloom_bits_len * 8UL;

  fd_gossip_pull_request_tx_3_t * prq3 = (fd_gossip_pull_request_tx_3_t *)(payload + prq1_sz + prq2_sz);
  prq3->bloom_len = filter->bits_len;
  for( ulong i=0UL; i<prq2->bloom_bits_len; i++ ) {
    prq3->bloom_num_bits_set += (uint)fd_ulong_popcnt( filter->bits[i] );
  }
  prq3->mask      = mask;
  prq3->mask_bits = mask_bits;

  ulong payload_sz = prq1_sz + prq2_sz + sizeof(fd_gossip_pull_request_tx_3_t);
  ulong rem_sz = 1232UL - payload_sz;

  /* TODO: contactinfo */

}

static inline long
next_pull_request( fd_gossip_t const * gossip,
                   long                now ) {
  (void)gossip;
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
  // purge_failed_inserts( gossip, now );
  // fd_crds_expire( gossip->crds, now );

  tx_ping( gossip, now );
  if( FD_UNLIKELY( now>=gossip->next_pull_request ) ) {
    tx_pull_request( gossip, now );
    gossip->next_pull_request = next_pull_request( gossip, now );
  }
  // if( FD_UNLIKELY( now>=gossip->next_contact_info_refresh ) ) {
  //   /* TODO: Frequency of this? More often if observing? */
  //   refresh_contact_info( gossip, now );
  //   gossip->next_contact_info_refresh = now+15L*500L*1000L*1000L; /* TODO: Jitter */
  // }
  // if( FD_UNLIKELY( now>=gossip->next_active_set_refresh ) ) {
  //   refresh_active_set( gossip, now );
  //   gossip->next_active_set_refresh = now+300L*1000L*1000L; /* TODO: Jitter */
  // }
}
