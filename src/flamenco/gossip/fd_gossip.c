#include "fd_gossip.h"
#include "fd_contact_info.h"
#include "fd_gossip_private.h"

#include "crds/fd_crds.h"
#include "fd_active_set.h"
#include "fd_prune_finder.h"
#include "fd_ping_tracker.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard.h"

#define BLOOM_FILTER_MAX_BYTES          (512UL) /* TODO: Calculate for worst case contactinfo */
#define BLOOM_FALSE_POSITIVE_RATE       (  0.1)
#define BLOOM_NUM_KEYS                  (  8.0)

#define PING_PONG_SIGN_TYPE             FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519
#define CRDS_SIGN_TYPE                  FD_KEYGUARD_SIGN_TYPE_ED25519

/* TODO: hardcode a CRDS filter instead of using bloom tmpls ? */
#define BLOOM_NAME    crds_bloom
#include "tmpl/fd_bloom.c"

struct stake_weight {
  fd_pubkey_t key;
  ulong       stake;
  ulong       hash;
};
typedef struct stake_weight stake_weight_t;

#define MAP_NAME               stake_map
#define MAP_T                  stake_weight_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_HASH_T             ulong
#define MAP_KEY_NULL           pubkey_null
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key)      ((key).ui[3])
#define MAP_KEY_MOVE(k0,k1)    (fd_memcpy((k0).key,(k1).key,sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        16 /* follow CRDS_MAX_CONTACT_INFO*2 */

#include "../../util/tmpl/fd_map.c"

struct failed_insert{
  uchar hash[32UL];
  long  wallclock_nanos; /* time when we last tried to insert */
};

typedef struct failed_insert failed_insert_t;

/* Push State holds a gossip push message buffer for
   a valid push destination (e.g., peers in the active set
   or entrypoints). This should be flushed out to the network
   once capacity is reached. */
struct push_state {
  uchar            msg[ 1232UL ];
  ulong            msg_sz;    /* Also functions as cursor */
  ulong            num_crds;
  fd_ip4_port_t    push_dest;
  uchar            has_my_ci; /* Whether my contact info is already in the push */
};

typedef struct push_state push_state_t;

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];
  ulong               identity_stake;

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  long                next_pull_request;

  fd_sha512_t         sha512[1];

  fd_ip4_port_t       entrypoints[ 16UL ];
  ulong               entrypoints_cnt;

  fd_rng_t *          rng;
  crds_bloom_t *      bloom;

  /* TODO: has_shred_version */
  ushort              expected_shred_version;

  stake_weight_t *    stake_weights;

  struct {
    failed_insert_t * entries;
    ulong             cursor; /* index into next entry to write to */
    ulong             cnt;
    ulong             cap;
  } failed_inserts;

  /* Event timers */
  long                next_active_set_refresh;
  long                next_contact_info_refresh;

  /* Callbacks */
  fd_gossip_sign_fn   sign_fn;
  void *              sign_ctx;

  fd_gossip_send_fn   send_fn;
  void *              send_ctx;

  struct {
    uchar             crds_val[ 1232UL ]; /* CRDS value for the push message */
    ulong             crds_val_sz;        /* Size of the CRDS value */
    fd_contact_info_t ci[1];
  } my_contact_info;

  /* Push state for each peer in the active set and entrypoints
     (16 max total). active_push_state tracks the active set, and must be
     flushed prior to a call to fd_active_set_rotate or fd_active_set_prune. */
  push_state_t        active_push_state[ FD_ACTIVE_SET_MAX_PEERS ];

  /* entrypt_push_set is a separate push set that is used on a separate regime,
     typically at bootup when the active set is sparse  */
  push_state_t        entrypt_push_state[ 16UL ];
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
  l = FD_LAYOUT_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(), stake_map_footprint() );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
}

static void
push_state_reset( push_state_t * state,
                  uchar const * identity_pubkey ) {
  state->msg[ 0 ] = FD_GOSSIP_MESSAGE_PUSH;
  fd_memcpy( &state->msg[ 4 ], identity_pubkey, 32UL );
  state->msg_sz     = 36UL; /* 4 byte tag + 32 byte sender pubkey */
  state->num_crds   = 0UL;
  state->has_my_ci  = 0;
}

static void
push_state_new( push_state_t * state,
                uchar const * identity_pubkey,
                fd_ip4_port_t push_dest ) {
  push_state_reset( state, identity_pubkey );
  state->push_dest = push_dest;
}

void *
fd_gossip_new( void *                    shmem,
               fd_rng_t *                rng,
               ulong                     max_values,
               ulong                     entrypoints_cnt,
               fd_ip4_port_t const *     entrypoints,
               fd_contact_info_t const * my_contact_info,
               long                      now,
               fd_gossip_send_fn         send_fn,
               void *                    send_ctx,
               fd_gossip_sign_fn         sign_fn,
               void *                    sign_ctx ) {
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
  void * active_set     = FD_SCRATCH_ALLOC_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  void * failed_inserts = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), max_values/4*sizeof(failed_insert_t) ); /* FIXME: figure out better numbers */
  void * ping_tracker   = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  void * bloom          = FD_SCRATCH_ALLOC_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  void * stake_weights  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(), stake_map_footprint() );

  gossip->entrypoints_cnt = entrypoints_cnt;
  fd_memcpy( gossip->entrypoints, entrypoints, entrypoints_cnt*sizeof(fd_ip4_port_t) );

  gossip->crds          = fd_crds_join( fd_crds_new( crds, rng, max_values, max_values*4 ) );
  gossip->active_set    = fd_active_set_join( fd_active_set_new( active_set, rng ) );
  gossip->ping_tracker  = fd_ping_tracker_join( fd_ping_tracker_new( ping_tracker, rng ) );
  gossip->bloom         = crds_bloom_join( crds_bloom_new( bloom, rng, BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  gossip->stake_weights = stake_map_join( stake_map_new( stake_weights ) );

  gossip->failed_inserts.entries = (failed_insert_t *)failed_inserts;
  gossip->failed_inserts.cursor  = 0UL;
  gossip->failed_inserts.cnt     = 0UL;
  gossip->failed_inserts.cap     = max_values/4;

  fd_sha512_init( gossip->sha512 );
  gossip->rng = rng;

  gossip->send_fn          = send_fn;
  gossip->send_ctx         = send_ctx;
  gossip->sign_fn          = sign_fn;
  gossip->sign_ctx         = sign_ctx;

  /* Init push states */
  for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERS; i++ ) {
    push_state_reset( &gossip->active_push_state[i], gossip->identity_pubkey );
  }
  for( ulong i=0UL; i<entrypoints_cnt; i++ ) {
    push_state_t * state = &gossip->entrypt_push_state[i];
    push_state_new( state, gossip->identity_pubkey, gossip->entrypoints[i] );
  }

  fd_gossip_set_my_contact_info( gossip, my_contact_info, now );
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

  return (fd_gossip_t *)shgossip;
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

static void
push_state_flush( fd_gossip_t *   gossip,
                  push_state_t *  state,
                  long            now ) {
  if( FD_UNLIKELY( !state->num_crds ) ) return; /* Nothing to flush */

  /* Send the message */
  gossip->send_fn( gossip->send_ctx, state->msg, state->msg_sz, &state->push_dest, (ulong)now );

  /* Reset the push state */
  state->msg_sz     = 36UL; /* 4 byte tag + 32 byte sender pubkey */
  state->num_crds   = 0UL;
  state->has_my_ci  = 0;
}

static void
push_state_append_crds( fd_gossip_t *                       gossip,
                        push_state_t *                      state,
                        uchar const *                       crds_bytes,
                        ulong                               crds_len,
                        long                                now ) {
  ulong remaining_space = sizeof(state->msg) - state->msg_sz;
  if( FD_UNLIKELY( remaining_space<crds_len ) ) {
    push_state_flush( gossip, state, now );
  }
  if( FD_UNLIKELY( remaining_space<crds_len ) ) {
    FD_LOG_ERR(( "Not enough space in push state to append CRDS value even after flushing" ));
  }
  fd_memcpy( &state->msg[ state->msg_sz ], crds_bytes, crds_len );
  state->msg_sz   += crds_len;
  state->num_crds += 1UL;
}

static void
push_my_contact_info( fd_gossip_t * gossip, long now ){
  for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERS; i++ ) {
    push_state_t * state = &gossip->active_push_state[i];
    if( state->has_my_ci ) continue;
    push_state_append_crds( gossip,
                            state,
                            gossip->my_contact_info.crds_val,
                            gossip->my_contact_info.crds_val_sz,
                            now );
    state->has_my_ci = 1;
  }
  for( ulong i=0UL; i<gossip->entrypoints_cnt; i++ ) {
    push_state_t * state = &gossip->entrypt_push_state[i];
    if( state->has_my_ci ) continue;
    push_state_append_crds( gossip,
                            state,
                            gossip->my_contact_info.crds_val,
                            gossip->my_contact_info.crds_val_sz,
                            now );
    state->has_my_ci = 1;
  }
}

static inline void
refresh_contact_info( fd_gossip_t * gossip,
                      long          now ) {
  gossip->my_contact_info.ci->wallclock_nanos = now;
  fd_gossip_contact_info_encode( gossip->my_contact_info.ci,
                                 gossip->my_contact_info.crds_val,
                                 1232UL,
                                 &gossip->my_contact_info.crds_val_sz );
  gossip->sign_fn( gossip->sign_ctx,
                   gossip->my_contact_info.crds_val+64UL,
                   gossip->my_contact_info.crds_val_sz-64UL,
                   CRDS_SIGN_TYPE,
                   gossip->my_contact_info.crds_val );
  push_my_contact_info( gossip, now );
}

void
fd_gossip_set_my_contact_info( fd_gossip_t *             gossip,
                               fd_contact_info_t const * contact_info,
                               long                      now ) {
  fd_memcpy( gossip->identity_pubkey, contact_info->pubkey, 32UL );
  gossip->expected_shred_version = contact_info->shred_version;

  *gossip->my_contact_info.ci = *contact_info;
  refresh_contact_info( gossip, now );
}

ulong
get_stake( fd_gossip_t const * gossip,
           uchar const * pubkey ) {
  stake_weight_t const * entry = stake_map_query_const( gossip->stake_weights, *(fd_pubkey_t const *)pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    return 0UL;
  }
  return entry->stake;
}

void
fd_gossip_stakes_update( fd_gossip_t *             gossip,
                         fd_stake_weight_t const * stake_weights,
                         ulong                     stake_weights_cnt ){
  stake_map_clear( gossip->stake_weights );

  for( ulong i=0UL; i<stake_weights_cnt; i++ ) {
    stake_weight_t * entry = stake_map_insert( gossip->stake_weights, stake_weights[i].key );
    if( FD_UNLIKELY( !entry ) ) {
      FD_LOG_ERR(( "Failed to insert stake weight" ));
    }
    entry->stake = stake_weights[i].stake;
  }



  /* TODO: contact info entries need to be updated? Or let it be driven by rx_{pullreq, pullresp, push} events? */
  /* Update the identity stake */
  gossip->identity_stake = get_stake( gossip, gossip->identity_pubkey );
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
                  fd_sha512_t *            sha ) {
  /* Ping/Pong messages */
  uchar const * signature, * pubkey, * signable_data;

  if( view->tag==FD_GOSSIP_MESSAGE_PING ) {
    signature     = view->ping->signature;
    pubkey        = view->ping->pubkey;
    signable_data = view->ping->ping_token;
  } else if( view->tag==FD_GOSSIP_MESSAGE_PONG ) {
    signature     = view->pong->signature;
    pubkey        = view->pong->pubkey;
    signable_data = view->pong->ping_hash;
  } else {
    FD_LOG_ERR(( "Invalid type %u, should not reach", view->tag ));
  }

  return fd_ed25519_verify( signable_data,
                            32UL,
                            signature,
                            pubkey,
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
      return verify_ping_pong( view, sha );
    default:
      return -1;
  };
}

static ulong
failed_inserts_start_idx( fd_gossip_t const * gossip ) {
  return (gossip->failed_inserts.cursor-gossip->failed_inserts.cnt+gossip->failed_inserts.cap)%gossip->failed_inserts.cap;
}

static void
failed_inserts_append( fd_gossip_t * gossip,
                       uchar const * hash,
                       long          now ) {
  failed_insert_t * failed_insert = &gossip->failed_inserts.entries[ gossip->failed_inserts.cursor ];
  failed_insert->wallclock_nanos  = now;
  fd_memcpy( failed_insert->hash, hash, 32UL );

  gossip->failed_inserts.cursor = (gossip->failed_inserts.cursor+1UL)%gossip->failed_inserts.cap;
  gossip->failed_inserts.cnt    = fd_ulong_min( gossip->failed_inserts.cnt+1UL, gossip->failed_inserts.cap );
}

static void
failed_inserts_purge( fd_gossip_t * gossip,
                      long          now ) {
  long cutoff_nanos = now-20L*1000L*1000L*1000L;
  ulong idx = failed_inserts_start_idx( gossip );
  while( gossip->failed_inserts.cnt ) {
    long ts = gossip->failed_inserts.entries[ idx ].wallclock_nanos;
    if( FD_UNLIKELY( ts>=cutoff_nanos ) ) break;

    idx = (idx+1UL)%gossip->failed_inserts.cap;
    gossip->failed_inserts.cnt--;
  }
}

static int
rx_pull_request( fd_gossip_t *                         gossip,
                 fd_gossip_view_pull_request_t const * pr_view,
                 uchar const *                         payload,
                 fd_ip4_port_t const *                 peer_addr,
                 long                                  now ) {
  /* TODO: Implement data budget? Or at least limit iteration range */

  fd_gossip_view_crds_value_t const * contact_info = pr_view->contact_info;
  if( FD_UNLIKELY( contact_info->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) return -1 /* FD_GOSSIP_RX_ERR_PULL_REQUEST_NOT_CONTACT_INFO */;

  if( FD_UNLIKELY( !memcmp( payload+contact_info->pubkey_off, gossip->identity_pubkey, 32UL ) ) ) return -1 /* FD_GOSSIP_RX_ERR_PULL_REQUEST_LOOPBACK */;

  uchar const * node = payload+contact_info->pubkey_off;
  ulong node_stake = get_stake( gossip, node );

  if( FD_UNLIKELY( !fd_ping_tracker_active( gossip->ping_tracker,
                                            node,
                                            node_stake,
                                            peer_addr,
                                            now ) ) ) {
    fd_ping_tracker_track( gossip->ping_tracker,
                           node,
                           node_stake,
                           peer_addr,
                           now );
    return -1;
  }

  crds_bloom_t filter[1];
  filter->keys_len = pr_view->bloom_keys_len;
  filter->keys     = (ulong *)( payload + pr_view->bloom_keys_offset );

  filter->bits_len = pr_view->bloom_len;
  filter->bits     = (ulong *)( payload + pr_view->bloom_bits_offset );

  /* TODO: Jitter? */
  long clamp_wallclock_lower_nanos = now - 15L*1000L*1000L*1000L;
  long clamp_wallclock_upper_nanos = now + 15L*1000L*1000L*1000L;
  if( FD_UNLIKELY( contact_info->wallclock_nanos<clamp_wallclock_lower_nanos ||
                   contact_info->wallclock_nanos>clamp_wallclock_upper_nanos ) ) return -1; /* FD_GOSSIP_RX_ERR_PULL_REQUEST_WALLCLOCK; */

  /* We use push_state since a pullresponse is identical save for the message discriminant */
  push_state_t pull_resp[1];
  push_state_new( pull_resp, gossip->identity_pubkey, *peer_addr );
  pull_resp->msg[ 0 ] = FD_GOSSIP_MESSAGE_PULL_RESPONSE;

  uchar iter_mem[ CRDS_MASK_ITER_SIZE ];

  for( fd_crds_mask_iter_t * it=fd_crds_mask_iter_init( gossip->crds, pr_view->mask, pr_view->mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it=fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_crds_entry_t const * candidate = fd_crds_mask_iter_value( it, gossip->crds );

    /* TODO: Add jitter here? */
    // if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock ) ) continue;

    if( FD_UNLIKELY( !crds_bloom_contains( filter, fd_crds_entry_hash( candidate ), 32UL ) ) ) continue;

    uchar const * crds_val;
    ulong *       crds_size = NULL;
    fd_crds_entry_value( candidate, &crds_val, crds_size );
    push_state_append_crds( gossip, pull_resp, crds_val, *crds_size, now );
  }
  push_state_flush( gossip, pull_resp, now );
  return 0;
}

static void
push_state_insert( fd_gossip_t *                       gossip,
                   fd_gossip_view_crds_value_t const * value,
                   uchar const *                       payload,
                   uchar const *                       origin_pubkey,
                   ulong                               origin_stake,
                   long                                now ) {
  ulong out_nodes[ 12UL ];
  ulong out_nodes_cnt = fd_active_set_nodes( gossip->active_set,
                                             gossip->identity_pubkey,
                                             gossip->identity_stake,
                                             origin_pubkey,
                                             origin_stake, /* origin_stake FIXME */
                                             0UL, /* ignore_prunes_if_peer_is_origin FIXME */
                                             out_nodes );
  if( FD_LIKELY( out_nodes_cnt ) ) {
    for( ulong j=0UL; j<out_nodes_cnt; j++ ) {
      ulong idx            = out_nodes[ j ];
      push_state_t * state = &gossip->active_push_state[ idx ];
      push_state_append_crds( gossip,
                              state,
                              payload+value->value_off,
                              value->length,
                              now );
    }
  } else {
    /* pick entrypoint to push value to ?? */
    ulong idx = fd_rng_ulong_roll( gossip->rng, gossip->entrypoints_cnt );
    push_state_append_crds( gossip,
                            &gossip->entrypt_push_state[idx],
                            payload+value->value_off,
                            value->length,
                            now );
  }
}

static int
rx_pull_response( fd_gossip_t *                          gossip,
                  fd_gossip_view_pull_response_t const * pull_response,
                  uchar const *                          payload,
                  long                                   now ) {
  /* TODO: use epoch_duration and make timeouts ... ? */

  for( ulong i=0UL; i<pull_response->crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &pull_response->crds_values[ i ];
    fd_crds_entry_t * candidate               = fd_crds_acquire( gossip->crds );

    /* Fill up with information needed for upsert check */
    fd_crds_populate_preflight( value, payload, candidate );

    int upserts = fd_crds_upserts( gossip->crds, candidate );

    if( FD_UNLIKELY( !upserts ) ) {
      failed_inserts_append( gossip, fd_crds_entry_hash( candidate ), now );
      fd_crds_release( gossip->crds, candidate );
      continue;
    }

    uchar const * origin_pubkey    = payload+value->pubkey_off;
    ulong origin_stake             = get_stake( gossip, origin_pubkey );

    /* TODO: Is this jittered in Agave? */
    long accept_after_nanos;
    if( FD_UNLIKELY( !memcmp( payload+value->pubkey_off, gossip->identity_pubkey, 32UL ) ) ) {
      accept_after_nanos = 0L;
    } else if( !origin_stake ) {
      accept_after_nanos = now-15L*1000L*1000L*1000L;
    } else {
      accept_after_nanos = now-432000L*1000L*1000L*1000L;
    }
    int error = 0;

    if( FD_LIKELY( accept_after_nanos<=value->wallclock_nanos ) ||
                   fd_crds_entry_is_contact_info( candidate ) ) {
      fd_crds_populate_full( gossip->crds,
                             value,
                             payload,
                             origin_stake,
                             now,
                             1, /* has_upsert_info */
                             candidate );
      error = fd_crds_insert( gossip->crds,
                              candidate,
                              0, /* from_push_msg */
                              now );
    } else {
      failed_inserts_append( gossip, fd_crds_entry_hash( candidate ), now );
      error = 1;
    }
    if( FD_UNLIKELY( !!error ) )
      fd_crds_release( gossip->crds, candidate );
    else {
      if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ){
         int active = fd_ping_tracker_active( gossip->ping_tracker,
                                              origin_pubkey,
                                              origin_stake,
                                              NULL /* TODO */,
                                              now );
          active ? fd_crds_peer_active( gossip->crds, origin_pubkey, now )
                 : fd_crds_peer_inactive( gossip->crds, origin_pubkey, now );

      }
      push_state_insert( gossip,
                         value,
                         payload,
                         origin_pubkey,
                         origin_stake,
                         now );
    }
  }

  return 0;
}

static int
rx_push( fd_gossip_t *                 gossip,
         fd_gossip_view_push_t const * push,
         uchar const *                 payload,
         long                          now ) {
  uchar const * relayer_pubkey = payload+push->from_off;
  (void)relayer_pubkey; /* TODO: use relayer_pubkey to update push state */

  for( ulong i=0UL; i<push->crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &push->crds_values[ i ];
    /* TODO: pretty sure this is 15s now. */
    if( FD_UNLIKELY( value->wallclock_nanos<now-30L*1000L*1000L*1000L || value->wallclock_nanos>now+30L*1000L*1000L*1000L ) ) continue;

    uchar const * origin_pubkey    = payload+value->pubkey_off;
    fd_crds_entry_t * candidate = fd_crds_acquire( gossip->crds );
    /* Separate upsert check prior to insertion to save us a memcpy + lookup if not upserting.

       FIXME: Even if new value does not upsert, we still need to call crds_insert
       so that the purge table is correctly updated, but we don't need to perform
       the full population since the insert call terminates prior to any insertion
       in this case. This is pretty confusing, will need to clean up. */
    fd_crds_populate_preflight( value, payload, candidate );
    ulong origin_stake;

    if( FD_UNLIKELY( fd_crds_upserts( gossip->crds, candidate ) ) ) {
      origin_stake = get_stake( gossip, origin_pubkey );
      fd_crds_populate_full( gossip->crds,
                             value,
                             payload,
                             origin_stake,
                             now,
                             1 /* has_upsert_info */,
                             candidate );
    }

    int error            = fd_crds_insert( gossip->crds,
                                           candidate,
                                           1 /* from_push_msg */,
                                           now );
    ulong num_duplicates = 0UL;
    if( FD_UNLIKELY( !!error ) ){
      fd_crds_release( gossip->crds, candidate );
      if( FD_UNLIKELY( error>0 ) )      num_duplicates = (ulong)error;
      else if( FD_UNLIKELY( error<0 ) ) num_duplicates = ULONG_MAX;
    } else {
      if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ) {
        fd_contact_info_t const * contact_info = fd_crds_entry_contact_info( candidate );
        fd_ip4_port_t origin_addr              = fd_contact_info_gossip_socket( contact_info );
         int active = fd_ping_tracker_active( gossip->ping_tracker,
                                              origin_pubkey,
                                              origin_stake,
                                              &origin_addr,
                                              now );
          active ? fd_crds_peer_active( gossip->crds, origin_pubkey, now )
                 : fd_crds_peer_inactive( gossip->crds, origin_pubkey, now );

      }
      push_state_insert( gossip,
                         value,
                         payload,
                         origin_pubkey,
                         origin_stake,
                         now );
    }
    (void)num_duplicates; /* TODO: use num_duplicates to prune the prune_finder */
    // fd_prune_finder_record( gossip->prune_finder,
    //                         origin_pubkey,
    //                         origin_stake,
    //                         relayer_pubkey,
    //                         get_stake( gossip, relayer_pubkey ),
    //                         num_duplicates );
  }

  return 0;
}

static int
rx_prune( fd_gossip_t *                  gossip,
          uchar const *                  payload,
          fd_gossip_view_prune_t const * prune,
          long                           now ) {
  if( FD_UNLIKELY( now-FD_MILLI_TO_NANOSEC(500L)>(long)prune->wallclock_nanos ) ) return FD_GOSSIP_RX_PRUNE_ERR_STALE;
  else if( FD_UNLIKELY( !!memcmp( gossip->identity_pubkey, payload+prune->destination_off, 32UL ) ) ) return FD_GOSSIP_RX_PRUNE_ERR_DESTINATION;


  fd_active_set_prunes( gossip->active_set,
                        gossip->identity_pubkey,
                        gossip->identity_stake,
                        payload+prune->prunes_off,
                        prune->prunes_len,
                        payload+prune->origin_off,
                        get_stake( gossip, payload+prune->origin_off ),
                        NULL /* TODO: use out_node_idx to update push states */ );

  return FD_GOSSIP_RX_OK;
}


static int
rx_ping( fd_gossip_t *           gossip,
         fd_gossip_view_ping_t * ping,
         fd_ip4_port_t *         peer_address,
         long                    now ) {
  /* TODO: have this point to dcache buffer directly instead */
  uchar out_payload[ sizeof(fd_gossip_view_pong_t) + 4UL];
  out_payload[0] = FD_GOSSIP_MESSAGE_PONG;

  fd_gossip_view_pong_t * out_pong = (fd_gossip_view_pong_t *)out_payload + 4UL;

  fd_memcpy( out_pong->pubkey, gossip->identity_pubkey, 32UL );
  fd_ping_tracker_hash_ping_token( ping->ping_token, out_pong->ping_hash );
  gossip->sign_fn( gossip->sign_ctx, out_pong->ping_hash, 32UL, PING_PONG_SIGN_TYPE, out_pong->signature );

  gossip->send_fn( gossip->send_ctx, (uchar *)out_payload, sizeof(out_payload), peer_address, (ulong)now );
  return FD_GOSSIP_RX_OK;
}

static int
rx_pong( fd_gossip_t *           gossip,
         fd_gossip_view_pong_t * pong,
         fd_ip4_port_t *         peer_address,
         long                    now ) {
  if( FD_UNLIKELY( is_entrypoint( gossip, peer_address ) )) return 0;

  fd_ping_tracker_register( gossip->ping_tracker,
                            gossip->crds,
                            pong->pubkey,
                            get_stake( gossip, pong->pubkey ),
                            peer_address,
                            pong->ping_hash,
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
      error = rx_prune( gossip, data, view->prune, now );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      error = rx_ping( gossip, view->ping, peer_address, now );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      error = rx_pong( gossip, view->pong, peer_address, now );
      break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %d", view->tag ));
      break;
  }

  return error;
}

static void
tx_ping( fd_gossip_t * gossip,
         long          now ) {

  /* TODO: have this point to dcache buffer directly instead. */
  uchar out_payload[ sizeof(fd_gossip_view_ping_t) + 4UL ];
  out_payload[0] = FD_GOSSIP_MESSAGE_PING;

  fd_gossip_view_ping_t * out_ping = (fd_gossip_view_ping_t *)( out_payload + 4UL );

  uchar const *         peer_pubkey;
  uchar const *         ping_token;
  fd_ip4_port_t const * peer_address;
  while( fd_ping_tracker_pop_request( gossip->ping_tracker,
                                      now,
                                      gossip->crds,
                                      &peer_pubkey,
                                      &peer_address,
                                      &ping_token ) ) {


    fd_memcpy( out_ping->ping_token, ping_token, 32UL );
    gossip->sign_fn( gossip->sign_ctx, out_ping->ping_token, 32UL, PING_PONG_SIGN_TYPE, out_ping->signature );

    gossip->send_fn( gossip->send_ctx, (uchar *)out_payload, sizeof(out_payload), peer_address, (ulong)now );
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

  //   ulong targets_len[ FD_ACTIVE_SET_MAX_PEERSUL ] = { 0UL };
  //   fd_crds_value_t * targets[ FD_ACTIVE_SET_MAX_PEERSUL ][ 4096UL ];

  //   for( ulong i=0UL i<fd_ulong_min( 9UL, nodes_len ); i++ ) {
  //     targets[ nodes[ i ] ][ targets_len[ nodes[ i ] ] ] = value;
  //     targets_len[ nodes[ i ] ]++;
  //     num_pushes++;
  //     if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
  //   }

  //   if( FD_UNLIKELY( num_pushes>=4096UL ) ) break;
  // }

  // for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERSUL; i++ ) {
  //   fd_gossip_push_t * push = new_outgoing( gossip );

  //   for( ulong j=0UL; j<targets_len[ i ]; j++ ) {
  //     /* TODO: Serialize into minimum number of push packets */
  //   }
  // }

  // gossip->crds_cursor = fd_crds_cursor( gossip->crds );
// }


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

  crds_bloom_t * filter   = gossip->bloom;
  crds_bloom_initialize( filter, (ulong)max_items+1 ); /* TODO: check cast */

  uchar iter_mem[ CRDS_MASK_ITER_SIZE ];

  for( fd_crds_mask_iter_t * it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it = fd_crds_mask_iter_next( it, gossip->crds ) ) {
    crds_bloom_insert( filter, fd_crds_entry_hash( fd_crds_mask_iter_value( it, gossip->crds ) ), 32UL );
  }

  ulong shift = 64UL-mask_bits;
  for( ulong i=0UL; i<fd_crds_purged_len( gossip->crds ); i++ ) {
    /* TODO: Make the purged list also a bplus, for fast finding of matching hashes? */
    uchar const * hash = fd_crds_purged( gossip->crds, i );
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    crds_bloom_insert( filter, hash, 32UL );
  }

  ulong fi_idx = failed_inserts_start_idx( gossip );
  for( ulong i=0UL; i<gossip->failed_inserts.cnt; i++ ) {
    /* TODO: Make the failed insert list also a bplus, for fast finding of matching hashes? */
    uchar const * hash = gossip->failed_inserts.entries[ fi_idx ].hash;
    if( FD_LIKELY( (fd_ulong_load_8( hash )>>shift)!=mask ) ) continue;
    crds_bloom_insert( filter, hash, 32UL );
    fi_idx = (fi_idx+1UL)%gossip->failed_inserts.cap;
  }

  fd_contact_info_t const * peer = fd_crds_peer_sample( gossip->crds, gossip->rng );
  fd_ip4_port_t peer_addr;
  if( FD_UNLIKELY( !peer ) ) {
    /* Choose random entrypoint */
    peer_addr = random_entrypoint( gossip );
  } else {
    peer_addr = fd_contact_info_gossip_socket( peer );
  }

  uchar payload[ 1232UL ];

  fd_gossip_pull_request_encode_ctx_t ctx[ 1 ];
  fd_gossip_pull_request_encode_ctx_init( payload,
                                          1232UL,
                                          filter->keys_len,
                                          (filter->bits_len+7UL)/8UL,
                                          ctx );

  fd_gossip_pull_request_encode_bloom_keys( ctx, filter->keys, filter->keys_len );

  fd_gossip_pull_request_encode_bloom_bits( ctx, filter->bits, filter->bits_len );

  *ctx->mask      = mask;
  *ctx->mask_bits = mask_bits;

  long rem_sz = 1232L - (ctx->contact_info - payload);
  if( FD_UNLIKELY( rem_sz<(long)gossip->my_contact_info.crds_val_sz ) ) {
    FD_LOG_ERR(( "Not enough space in pull request for contact info, check bloom filter params" ));
  }

  fd_memcpy( ctx->contact_info, gossip->my_contact_info.crds_val, gossip->my_contact_info.crds_val_sz );
  ulong payload_sz = (ulong)(ctx->contact_info - payload) + gossip->my_contact_info.crds_val_sz;

  gossip->send_fn( gossip->send_ctx,
                   payload,
                   payload_sz,
                   &peer_addr,
                   (ulong)now );
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

static inline void
rotate_active_set( fd_gossip_t * gossip,
                        long          now ) {
  ulong replaced_idx;
  fd_contact_info_t const * new_peer = fd_active_set_rotate( gossip->active_set, gossip->crds, &replaced_idx );
  if( FD_UNLIKELY( !new_peer ) ) {
    FD_LOG_WARNING(( "No new peer to rotate into active set" ));
  }

  push_state_flush( gossip, &gossip->active_push_state[replaced_idx], now );

  push_state_new( &gossip->active_push_state[replaced_idx],
                  gossip->identity_pubkey,
                  fd_contact_info_gossip_socket( new_peer ) );

}

void
fd_gossip_advance( fd_gossip_t * gossip,
                   long          now ) {
  failed_inserts_purge( gossip, now );
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
    rotate_active_set( gossip, now );
    gossip->next_active_set_refresh = now+300L*1000L*1000L; /* TODO: Jitter */
  }
}
