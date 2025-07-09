#include <math.h>
#include "fd_gossip.h"
#include "fd_bloom.h"
#include "fd_contact_info.h"
#include "fd_gossip_private.h"

#include "crds/fd_crds.h"
#include "fd_active_set.h"
#include "fd_ping_tracker.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard.h"

#define BLOOM_FILTER_MAX_BYTES          (512UL) /* TODO: Calculate for worst case contactinfo */
#define BLOOM_FALSE_POSITIVE_RATE       (  0.1)
#define BLOOM_NUM_KEYS                  (  8.0)

#define PONG_SIGN_TYPE                  FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519
#define GOSSIP_SIGN_TYPE                FD_KEYGUARD_SIGN_TYPE_ED25519

struct stake_weight {
  fd_pubkey_t key;
  ulong       stake;
  ulong       hash;
};
typedef struct stake_weight stake_weight_entry_t;

fd_pubkey_t pubkey_null = { .ul = {0UL,0UL,0UL,0UL} };

#define MAP_NAME               stake_map
#define MAP_T                  stake_weight_entry_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_HASH_T             ulong
#define MAP_KEY_NULL           pubkey_null
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_HASH(key)      ((key).ui[3])
#define MAP_KEY_MOVE(k0,k1)    (fd_memcpy((k0).key,(k1).key,sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_LG_SLOT_CNT        CRDS_MAX_CONTACT_INFO_LG

#include "../../util/tmpl/fd_map.c"

/* Push State holds a gossip push message buffer for
   a valid push destination (e.g., peers in the active set
   or entrypoints). This should be flushed out to the network
   once capacity is reached.

   TODO: move this to a separate CRDS Builder/set API */
struct push_state {
  uchar            msg[ 1232UL ];
  ulong            msg_sz;    /* Also functions as cursor */
  ulong            num_crds;
  fd_ip4_port_t    push_dest;
  uchar            has_my_ci;

  struct {
    ulong next;
  } pool;
  struct{
    long  wallclock_nanos;
    ulong prev;
    ulong next;
  } last_hit;
};

typedef struct push_state push_state_t;

static void
push_state_reset( push_state_t * state,
                  uchar const *  identity_pubkey ) {
  FD_STORE( uint, state->msg, FD_GOSSIP_MESSAGE_PUSH );
  fd_memcpy( &state->msg[ 4 ], identity_pubkey, 32UL );
  state->msg_sz       = 44UL; /* 4 byte tag + 32 byte sender pubkey + 8 byte crds len*/
  state->num_crds     = 0UL;
  state->has_my_ci    = 0U;
  state->push_dest.l  = 0UL;
}

static void
push_state_new( push_state_t * state,
                uchar const * identity_pubkey,
                fd_ip4_port_t push_dest ) {
  push_state_reset( state, identity_pubkey );
  state->push_dest = push_dest;
}

#define POOL_NAME pstate_pool
#define POOL_T    push_state_t
#define POOL_NEXT pool.next
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  pset_last_hit
#define DLIST_ELE_T push_state_t
#define DLIST_PREV  last_hit.prev
#define DLIST_NEXT  last_hit.next

#include "../../util/tmpl/fd_dlist.c"

struct push_set {
  push_state_t *        pool;
  pset_last_hit_t * last_hit;
};

typedef struct push_set push_set_t;

ulong
push_set_align( void ) {
  return pstate_pool_align();
}

ulong
push_set_footprint( ulong ele_max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, pstate_pool_align(), pstate_pool_footprint( ele_max ) );
  l = FD_LAYOUT_APPEND( l, pset_last_hit_align(), pset_last_hit_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(push_set_t), sizeof(push_set_t) );
  l = FD_LAYOUT_FINI( l, push_set_align() );
  return l;
}

void *
push_set_new( void * shmem,
               ulong ele_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_ERR(( "NULL shmem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, push_set_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shmem" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void *       _pool          = FD_SCRATCH_ALLOC_APPEND( l, pstate_pool_align(), pstate_pool_footprint( ele_max ) );
  void *       _last_appended = FD_SCRATCH_ALLOC_APPEND( l, pset_last_hit_align(), pset_last_hit_footprint() );
  push_set_t * push_set       = FD_SCRATCH_ALLOC_APPEND( l, alignof(push_set_t), sizeof(push_set_t) );

  push_set->pool          = pstate_pool_join( pstate_pool_new( _pool, ele_max ) );
  push_set->last_hit = pset_last_hit_join( pset_last_hit_new( _last_appended ) );

  return (void *)push_set;
}

push_set_t *
push_set_join( void * shpool ) {
  if( FD_UNLIKELY( !shpool ) ) {
    FD_LOG_ERR(( "NULL shpool" ));
  }
  return (push_set_t *)shpool;
}

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];
  ulong               identity_stake;

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  fd_sha512_t         sha512[1];

  fd_ip4_port_t       entrypoints[ 16UL ];
  ulong               entrypoints_cnt;

  fd_rng_t *          rng;
  fd_bloom_t *        bloom;

  /* TODO: has_shred_version */
  ushort              expected_shred_version;

  stake_weight_entry_t *    stake_weights;

  /* Event timers */
  struct {
    long next_pull_request;
    long next_active_set_refresh;
    long next_contact_info_refresh;
    long next_flush_push_state;
    long next_metrics_print;
  } timers;

  /* Callbacks */
  fd_gossip_sign_fn   sign_fn;
  void *              sign_ctx;

  fd_gossip_send_fn   send_fn;
  void *              send_ctx;

  struct {
    uchar             crds_val[ 1232UL ];
    ulong             crds_val_sz;
    fd_contact_info_t ci[1];
  } my_contact_info;

  /* Push state for each peer in the active set and entrypoints
     (16 max total). active_push_state tracks the active set, and must be
     flushed prior to a call to fd_active_set_rotate or fd_active_set_prune. */
  push_set_t *        active_pset;

  /* entry_ps is a separate push set that is used on a separate regime,
     typically at bootup when the active set is sparse  */
  push_set_t *        entry_pset;

  fd_gossip_out_ctx_t * gossip_net_out;
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
  l = FD_LAYOUT_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(), stake_map_footprint() );
  l = FD_LAYOUT_APPEND( l, push_set_align(), push_set_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  l = FD_LAYOUT_APPEND( l, push_set_align(), push_set_footprint( 16UL ) );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
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
               void *                    sign_ctx,
               fd_gossip_out_ctx_t *     gossip_update_out,
               fd_gossip_out_ctx_t *     gossip_net_out ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_ERR(( "NULL shmem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_align() ) ) ) {
    FD_LOG_ERR(( "misaligned shmem" ));
  }
  if( FD_UNLIKELY( entrypoints_cnt>16UL ) ) {
    FD_LOG_ERR(( "entrypoints_cnt %lu exceeds maximum of 16", entrypoints_cnt ));
  }
  if( FD_UNLIKELY( !gossip_net_out ) ) {
    FD_LOG_ERR(( "NULL gossip_out" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_t * gossip  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  void * crds           = FD_SCRATCH_ALLOC_APPEND( l, fd_crds_align(), fd_crds_footprint( max_values, max_values*4 ) );
  void * active_set     = FD_SCRATCH_ALLOC_APPEND( l, fd_active_set_align(), fd_active_set_footprint() );
  void * ping_tracker   = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  void * bloom          = FD_SCRATCH_ALLOC_APPEND( l, fd_bloom_align(), fd_bloom_footprint( BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  void * stake_weights  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(), stake_map_footprint() );
  void * active_ps      = FD_SCRATCH_ALLOC_APPEND( l, push_set_align(), push_set_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  void * entry_ps       = FD_SCRATCH_ALLOC_APPEND( l, push_set_align(), push_set_footprint( 16UL ) );

  gossip->gossip_net_out  = gossip_net_out;

  gossip->entrypoints_cnt = entrypoints_cnt;
  fd_memcpy( gossip->entrypoints, entrypoints, entrypoints_cnt*sizeof(fd_ip4_port_t) );

  gossip->crds          = fd_crds_join( fd_crds_new( crds, rng, max_values, max_values*4, gossip_update_out ) );
  gossip->active_set    = fd_active_set_join( fd_active_set_new( active_set, rng ) );
  gossip->ping_tracker  = fd_ping_tracker_join( fd_ping_tracker_new( ping_tracker, rng ) );
  gossip->bloom         = fd_bloom_join( fd_bloom_new( bloom, rng, BLOOM_FALSE_POSITIVE_RATE, BLOOM_FILTER_MAX_BYTES ) );
  gossip->stake_weights = stake_map_join( stake_map_new( stake_weights ) );
  gossip->active_pset   = push_set_join( push_set_new( active_ps, FD_ACTIVE_SET_MAX_PEERS ) );
  gossip->entry_pset    = push_set_join( push_set_new( entry_ps, 16UL ) );

  fd_sha512_init( gossip->sha512 );
  gossip->rng = rng;

  gossip->send_fn   = send_fn;
  gossip->send_ctx  = send_ctx;
  gossip->sign_fn   = sign_fn;
  gossip->sign_ctx  = sign_ctx;

  /* Initializing a push set is weird. We "acquire" all elements in the
     respective pools, effectively treating them as static arrays.
     We use fd_pool APIs because fd_dlist doesn't work otherwise and
     there are no suitable linked list APIs */
  push_set_t * ps = gossip->active_pset;
  for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERS; i++ ) {
    push_state_t * entry = pstate_pool_ele_acquire( ps->pool );
    push_state_reset( entry, gossip->identity_pubkey );
    entry->last_hit.wallclock_nanos = now;
    pset_last_hit_ele_push_tail( ps->last_hit, entry, ps->pool );
  }
  ps = gossip->entry_pset;
  for( ulong i=0UL; i<entrypoints_cnt; i++ ) {
    push_state_t * entry = pstate_pool_ele_acquire( gossip->entry_pset->pool );
    /* Entrypoint ip destinations are known, so we use new instead of
       reset */
    push_state_new( entry, gossip->identity_pubkey, gossip->entrypoints[i] );
    entry->last_hit.wallclock_nanos = now;
    pset_last_hit_ele_push_tail( ps->last_hit, entry, ps->pool );
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

static inline void
metrics_update( fd_gossip_t * gossip ) {
  fd_gossip_metrics_t * metrics = gossip->metrics;

  metrics->table_size  = fd_crds_len( gossip->crds );
  metrics->purged_size = fd_crds_purged_len( gossip->crds );
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
push_state_flush( fd_gossip_t *       gossip,
                  push_state_t *      state,
                  fd_stem_context_t * stem,
                  long                now ) {
  if( FD_UNLIKELY( !state->num_crds ) ) return;
  FD_STORE( ulong, &state->msg[ 36UL ], state->num_crds );
  if( FD_LIKELY( state->push_dest.l ) ){
    gossip->send_fn( gossip->send_ctx, stem, state->msg, state->msg_sz, &state->push_dest, (ulong)now );
    uint msg_type = FD_LOAD( uint, state->msg );
    gossip->metrics->packets_tx[ msg_type ]++; /* might be push or pull resp */
  }

  /* Reset the push state */
  state->msg_sz                        = 44UL; /* 4 byte tag + 32 byte sender pubkey */
  state->num_crds                      = 0UL;
  state->has_my_ci                     = 0;
}

static void
push_state_append_crds( fd_gossip_t *       gossip,
                        push_state_t *      state,
                        uchar const *       crds_bytes,
                        ulong               crds_sz,
                        fd_stem_context_t * stem,
                        long                now ) {
  ulong remaining_space = fd_ulong_sat_sub( sizeof(state->msg), state->msg_sz );
  if( FD_UNLIKELY( remaining_space<crds_sz ) ) {
    push_state_flush( gossip, state, stem, now );
    remaining_space = fd_ulong_sat_sub( sizeof(state->msg), state->msg_sz );
  }
  if( FD_UNLIKELY( remaining_space<crds_sz ) ) {
    FD_LOG_CRIT(( "Not enough space in push state to append CRDS value of size %lu even after flushing", crds_sz ));
  }
  fd_memcpy( &state->msg[ state->msg_sz ], crds_bytes, crds_sz );
  state->msg_sz   += crds_sz;
  state->num_crds += 1UL;
}

static void
push_set_pop_append( push_set_t *   pset,
                     push_state_t * state,
                     long           now ) {
  state->last_hit.wallclock_nanos = now;
  pset_last_hit_ele_remove( pset->last_hit, state, pset->pool );
  pset_last_hit_ele_push_tail( pset->last_hit, state, pset->pool );
}

static void
push_set_flush_idx( fd_gossip_t *       gossip,
                    push_set_t *        pset,
                    ulong               idx,
                    fd_stem_context_t * stem,
                    long                now ) {
  push_state_t * state = pstate_pool_ele( pset->pool, idx );
  push_state_flush( gossip, state, stem, now );
  push_set_pop_append( pset, state, now );
}



static void
push_set_append_crds_idx( fd_gossip_t *       gossip,
                          push_set_t *        pset,
                          ulong               idx,
                          uchar const *       crds_bytes,
                          ulong               crds_sz,
                          fd_stem_context_t * stem,
                          long                now ) {
  push_state_t * state = pstate_pool_ele( pset->pool, idx );
  push_state_append_crds( gossip, state, crds_bytes, crds_sz, stem, now );
  push_set_pop_append( pset, state, now );
}

static void
push_state_insert( fd_gossip_t *                       gossip,
                   fd_gossip_view_crds_value_t const * value,
                   uchar const *                       payload,
                   uchar const *                       origin_pubkey,
                   ulong                               origin_stake,
                    fd_stem_context_t *                stem,
                   long                                now ) {
  ulong out_nodes[ 12UL ];
  ulong out_nodes_cnt = fd_active_set_nodes( gossip->active_set,
                                             gossip->identity_pubkey,
                                             gossip->identity_stake,
                                             origin_pubkey,
                                             origin_stake,
                                             0UL, /* ignore_prunes_if_peer_is_origin TODO */
                                             out_nodes );
  for( ulong j=0UL; j<out_nodes_cnt; j++ ) {
    ulong idx            = out_nodes[ j ];
    push_set_append_crds_idx( gossip,
                              gossip->active_pset,
                              idx,
                              payload+value->value_off,
                              value->length,
                              stem,
                              now );
  }
}

static void
push_my_contact_info( fd_gossip_t * gossip,
                      fd_stem_context_t * stem,
                      long now ){
  for( ulong i=0UL; i<FD_ACTIVE_SET_MAX_PEERS; i++ ) {
    push_state_t * state = pstate_pool_ele( gossip->active_pset->pool, i );
    if( state->has_my_ci ) continue;
    push_set_append_crds_idx( gossip,
                              gossip->active_pset,
                              i,
                              gossip->my_contact_info.crds_val,
                              gossip->my_contact_info.crds_val_sz,
                              stem,
                              now );
    state->has_my_ci = 1;
  }
  for( ulong i=0UL; i<gossip->entrypoints_cnt; i++ ) {
    push_state_t * state = pstate_pool_ele( gossip->entry_pset->pool, i );
    if( state->has_my_ci ) continue;
    push_set_append_crds_idx( gossip,
                              gossip->entry_pset,
                              i,
                              gossip->my_contact_info.crds_val,
                              gossip->my_contact_info.crds_val_sz,
                              stem,
                              now );
    state->has_my_ci = 1;
  }
}

static inline void
refresh_contact_info( fd_gossip_t *       gossip,
                      long                now ) {
  gossip->my_contact_info.ci->wallclock_nanos = now;
  fd_gossip_contact_info_encode( gossip->my_contact_info.ci,
                                 gossip->my_contact_info.crds_val,
                                 1232UL,
                                 &gossip->my_contact_info.crds_val_sz );
  gossip->sign_fn( gossip->sign_ctx,
                   gossip->my_contact_info.crds_val+64UL,
                   gossip->my_contact_info.crds_val_sz-64UL,
                   GOSSIP_SIGN_TYPE,
                   gossip->my_contact_info.crds_val );

  /* We don't have stem_ctx here so we pre-empt in next
     fd_gossip_advance iteration instead. */
  gossip->timers.next_contact_info_refresh = now;
}

void
fd_gossip_set_my_contact_info( fd_gossip_t *             gossip,
                               fd_contact_info_t const * contact_info,
                               long                      now ) {
  fd_memcpy( gossip->identity_pubkey, contact_info->pubkey.uc, 32UL );
  gossip->expected_shred_version = contact_info->shred_version;

  *gossip->my_contact_info.ci = *contact_info;
  refresh_contact_info( gossip, now );
}

ulong
get_stake( fd_gossip_t const * gossip,
           uchar const * pubkey ) {
  stake_weight_entry_t const * entry = stake_map_query_const( gossip->stake_weights, *(fd_pubkey_t const *)pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    return 0UL;
  }
  return entry->stake;
}

void
fd_gossip_stakes_update( fd_gossip_t *             gossip,
                         fd_stake_weight_t const * stake_weights,
                         ulong                     stake_weights_cnt ) {
  if( FD_UNLIKELY( stake_weights_cnt>CRDS_MAX_CONTACT_INFO ) ) {
    FD_LOG_ERR(( "stake_weights_cnt %lu exceeds maximum of %d", stake_weights_cnt, CRDS_MAX_CONTACT_INFO ));
  }

  stake_map_clear( gossip->stake_weights );

  for( ulong i=0UL; i<stake_weights_cnt; i++ ) {
    stake_weight_entry_t * entry = stake_map_insert( gossip->stake_weights, stake_weights[i].key );
    if( FD_UNLIKELY( !entry ) ) {
      FD_LOG_ERR(( "Failed to insert stake weight" ));
    }
    entry->stake = stake_weights[i].stake;
  }
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
verify_crds_value( fd_gossip_view_crds_value_t const * value,
                    uchar const *                      payload,
                    fd_sha512_t *                      sha ) {
    return fd_ed25519_verify( payload+value->signature_off+64UL, /* signable data begins after signature */
                              value->length-64UL,                /* signable data length */
                              payload+value->signature_off,
                              payload+value->pubkey_off,
                              sha );
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
      return verify_crds_value( view->pull_request->contact_info, payload, sha );
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
    case FD_GOSSIP_MESSAGE_PUSH:
    /* Push and pull resp CRDS values are verified in their
       respective rx_* loops */
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      return verify_prune( view->prune, payload, sha );
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      return verify_ping_pong( view, sha );
    default:
      return -1;
  };
  return FD_ED25519_SUCCESS;
}

static int
rx_pull_request( fd_gossip_t *                         gossip,
                 fd_gossip_view_pull_request_t const * pr_view,
                 uchar const *                         payload,
                 fd_ip4_port_t const *                 peer_addr,
                 fd_stem_context_t *                   stem,
                 long                                  now ) {
  /* TODO: Implement data budget? Or at least limit iteration range */

  fd_gossip_view_crds_value_t const * contact_info = pr_view->contact_info;

  /* Some pull requests still attach legacy contact infos instead of the
     current type. We choose to ignore such pull requests entirely since
     legacy contact infos should be fully deprecated. */
  if( FD_UNLIKELY( contact_info->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) return -1;

  if( FD_UNLIKELY( !memcmp( payload+contact_info->pubkey_off, gossip->identity_pubkey, 32UL ) ) ) return -1;

  uchar const * node = payload+contact_info->pubkey_off;
  ulong node_stake = get_stake( gossip, node );

  if( FD_UNLIKELY( !fd_ping_tracker_active( gossip->ping_tracker,
                                            node,
                                            node_stake,
                                            peer_addr,
                                            now ) &&
                   !is_entrypoint( gossip, peer_addr) ) ) {
    fd_ping_tracker_track( gossip->ping_tracker,
                           node,
                           node_stake,
                           peer_addr,
                           now );
    return -1;
  }

  fd_bloom_t filter[1];
  filter->keys_len = pr_view->bloom_keys_len;
  filter->keys     = (ulong *)( payload + pr_view->bloom_keys_offset );

  filter->bits_len = pr_view->bloom_bits_cnt;
  filter->bits     = (ulong *)( payload + pr_view->bloom_bits_offset );

  /* TODO: Jitter? */
  long clamp_wallclock_lower_nanos = now - 15L*1000L*1000L*1000L;
  long clamp_wallclock_upper_nanos = now + 15L*1000L*1000L*1000L;
  if( FD_UNLIKELY( contact_info->wallclock_nanos<clamp_wallclock_lower_nanos ||
                   contact_info->wallclock_nanos>clamp_wallclock_upper_nanos ) ) return -1;

  /* We use push_state since a pullresponse is identical save for the message discriminant */
  push_state_t pull_resp[1];
  push_state_new( pull_resp, gossip->identity_pubkey, *peer_addr );
  pull_resp->msg[ 0 ] = FD_GOSSIP_MESSAGE_PULL_RESPONSE;

  uchar iter_mem[ 16UL ];

  for( fd_crds_mask_iter_t * it=fd_crds_mask_iter_init( gossip->crds, pr_view->mask, pr_view->mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it=fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_crds_entry_t const * candidate = fd_crds_mask_iter_entry( it, gossip->crds );

    /* TODO: Add jitter here? */
    // if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock_nanos ) ) continue;

    if( FD_UNLIKELY( !fd_bloom_contains( filter, fd_crds_entry_hash( candidate ), 32UL ) ) ) continue;

    uchar const * crds_val;
    ulong         crds_size;
    fd_crds_entry_value( candidate, &crds_val, &crds_size );
    push_state_append_crds( gossip, pull_resp, crds_val, crds_size, stem, now );
  }
  push_state_flush( gossip, pull_resp, stem, now );
  return 0;
}


static int
rx_pull_response( fd_gossip_t *                          gossip,
                  fd_gossip_view_pull_response_t const * pull_response,
                  uchar const *                          payload,
                  fd_stem_context_t *                    stem,
                  long                                   now ) {
  /* TODO: use epoch_duration and make timeouts ... ? */

  for( ulong i=0UL; i<pull_response->crds_values_len; i++ ) {
    gossip->metrics->pull->values_rx++;
    fd_gossip_view_crds_value_t const * value = &pull_response->crds_values[ i ];

    int checks_res = fd_crds_checks_fast( gossip->crds,
                                             value,
                                             payload,
                                             0 /* from_push_msg m*/ );
    if( FD_UNLIKELY( !!checks_res ) ) {
      checks_res < 0 ? gossip->metrics->pull->too_old++ : gossip->metrics->pull->duplicates++;
      continue;
    }

    uchar const * origin_pubkey    = payload+value->pubkey_off;
    ulong origin_stake             = get_stake( gossip, origin_pubkey );

    /* TODO: Is this jittered in Agave? */
    long accept_after_nanos;
    uchar is_me = !memcmp( origin_pubkey, gossip->identity_pubkey, 32UL );
    if( FD_UNLIKELY( is_me ) ) {
      accept_after_nanos = 0L;
    } else if( !origin_stake ) {
      accept_after_nanos = now-15L*1000L*1000L*1000L;
    } else {
      accept_after_nanos = now-432000L*1000L*1000L*1000L;
    }

    /* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/crds_gossip_pull.rs#L340-L351 */
    if( FD_UNLIKELY( accept_after_nanos>value->wallclock_nanos &&
                     !fd_crds_contact_info_lookup( gossip->crds, origin_pubkey ) ) ) {
      gossip->metrics->pull->too_old++;
      uchar candidate_hash[ 32UL ];
      fd_crds_genrate_hash( payload+value->value_off, value->length, candidate_hash );
      fd_crds_insert_failed_insert( gossip->crds, candidate_hash, now );
      continue;
    }

    int err = verify_crds_value( value, payload, gossip->sha512 );
    if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) {
      continue;
    } else {
      gossip->metrics->verified[ FD_GOSSIP_MESSAGE_PULL_RESPONSE ]++;
    }

    fd_crds_entry_t const * candidate = fd_crds_insert( gossip->crds,
                                                        value,
                                                        payload,
                                                        origin_stake,
                                                        checks_res,
                                                        is_me,
                                                        now,
                                                        stem );
    if( FD_UNLIKELY( !candidate ) ) continue;
    gossip->metrics->pull->upserted++;
    if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ){
      fd_contact_info_t const * contact_info = fd_crds_entry_contact_info( candidate );
      fd_ip4_port_t origin_addr              = fd_contact_info_gossip_socket( contact_info );
      if( FD_LIKELY( !is_entrypoint( gossip, &origin_addr ) ) ){
        int active = fd_ping_tracker_active( gossip->ping_tracker,
                                             origin_pubkey,
                                             origin_stake,
                                             &origin_addr,
                                             now );
        active ? fd_crds_peer_active( gossip->crds, origin_pubkey, now )
               : fd_crds_peer_inactive( gossip->crds, origin_pubkey, now );

        fd_ping_tracker_track( gossip->ping_tracker,
                                origin_pubkey,
                                origin_stake,
                                &origin_addr,
                                now );
      }
    }
    push_state_insert( gossip,
                       value,
                       payload,
                       origin_pubkey,
                       origin_stake,
                       stem,
                       now );
  }
  return 0;
}

/* process_push_crds() > 0 holds the duplicate count */
static int
process_push_crds( fd_gossip_t *                       gossip,
                   fd_gossip_view_crds_value_t const * value,
                   uchar const *                       payload,
                   long                                now,
                   fd_stem_context_t *                 stem ) {
  gossip->metrics->push->values_rx++;
  /* TODO: pretty sure this is 15s now. */
  if( FD_UNLIKELY( value->wallclock_nanos<now-30L*1000L*1000L*1000L || value->wallclock_nanos>now+30L*1000L*1000L*1000L ) ) return -1;
  /* overrides_fast here, either count duplicates or purge if older (how!?) */


  /* return values in both fd_crds_checks_fast and fd_crds_inserted need
     to be propagated since they both work the same (error>0 holds duplicate
     count). This is quite fragile. */
  int checks_res = fd_crds_checks_fast( gossip->crds,
                                        value,
                                        payload,
                                        1 /* from_push_msg */ );
  if( FD_UNLIKELY( !!checks_res ) ) {
    checks_res<0 ? gossip->metrics->push->too_old++ : gossip->metrics->push->duplicates++;
    return checks_res;
  }

  int err = verify_crds_value( value, payload, gossip->sha512 );
  if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) {
    return -1;
  } else {
    gossip->metrics->verified[ FD_GOSSIP_MESSAGE_PUSH ]++;
  }

  uchar const * origin_pubkey    = payload+value->pubkey_off;
  uchar is_me                    = !memcmp( origin_pubkey, gossip->identity_pubkey, 32UL );
  ulong origin_stake             = get_stake( gossip, origin_pubkey );


  fd_crds_entry_t const * candidate = fd_crds_insert( gossip->crds,
                                                      value,
                                                      payload,
                                                      origin_stake,
                                                      checks_res,
                                                      is_me,
                                                      now,
                                                      stem );
  if( FD_UNLIKELY( !candidate ) ) return -1;

  gossip->metrics->push->upserted++;
  if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ) {
    fd_contact_info_t const * contact_info = fd_crds_entry_contact_info( candidate );
    fd_ip4_port_t origin_addr              = fd_contact_info_gossip_socket( contact_info );
    if( FD_LIKELY( !is_entrypoint( gossip, &origin_addr ) ) ) {
      int active = fd_ping_tracker_active( gossip->ping_tracker,
                                          origin_pubkey,
                                          origin_stake,
                                          &origin_addr,
                                          now );
      active ? fd_crds_peer_active( gossip->crds, origin_pubkey, now )
             : fd_crds_peer_inactive( gossip->crds, origin_pubkey, now );

      fd_ping_tracker_track( gossip->ping_tracker,
                            origin_pubkey,
                            origin_stake,
                            &origin_addr,
                            now );
    }
  }
  push_state_insert( gossip,
                     value,
                     payload,
                     origin_pubkey,
                     origin_stake,
                     stem,
                     now );
  return 0;
}

static int
rx_push( fd_gossip_t *                 gossip,
         fd_gossip_view_push_t const * push,
         uchar const *                 payload,
         long                          now,
         fd_stem_context_t *           stem ) {
  for( ulong i=0UL; i<push->crds_values_len; i++ ) {
    int err = process_push_crds( gossip,
                                 &push->crds_values[ i ],
                                 payload,
                                 now,
                                 stem );
    if( FD_UNLIKELY( err>0 ) ) {
      /* TODO: implement prune finder
      ulong num_duplicates         = (ulong)err;
      uchar const * relayer_pubkey = payload+push->from_off;
      fd_prune_finder_record( gossip->prune_finder,
                              origin_pubkey,
                              origin_stake,
                              relayer_pubkey,
                              get_stake( gossip, relayer_pubkey ),
                              num_duplicates ); */
    }
  }

  return 0;
}

static int
rx_prune( fd_gossip_t *                  gossip,
          uchar const *                  payload,
          fd_gossip_view_prune_t const * prune,
          long                           now ) {
  if( FD_UNLIKELY( now-FD_MILLI_TO_NANOSEC(500L)>(long)prune->wallclock_nanos ) ) return -1;
  else if( FD_UNLIKELY( !!memcmp( gossip->identity_pubkey, payload+prune->destination_off, 32UL ) ) ) return -1;


  fd_active_set_prunes( gossip->active_set,
                        gossip->identity_pubkey,
                        gossip->identity_stake,
                        payload+prune->prunes_off,
                        prune->prunes_len,
                        payload+prune->origin_off,
                        get_stake( gossip, payload+prune->origin_off ),
                        NULL /* TODO: use out_node_idx to update push states */ );

  return 0;
}


static int
rx_ping( fd_gossip_t *           gossip,
         fd_gossip_view_ping_t * ping,
         fd_ip4_port_t *         peer_address,
         fd_stem_context_t *     stem,
         long                    now ) {
  /* TODO: have this point to dcache buffer directly instead */
  uchar out_payload[ sizeof(fd_gossip_view_pong_t) + 4UL];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PONG );

  fd_gossip_view_pong_t * out_pong = (fd_gossip_view_pong_t *)(out_payload + 4UL);
  fd_memcpy( out_pong->pubkey, gossip->identity_pubkey, 32UL );

  /* fd_keyguard checks payloads for certain patterns before performing the
     sign. Pattern-matching can't be done on hashed data, so we need
     to supply the pre-hashed image to the sign fn (fd_keyguard will hash when
     supplied with FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519) while also hashing
     the image ourselves onto pong->ping_hash */

  /* Clobber the ping message pubkey since we already verified the message at
     this point */
  uchar *    pre_hash_img = ping->ping_token-16UL;
  fd_memcpy( pre_hash_img, "SOLANA_PING_PONG", 16UL );

  fd_sha256_hash( pre_hash_img, 48UL, out_pong->ping_hash );
  gossip->sign_fn( gossip->sign_ctx, pre_hash_img, 48UL, PONG_SIGN_TYPE, out_pong->signature );

  gossip->send_fn( gossip->send_ctx, stem, (uchar *)out_payload, sizeof(out_payload), peer_address, (ulong)now );
  gossip->metrics->packets_tx[ FD_GOSSIP_MESSAGE_PONG ]++;
  return 0;
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

  *payload     = (uchar *)( (ulong)udp + sizeof(fd_udp_hdr_t) );
  *payload_sz  = payload_sz_;

  if( FD_UNLIKELY( (ulong)(*payload)+payload_sz_>(ulong)data+data_sz ) )
    FD_LOG_ERR(( "Malformed UDP payload" ));

  peer_address->addr = ip4->saddr;
  peer_address->port = udp->net_sport;
  return 0;
}

int
fd_gossip_rx( fd_gossip_t * gossip,
              uchar const * packet,
              ulong         packet_sz,
              long          now,
              fd_stem_context_t * stem ) {

  uchar *       gossip_payload;
  ulong         gossip_payload_sz;
  fd_ip4_port_t peer_address[1];

  // FD_LOG_WARNING(( "fd_gossip_rx: data_sz=%lu", data_sz ));

  int error = strip_network_hdrs( packet,
                                  packet_sz,
                                  &gossip_payload,
                                  &gossip_payload_sz,
                                  peer_address );
  if( FD_UNLIKELY( error ) ) return error;

  fd_gossip_view_t view[ 1 ];
  ulong decode_sz = fd_gossip_msg_parse( view, gossip_payload, gossip_payload_sz );
  if( FD_UNLIKELY( !decode_sz ) ) {
    FD_LOG_WARNING(( "Failed to decode gossip message" ));
    return -1;
  }
  gossip->metrics->packets_rx[ view->tag ]++;

  error = verify_signatures( view, gossip_payload, gossip->sha512 );
  if( FD_UNLIKELY( error ) ) return error;

  // error = filter_shred_version( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  // error = check_duplicate_instance( gossip, message );
  // if( FD_UNLIKELY( error ) ) return error;

  if( FD_UNLIKELY( error ) ) return error;

  /* TODO: Implement traffic shaper / bandwidth limiter */

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      error = rx_pull_request( gossip,
                               view->pull_request,
                               gossip_payload,
                               peer_address,
                               stem,
                               now );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      error = rx_pull_response( gossip, view->pull_response, gossip_payload, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      error = rx_push( gossip, view->push, gossip_payload, now, stem );
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      error = rx_prune( gossip, gossip_payload, view->prune, now );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      error = rx_ping( gossip, view->ping, peer_address, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      error = rx_pong( gossip, view->pong, peer_address, now );
      break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %d", view->tag ));
      break;
  }
  metrics_update( gossip );

  return error;
}

int
fd_gossip_push_vote( fd_gossip_t *       gossip,
                     uchar const *       txn,
                     ulong               txn_sz,
                     fd_stem_context_t * stem,
                     long                now ) {
  /* TODO: we can avoid addt'l memcpy if we pass a propely laid out
     crds buffer instead */
  uchar crds_val[ 1232UL ];
  ulong crds_val_sz;
  fd_gossip_crds_vote_encode( crds_val,
                              1232UL,
                              txn,
                              txn_sz,
                              gossip->identity_pubkey,
                              now,
                              &crds_val_sz );
  fd_gossip_view_crds_value_t value[1];

  gossip->sign_fn( gossip->sign_ctx,
                   crds_val+64UL,
                   crds_val_sz-64UL,
                   GOSSIP_SIGN_TYPE,
                   crds_val );

  value->tag                   = FD_GOSSIP_VALUE_VOTE;
  value->value_off             = 0UL;
  value->length                = (ushort)crds_val_sz;
  value->pubkey_off            = 64UL+1UL; /* Signature + vote index */
  value->wallclock_nanos       = now;
  fd_gossip_view_vote_t * vote = value->vote;
  vote->index                  = 0UL; /* TODO */
  vote->txn_sz                 = (ushort)txn_sz;
  vote->txn_off                = 64UL+1UL+32UL; /* Signature + vote index + pubkey */

  int res = fd_crds_checks_fast( gossip->crds,
                                 value,
                                 crds_val,
                                 0 );
  if( FD_UNLIKELY( res ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_crds_insert( gossip->crds,
                                     value,
                                     crds_val,
                                     gossip->identity_stake,
                                     res,
                                     1, /* is_me */
                                     now,
                                     stem ) ) ) {
    return -1;
  }
  /* TODO: Possibly flush if we want this out ASAP? */
  push_state_insert( gossip,
                     value,
                     crds_val,
                     gossip->identity_pubkey,
                     gossip->identity_stake,
                     stem,
                     now );
  return 0;
}

static void
tx_ping( fd_gossip_t *       gossip,
         fd_stem_context_t * stem,
         long                now ) {

  /* TODO: have this point to dcache buffer directly instead. */
  uchar out_payload[ sizeof(fd_gossip_view_ping_t) + 4UL ];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PING );

  fd_gossip_view_ping_t * out_ping = (fd_gossip_view_ping_t *)( out_payload + 4UL );
  fd_memcpy( out_ping->pubkey, gossip->identity_pubkey, 32UL );

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

    gossip->sign_fn( gossip->sign_ctx, out_ping->ping_token, 32UL, GOSSIP_SIGN_TYPE, out_ping->signature );
    gossip->send_fn( gossip->send_ctx, stem, out_payload, sizeof(out_payload), peer_address, (ulong)now );
    gossip->metrics->packets_tx[ FD_GOSSIP_MESSAGE_PING ]++;
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
tx_pull_request( fd_gossip_t *       gossip,
                 fd_stem_context_t * stem,
                 long                now ) {
  ulong total_crds_vals = fd_crds_len( gossip->crds ) + fd_crds_purged_len( gossip->crds );
  ulong num_items       = fd_ulong_max( 512UL, total_crds_vals );

  double max_bits       = (double)(BLOOM_FILTER_MAX_BYTES*8UL);
  double max_items      = ceil(max_bits / ( -BLOOM_NUM_KEYS / log( 1.0 - exp( log( BLOOM_FALSE_POSITIVE_RATE ) / BLOOM_NUM_KEYS) )));
  double _mask_bits     = ceil( log2( (double)num_items / max_items ) );
  uint mask_bits        = _mask_bits >= 0.0 ? (uint)_mask_bits : 0UL;
  ulong mask            = fd_rng_ulong( gossip->rng ) | (~0UL>>(mask_bits));

  fd_bloom_t * filter   = gossip->bloom;
  fd_bloom_initialize( filter, (ulong)max_items+1 );

  uchar iter_mem[ 16UL ];
  for( fd_crds_mask_iter_t * it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it = fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_bloom_insert( filter, fd_crds_entry_hash( fd_crds_mask_iter_entry( it, gossip->crds ) ), 32UL );
  }

  for( fd_crds_mask_iter_t * it = fd_crds_purged_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_purged_mask_iter_done( it, gossip->crds );
       it = fd_crds_purged_mask_iter_next( it, gossip->crds ) ){
    fd_bloom_insert( filter, fd_crds_purged_mask_iter_hash( it, gossip->crds ), 32UL );
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

  fd_gossip_view_pull_request_t view[ 1 ];
  fd_gossip_pull_request_encode_ctx_init( payload,
                                          1232UL,
                                          filter->keys_len,
                                          (filter->bits_len),
                                          mask,
                                          mask_bits,
                                          view );

  fd_gossip_pull_request_encode_bloom_keys( view, payload, filter->keys, filter->keys_len );
  fd_gossip_pull_request_encode_bloom_bits( view, payload, filter->bits, filter->bits_len );

  long rem_sz = 1232L - view->contact_info->value_off;
  if( FD_UNLIKELY( rem_sz<(long)gossip->my_contact_info.crds_val_sz ) ) {
    FD_LOG_ERR(( "Not enough space in pull request for contact info, check bloom filter params" ));
  }

  fd_memcpy( payload+view->contact_info->value_off, gossip->my_contact_info.crds_val, gossip->my_contact_info.crds_val_sz );
  ulong payload_sz = view->contact_info->value_off + gossip->my_contact_info.crds_val_sz;

  gossip->send_fn( gossip->send_ctx,
                   stem,
                   payload,
                   payload_sz,
                   &peer_addr,
                   (ulong)now );
  gossip->metrics->packets_tx[ FD_GOSSIP_MESSAGE_PULL_REQUEST ]++;
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
  return now+1600L*1000L;
}

static inline void
rotate_active_set( fd_gossip_t *       gossip,
                   fd_stem_context_t * stem,
                   long                now ) {
  ulong replaced_idx;
  fd_contact_info_t const * new_peer = fd_active_set_rotate( gossip->active_set, gossip->crds, &replaced_idx );
  if( FD_UNLIKELY( !new_peer ) ) {
    return;
  }

  push_set_flush_idx( gossip, gossip->active_pset, replaced_idx, stem, now );

  push_state_new( pstate_pool_ele( gossip->active_pset->pool, replaced_idx ),
                  gossip->identity_pubkey,
                  fd_contact_info_gossip_socket( new_peer ) );
}

static inline void
flush_stale_push_states( fd_gossip_t * gossip,
                         push_set_t  * push_set,
                         fd_stem_context_t * stem,
                         long          now ) {
  long stale_if_before = now-1*1000L*1000L;
  for(;;) {
    push_state_t * state = pset_last_hit_ele_peek_head( push_set->last_hit, push_set->pool );
    if( FD_UNLIKELY( state->last_hit.wallclock_nanos>stale_if_before ) ) break;
    push_set_flush_idx( gossip, push_set, pstate_pool_idx( push_set->pool, state ), stem, now );
  }
}


static inline void
metrics_print_crds( crds_metrics_t const * new, crds_metrics_t const * old ) {
  FD_LOG_NOTICE(( "Total Rx\t\t: %lu", new->values_rx - old->values_rx ));
  FD_LOG_NOTICE(( "Upserts\t\t: %lu",   new->upserted - old->upserted ));
  FD_LOG_NOTICE(( "Duplicates\t\t: %lu",  new->duplicates - old->duplicates ));
  FD_LOG_NOTICE(( "Too Old\t\t: %lu",   new->too_old - old->too_old ));
}

static inline void
metrics_print( fd_gossip_t * gossip ){
  static fd_gossip_metrics_t prev_metrics[ 1 ];
  fd_gossip_metrics_t *      metrics = gossip->metrics;

  FD_LOG_NOTICE(( "========== GOSSIP METRICS ==========" ));
  FD_LOG_NOTICE(( "Table size\t\t: %lu",     metrics->table_size ));
  FD_LOG_NOTICE(( "Purged size\t\t: %lu",    metrics->purged_size ));
  FD_LOG_NOTICE(( "Num peers\t\t: %lu",      fd_crds_peer_count( gossip->crds ) ));

  FD_LOG_NOTICE(("---------- Push Ingress ----------"));
  metrics_print_crds( metrics->push, prev_metrics->push );
  FD_LOG_NOTICE(("--------- Pull Ingress -----------"));
  metrics_print_crds( metrics->pull, prev_metrics->pull );

  FD_LOG_NOTICE(( "-------- Packets Received --------" ));
  FD_LOG_NOTICE(( "Pull Requests\t: %lu",   metrics->packets_rx[ 0U ] - prev_metrics->packets_rx[ 0U ] ));
  FD_LOG_NOTICE(( "Pull Responses\t: %lu",  metrics->packets_rx[ 1U ] - prev_metrics->packets_rx[ 1U ] ));
  FD_LOG_NOTICE(( "Pushes\t\t: %lu",        metrics->packets_rx[ 2U ] - prev_metrics->packets_rx[ 2U ] ));
  FD_LOG_NOTICE(( "Pings\t\t: %lu",         metrics->packets_rx[ 4U ] - prev_metrics->packets_rx[ 4U ] ));
  FD_LOG_NOTICE(( "Pongs\t\t: %lu",         metrics->packets_rx[ 5U ] - prev_metrics->packets_rx[ 5U ] ));

  // FD_LOG_NOTICE(( "-------- Packets verified ---------" ));
  // FD_LOG_NOTICE(( "Pull Requests\t\t: %lu",   metrics->verified[ 0U ] - prev_metrics->verified[ 0U ] ));
  // FD_LOG_NOTICE(( "Pull Responses\t: %lu",  metrics->verified[ 1U ] - prev_metrics->verified[ 1U ] ));
  // FD_LOG_NOTICE(( "Pushes\t\t: %lu",        metrics->verified[ 2U ] - prev_metrics->verified[ 2U ] ));
  // // FD_LOG_NOTICE(( "Prunes\t\t: %lu", metrics->verified[ 3U ] - prev_metrics->verified[ 3U ] ));
  // FD_LOG_NOTICE(( "Pings\t\t\t: %lu",         metrics->verified[ 4U ] - prev_metrics->verified[ 4U ] ));
  // FD_LOG_NOTICE(( "Pongs\t\t\t: %lu",         metrics->verified[ 5U ] - prev_metrics->verified[ 5U ] ));

  FD_LOG_NOTICE(( "---------- Packets Sent ----------" ));
  FD_LOG_NOTICE(( "Pull Requests\t: %lu",   metrics->packets_tx[ 0U ] - prev_metrics->packets_tx[ 0U ] ));
  FD_LOG_NOTICE(( "Pull Responses\t: %lu",  metrics->packets_tx[ 1U ] - prev_metrics->packets_tx[ 1U ] ));
  FD_LOG_NOTICE(( "Pushes\t\t: %lu",        metrics->packets_tx[ 2U ] - prev_metrics->packets_tx[ 2U ] ));
  // FD_LOG_NOTICE(( "Prunes\t\t: %lu", metrics->packets_tx[ 3U ] - prev_metrics->packets_tx[ 3U ] ));
  FD_LOG_NOTICE(( "Pings\t\t: %lu",         metrics->packets_tx[ 4U ] - prev_metrics->packets_tx[ 4U ] ));
  FD_LOG_NOTICE(( "Pongs\t\t: %lu",         metrics->packets_tx[ 5U ] - prev_metrics->packets_tx[ 5U ] ));

  *prev_metrics = *metrics;
}


void
fd_gossip_advance( fd_gossip_t *       gossip,
                   long                now,
                   fd_stem_context_t * stem ) {
  fd_crds_expire( gossip->crds, now, stem );
  tx_ping( gossip, stem, now );
  flush_stale_push_states( gossip, gossip->active_pset, stem, now );
  flush_stale_push_states( gossip, gossip->entry_pset, stem, now );
  if( FD_UNLIKELY( now>=gossip->timers.next_pull_request ) ) {
    tx_pull_request( gossip, stem, now );
    gossip->timers.next_pull_request = next_pull_request( gossip, now );
  }
  if( FD_UNLIKELY( now>=gossip->timers.next_contact_info_refresh ) ) {
    /* TODO: Frequency of this? More often if observing? */
    refresh_contact_info( gossip, now );
    push_my_contact_info( gossip, stem, now);
    gossip->timers.next_contact_info_refresh = now+15L*500L*1000L*1000L; /* TODO: Jitter */
  }
  if( FD_UNLIKELY( now>=gossip->timers.next_active_set_refresh ) ) {
    rotate_active_set( gossip, stem, now );
    gossip->timers.next_active_set_refresh = now+300L*1000L*1000L; /* TODO: Jitter */
  }
}
