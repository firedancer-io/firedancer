#define _GNU_SOURCE 1
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../util/rng/fd_rng.h"
#include "../../flamenco/fd_flamenco_base.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

void *
fd_repair_new ( void * shmem, ulong sign_tile_depth, ulong sign_tile_cnt, ulong seed ) {
  ulong sign_req_max = sign_tile_depth * sign_tile_cnt;
  sign_req_max = fd_ulong_pow2_up( sign_req_max );

  FD_SCRATCH_ALLOC_INIT(l, shmem);
  fd_repair_t * repair   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_t),                    sizeof(fd_repair_t) );
  void        * actives  = FD_SCRATCH_ALLOC_APPEND( l, fd_active_table_align(),                 fd_active_table_footprint(FD_ACTIVE_KEY_MAX) );
  void        * inflight = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_table_align(),               fd_inflight_table_footprint(FD_NEEDED_KEY_MAX) );
  void        * inflpool = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_pool_align(),                fd_inflight_pool_footprint(FD_NEEDED_KEY_MAX) );
  void        * inflmap  = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_map_align(),                 fd_inflight_map_footprint(FD_NEEDED_KEY_MAX) );
  void        * infldl   = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_dlist_align(),               fd_inflight_dlist_footprint()                 );
  void        * pinged   = FD_SCRATCH_ALLOC_APPEND( l, fd_pinged_table_align(),                 fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX) );
  void        * signpool = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_pending_sign_req_pool_align(), fd_repair_pending_sign_req_pool_footprint( sign_req_max ) );
  void        * signmap  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_pending_sign_req_map_align(),  fd_repair_pending_sign_req_map_footprint ( sign_req_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_repair_align() ) == (ulong)shmem + fd_repair_footprint( sign_tile_depth, sign_tile_cnt ) );

  fd_memset(repair, 0, sizeof(fd_repair_t));
  repair->actives        = fd_active_table_join  ( fd_active_table_new  ( actives,  FD_ACTIVE_KEY_MAX,    seed ));
  FD_TEST(repair->actives);
  repair->dupdetect      = fd_inflight_table_join( fd_inflight_table_new( inflight, FD_NEEDED_KEY_MAX,    seed ));
  repair->inflight_pool  = fd_inflight_pool_join ( fd_inflight_pool_new ( inflpool, FD_NEEDED_KEY_MAX          ));
  repair->inflight_map   = fd_inflight_map_join  ( fd_inflight_map_new  ( inflmap,  FD_NEEDED_KEY_MAX,    seed ));
  repair->inflight_dlist = fd_inflight_dlist_join( fd_inflight_dlist_new( infldl                               ));
  repair->pinged         = fd_pinged_table_join  ( fd_pinged_table_new  ( pinged,   FD_REPAIR_PINGED_MAX, seed ));
  repair->pending_sign_pool = fd_repair_pending_sign_req_pool_join( fd_repair_pending_sign_req_pool_new( signpool, sign_req_max       ) );
  repair->pending_sign_map  = fd_repair_pending_sign_req_map_join ( fd_repair_pending_sign_req_map_new ( signmap,  sign_req_max, seed ) );

  repair->seed = seed;
  repair->last_decay = 0;
  repair->last_print = 0;
  repair->next_nonce = 0;
  fd_rng_new(repair->rng, (uint)seed, 0UL);
  repair->peer_cnt   = 0;
  repair->peer_idx   = 0;


  return repair;
}

fd_repair_t *
fd_repair_join ( void * shmap ) { return (fd_repair_t *)shmap; }

void *
fd_repair_leave ( fd_repair_t * join ) { return join; }

void *
fd_repair_delete ( void * shmap ) {
  fd_repair_t * glob = (fd_repair_t *)shmap;
  fd_active_table_delete( fd_active_table_leave( glob->actives ) );
  fd_inflight_table_delete( fd_inflight_table_leave( glob->dupdetect ) );
  fd_pinged_table_delete( fd_pinged_table_leave( glob->pinged ) );
  fd_repair_pending_sign_req_pool_delete( fd_repair_pending_sign_req_pool_leave( glob->pending_sign_pool ) );
  fd_repair_pending_sign_req_map_delete( fd_repair_pending_sign_req_map_leave  ( glob->pending_sign_map ) );
  return glob;
}

/* Convert an address to a human readable string */
const char * fd_repair_addr_str( char * dst, size_t dstlen, fd_ip4_port_t const * src ) {
  char tmp[INET_ADDRSTRLEN];
  snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET, &src->addr, tmp, INET_ADDRSTRLEN), (uint)ntohs(src->port));
  return dst;
}

/* Set the repair configuration */
int
fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config ) {
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( config->public_key->uc, NULL, keystr );
  FD_LOG_NOTICE(("configuring address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), &config->intake_addr), keystr));

  glob->public_key = config->public_key;
  glob->private_key = config->private_key;
  fd_repair_peer_addr_copy(&glob->intake_addr, &config->intake_addr);
  fd_repair_peer_addr_copy(&glob->service_addr, &config->service_addr);
  return 0;
}

int
fd_repair_update_addr( fd_repair_t * glob, const fd_ip4_port_t * intake_addr, const fd_ip4_port_t * service_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_repair_addr_str(tmp, sizeof(tmp), intake_addr)));

  fd_repair_peer_addr_copy(&glob->intake_addr, intake_addr);
  fd_repair_peer_addr_copy(&glob->service_addr, service_addr);
  return 0;
}

/* Initiate connection to a peer */
int
fd_repair_add_active_peer( fd_repair_t * glob, fd_ip4_port_t const * addr, fd_pubkey_t const * id ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if (val == NULL) {
    val = fd_active_table_insert(glob->actives, id);
    fd_repair_peer_addr_copy(&val->addr, addr);
    val->resp_cnt = 0;
    val->total_latency = 0;
    val->stake = 0UL;

    glob->peers[ glob->peer_cnt++ ] = (fd_peer_t){
      .key = *id,
      .ip4 = *addr
    };
    return 0;
  }
  return 1;
}

/* Set the current protocol time in nanosecs */
void
fd_repair_settime( fd_repair_t * glob, long ts ) {
  glob->now = ts;
}

/* Get the current protocol time in nanosecs */
long
fd_repair_gettime( fd_repair_t * glob ) {
  return glob->now;
}
/* Start timed events and other protocol behavior */
int
fd_repair_start( fd_repair_t * glob ) {
  glob->last_sends = glob->now;
  glob->last_decay = glob->now;
  glob->last_print = glob->now;
  return 0;
}

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_repair_continue( fd_repair_t * glob ) {
  if ( glob->now - glob->last_print > (long)30e9 ) { /* 30 seconds */
    glob->last_print = glob->now;
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_decay > (long)15e9 ) { /* 15 seconds */
    glob->last_decay = glob->now;
  }
  return 0;
}

int
fd_repair_construct_request_protocol( fd_repair_t          * glob,
                                      fd_repair_protocol_t * protocol,
                                      enum fd_needed_elem_type type,
                                      ulong                  slot,
                                      uint                   shred_index,
                                      fd_pubkey_t const    * recipient,
                                      uint                   nonce,
                                      long                   now ) {
  switch( type ) {
    case fd_needed_window_index: {
      fd_repair_protocol_new_disc(protocol, fd_repair_protocol_enum_window_index);
      fd_repair_window_index_t * wi = &protocol->inner.window_index;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      wi->shred_index = shred_index;
      return 1;
    }

    case fd_needed_highest_window_index: {
      fd_repair_protocol_new_disc( protocol, fd_repair_protocol_enum_highest_window_index );
      fd_repair_highest_window_index_t * wi = &protocol->inner.highest_window_index;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      wi->shred_index = shred_index;
      return 1;
    }

    case fd_needed_orphan: {
      fd_repair_protocol_new_disc( protocol, fd_repair_protocol_enum_orphan );
      fd_repair_orphan_t * wi = &protocol->inner.orphan;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      return 1;
    }
  }
  return 0;
}

/* Returns 1 if its valid to send a request for the given shred. 0 if
   it is not, i.e., there is an inflight request for it that was sent
   within the last x ms. */
static int
fd_repair_create_dedup_request( fd_repair_t * glob, int type, ulong slot, uint shred_index, long now ) {

  /* If there are no active sticky peers from which to send requests to, refresh the sticky peers
     selection. It may be that stake weights were not available before, and now they are. */

  fd_inflight_key_t    dupkey  = { .type = (enum fd_needed_elem_type)type, .slot = slot, .shred_index = shred_index };
  fd_inflight_elem_t * dupelem = fd_inflight_table_query( glob->dupdetect, &dupkey, NULL );

  if( dupelem == NULL ) {
    if( FD_UNLIKELY( fd_inflight_table_is_full( glob->dupdetect ) ) ) {
      FD_LOG_WARNING(( "Failed to insert duplicate detection element for slot %lu, shred_index %u. Eviction unimplemented.", slot, shred_index ));
      return 0;
    }
    dupelem = fd_inflight_table_insert( glob->dupdetect, &dupkey );
    dupelem->last_send_time = 0L;
  }

  if( FD_LIKELY( dupelem->last_send_time+(long)80e6  < now ) ) { /* 80ms */
    dupelem->last_send_time = now;
    dupelem->req_cnt        = FD_REPAIR_NUM_NEEDED_PEERS;
    return 1;
  }
  return 0;
}

long
fd_repair_inflight_remove( fd_repair_t * glob,
                           ulong         slot,
                           uint          shred_index,
                           ulong         nonce ) {
  /* If we have a shred, we can remove it from the inflight table */
  // FIXME: might be worth adding eviction logic here for orphan / highest window reqs

  fd_inflight_key_t    dupkey  = { .type = fd_needed_window_index, .slot = slot, .shred_index = shred_index };
  fd_inflight_elem_t * dupelem = fd_inflight_table_query( glob->dupdetect, &dupkey, NULL );
  if( dupelem ) {
    /* Remove the element from the inflight table */
    fd_inflight_table_remove( glob->dupdetect, &dupkey );
  }

  fd_inflight_t * inflight_req = fd_inflight_map_ele_query( glob->inflight_map, &nonce, NULL, glob->inflight_pool );
  if( inflight_req ) {
    long rtt = fd_log_wallclock() - inflight_req->timestamp_ns;

    /* update peer stats */
    fd_active_elem_t * active_elem = fd_active_table_query( glob->actives, &inflight_req->pubkey, NULL );
    if( FD_LIKELY( active_elem ) ) {
      active_elem->resp_cnt++;
      active_elem->total_latency += rtt;
    }
    /* Remove the element from the inflight table */
    fd_inflight_map_ele_remove  ( glob->inflight_map, &nonce, NULL, glob->inflight_pool );
    fd_inflight_dlist_ele_remove( glob->inflight_dlist, inflight_req, glob->inflight_pool );
    fd_inflight_pool_ele_release( glob->inflight_pool, inflight_req );
    return rtt;
  }

  return 0;
}

int
fd_repair_need_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  // FD_LOG_NOTICE(( "[%s] need window %lu, shred_index %u", __func__, slot, shred_index ));
  return fd_repair_create_dedup_request( glob, fd_needed_window_index, slot, shred_index, glob->now );
}

int
fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  //FD_LOG_DEBUG(( "[%s] need highest %lu", __func__, slot ));
  return fd_repair_create_dedup_request( glob, fd_needed_highest_window_index, slot, shred_index, glob->now );
}

int
fd_repair_need_orphan( fd_repair_t * glob, ulong slot ) {
  // FD_LOG_NOTICE( ( "[repair] need orphan %lu", slot ) );
  return fd_repair_create_dedup_request( glob, fd_needed_orphan, slot, UINT_MAX, glob->now );
}

/* Pending Sign Request API

   These functions manage the pool and map of pending sign requests in
   the repair module. Each request is identified by a unique nonce,
   allowing for nonce to be used as a key in the map.

  fd_repair_pending_sign_req_t * fd_repair_acquire_pending_request(...);
    Acquires an empty pending sign request from the pool. Returns
    pointer or NULL if pool is full. Caller is responsible for setting
    all fields before adding to map.

  int fd_repair_add_pending_to_map(...);
    Adds a pending sign request to the map. Returns 0 on success, -1 on
    failure. The pending request must be previously acquired from the
    pool.

  fd_repair_pending_sign_req_t * fd_repair_find_pending_request(...);
    Finds a pending sign request by nonce. Returns pointer or NULL.

  int fd_repair_remove_pending_request(...);
    Removes a pending sign request by nonce. Returns 0 on success, -1
    if not found.

   All functions assume the repair context is valid and not used concurrently.
*/

fd_repair_pending_sign_req_t *
fd_repair_insert_pending_request( fd_repair_t *            repair,
                                  fd_repair_protocol_t *   protocol,
                                  uint                     dst_ip_addr,
                                  ushort                   dst_port,
                                  enum fd_needed_elem_type type,
                                  ulong                    slot,
                                  uint                     shred_index,
                                  long                     now,
                                  fd_pubkey_t const *      recipient ) {

  /* Check if there is any space for a new pending sign request */
  if( FD_UNLIKELY( fd_repair_pending_sign_req_pool_free( repair->pending_sign_pool ) == 0 ) ) {
    return NULL;
  }

  fd_repair_pending_sign_req_t * pending = fd_repair_pending_sign_req_pool_ele_acquire( repair->pending_sign_pool );
  pending->nonce = repair->next_nonce;

  fd_repair_pending_sign_req_map_ele_insert( repair->pending_sign_map, pending, repair->pending_sign_pool );
  fd_repair_construct_request_protocol( repair, protocol, type, slot, shred_index, recipient, repair->next_nonce, now );

  pending->sig_offset  = 4;
  pending->dst_ip_addr = dst_ip_addr;
  pending->dst_port    = dst_port;
  pending->recipient   = *recipient;
  pending->type        = (uchar)type;

  /* Add the request to the inflight table */
  fd_inflight_t * inflight_req = fd_inflight_pool_ele_acquire( repair->inflight_pool );
  if( FD_UNLIKELY( !inflight_req ) ) {
    FD_LOG_ERR(("Failed to acquire inflight request from pool, implement eviction"));
  }
  inflight_req->nonce = repair->next_nonce;
  inflight_req->timestamp_ns = now;
  inflight_req->pubkey = *recipient;

  fd_inflight_map_ele_insert( repair->inflight_map, inflight_req, repair->inflight_pool );
  fd_inflight_dlist_ele_push_tail( repair->inflight_dlist, inflight_req, repair->inflight_pool );

  repair->next_nonce++;
  return pending;
}

fd_repair_pending_sign_req_t *
fd_repair_query_pending_request( fd_repair_t * repair,
                                 ulong         nonce ) {
  return fd_repair_pending_sign_req_map_ele_query( repair->pending_sign_map, &nonce, NULL, repair->pending_sign_pool );
}

int
fd_repair_remove_pending_request( fd_repair_t * repair,
                                  ulong         nonce ) {
  fd_repair_pending_sign_req_t * pending = fd_repair_pending_sign_req_map_ele_query( repair->pending_sign_map, &nonce, NULL, repair->pending_sign_pool );
  if( FD_UNLIKELY( !pending ) ) {
    return -1;
  }

  fd_repair_pending_sign_req_map_ele_remove( repair->pending_sign_map, &nonce, NULL, repair->pending_sign_pool );
  fd_repair_pending_sign_req_pool_ele_release( repair->pending_sign_pool, pending );
  return 0;
}
