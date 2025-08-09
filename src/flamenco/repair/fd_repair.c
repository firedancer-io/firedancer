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
fd_repair_new ( void * shmem, ulong seed ) {
  FD_SCRATCH_ALLOC_INIT(l, shmem);
  fd_repair_t * glob = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_t), sizeof(fd_repair_t) );
  fd_memset(glob, 0, sizeof(fd_repair_t));
  void * shm = FD_SCRATCH_ALLOC_APPEND( l, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX) );
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));
  glob->seed = seed;
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_table_align(), fd_inflight_table_footprint(FD_NEEDED_KEY_MAX) );
  glob->dupdetect = fd_inflight_table_join(fd_inflight_table_new(shm, FD_NEEDED_KEY_MAX, seed));
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_pinged_table_align(), fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX) );
  glob->pinged = fd_pinged_table_join(fd_pinged_table_new(shm, FD_REPAIR_PINGED_MAX, seed));
  glob->stake_weights = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_vote_stake_weight_t) );
  glob->stake_weights_temp = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_vote_stake_weight_t) );
  glob->stake_weights_temp_cnt = 0;
  glob->stake_weights_cnt = 0;
  glob->last_decay = 0;
  glob->last_print = 0;
  glob->last_good_peer_cache_file_write = 0;
  glob->oldest_nonce = glob->current_nonce = glob->next_nonce = 0;
  fd_rng_new(glob->rng, (uint)seed, 0UL);

  glob->peer_cnt   = 0;
  glob->peer_idx   = 0;
  glob->actives_random_seed  = 0;

  /* Initialize pending sign request pool and map */
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_pending_sign_req_pool_align(), fd_repair_pending_sign_req_pool_footprint( FD_REPAIR_PENDING_SIGN_REQ_MAX ) );
  glob->pending_sign_req_pool = fd_repair_pending_sign_req_pool_join( fd_repair_pending_sign_req_pool_new( shm, FD_REPAIR_PENDING_SIGN_REQ_MAX ) );
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_pending_sign_req_map_align(), fd_repair_pending_sign_req_map_footprint( FD_REPAIR_PENDING_SIGN_REQ_MAX ) );
  glob->pending_sign_req_map = fd_repair_pending_sign_req_map_join( fd_repair_pending_sign_req_map_new( shm, FD_REPAIR_PENDING_SIGN_REQ_MAX, seed ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI(l, 1UL);
  if ( scratch_top > (ulong)shmem + fd_repair_footprint() ) {
    FD_LOG_ERR(("Enough space not allocated for repair"));
  }

  return glob;
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
  fd_repair_pending_sign_req_pool_delete( fd_repair_pending_sign_req_pool_leave( glob->pending_sign_req_pool ) );
  fd_repair_pending_sign_req_map_delete( fd_repair_pending_sign_req_map_leave( glob->pending_sign_req_map ) );
  return glob;
}

/* Convert an address to a human readable string */
const char * fd_repair_addr_str( char * dst, size_t dstlen, fd_repair_peer_addr_t const * src ) {
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
  glob->good_peer_cache_file_fd = config->good_peer_cache_file_fd;
  return 0;
}

int
fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * intake_addr, const fd_repair_peer_addr_t * service_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_repair_addr_str(tmp, sizeof(tmp), intake_addr)));

  fd_repair_peer_addr_copy(&glob->intake_addr, intake_addr);
  fd_repair_peer_addr_copy(&glob->service_addr, service_addr);
  return 0;
}

/* Initiate connection to a peer */
int
fd_repair_add_active_peer( fd_repair_t * glob, fd_repair_peer_addr_t const * addr, fd_pubkey_t const * id ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if (val == NULL) {
    val = fd_active_table_insert(glob->actives, id);
    fd_repair_peer_addr_copy(&val->addr, addr);
    val->avg_reqs = 0;
    val->avg_reps = 0;
    val->avg_lat = 0;
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

static void
fd_repair_decay_stats( fd_repair_t * glob ) {
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );
#define DECAY(_v_) _v_ = _v_ - ((_v_)>>3U) /* Reduce by 12.5% */
    DECAY(ele->avg_reqs);
    DECAY(ele->avg_reps);
    DECAY(ele->avg_lat);
#undef DECAY
  }
}

/**
 * read_line() reads characters one by one from 'fd' until:
 *   - it sees a newline ('\n')
 *   - it reaches 'max_len - 1' characters
 *   - or EOF (read returns 0)
 * It stores the line in 'buf' and null-terminates it.
 *
 * Returns the number of characters read (not counting the null terminator),
 * or -1 on error.
 */
static long
read_line( int fd, char * buf ) {
    long i = 0;

    while (i < 255) {
        char c;
        long n = read(fd, &c, 1);

        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        } else if (n == 0) {
            break;
        }

        buf[i++] = c;

        if (c == '\n') {
            break;
        }
    }

    buf[i] = '\0';
    return i;
}

static int
fd_read_in_good_peer_cache_file( fd_repair_t * repair ) {
  if( repair->good_peer_cache_file_fd==-1 ) {
    FD_LOG_NOTICE(( "No repair good_peer_cache_file specified, not loading cached peers" ));
    return 0;
  }

  long seek = lseek( repair->good_peer_cache_file_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_WARNING(( "Failed to seek to the beginning of the good peer cache file" ));
    return 1;
  }

  int   loaded_peers   = 0;
  char  line[256];
  char  *saveptr      = NULL;

  long len;
  while ((len = read_line(repair->good_peer_cache_file_fd, line)) > 0) {

    /* Strip newline if present */
    size_t len = strlen( line );
    if( len>0 && line[len-1]=='\n' ) {
      line[len-1] = '\0';
      len--;
    }

    /* Skip empty or comment lines */
    if( !len || line[0]=='#' ) continue;

    /* Parse: base58EncodedPubkey/ipAddr/port */
    char * base58_str = strtok_r( line, "/", &saveptr );
    char * ip_str     = strtok_r( NULL, "/", &saveptr );
    char * port_str   = strtok_r( NULL, "/", &saveptr );

    if( FD_UNLIKELY( !base58_str || !ip_str || !port_str ) ) {
      FD_LOG_WARNING(( "Malformed line, skipping" ));
      continue;
    }

    /* Decode the base58 public key */
    fd_pubkey_t pubkey;
    if( !fd_base58_decode_32( base58_str, pubkey.uc ) ) {
      FD_LOG_WARNING(( "Failed to decode base58 public key '%s', skipping", base58_str ));
      continue;
    }

    /* Convert IP address */
    struct in_addr addr_parsed;
    if( inet_aton( ip_str, &addr_parsed )==0 ) {
      FD_LOG_WARNING(( "Invalid IPv4 address '%s', skipping", ip_str ));
      continue;
    }

    /* Convert the port */
    char * endptr = NULL;
    long   port   = strtol( port_str, &endptr, 10 );
    if( (port<=0L) || (port>65535L) || (endptr && *endptr!='\0') ) {
      FD_LOG_WARNING(( "Invalid port '%s', skipping", port_str ));
      continue;
    }

    /* Create the peer address struct (byte-swap the port to network order). */
    //fd_repair_peer_addr_t peer_addr;
    /* already in network byte order from inet_aton */
    //peer_addr.addr = ip_addr;
    /* Flip to big-endian for network order */
    //peer_addr.port = fd_ushort_bswap( (ushort)port );

    /* Add to active peers in the repair tile. */
   // fd_repair_add_active_peer( repair, &peer_addr, &pubkey );

    loaded_peers++;
  }

  FD_LOG_INFO(( "Loaded %d peers from good peer cache file", loaded_peers ));
  return 0;
}

/* Start timed events and other protocol behavior */
int
fd_repair_start( fd_repair_t * glob ) {
  glob->last_sends = glob->now;
  glob->last_decay = glob->now;
  glob->last_print = glob->now;
  return fd_read_in_good_peer_cache_file( glob );
}

static void fd_repair_print_all_stats( fd_repair_t * glob );
static int fd_write_good_peer_cache_file( fd_repair_t * repair );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_repair_continue( fd_repair_t * glob ) {
  if ( glob->now - glob->last_print > (long)30e9 ) { /* 30 seconds */
    fd_repair_print_all_stats( glob );
    glob->last_print = glob->now;
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_decay > (long)15e9 ) { /* 15 seconds */
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_good_peer_cache_file_write > (long)60e9 ) { /* 1 minute */
    fd_write_good_peer_cache_file( glob );
    glob->last_good_peer_cache_file_write = glob->now;
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
      glob->metrics.sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_WINDOW_IDX]++;
      fd_repair_protocol_new_disc(protocol, fd_repair_protocol_enum_window_index);
      fd_repair_window_index_t * wi = &protocol->inner.window_index;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      wi->shred_index = shred_index;
        //FD_LOG_INFO(( "repair request for %lu, %lu", wi->slot, wi->shred_index ));
      return 1;
    }

    case fd_needed_highest_window_index: {
      glob->metrics.sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_HIGHEST_WINDOW_IDX]++;
      fd_repair_protocol_new_disc( protocol, fd_repair_protocol_enum_highest_window_index );
      fd_repair_highest_window_index_t * wi = &protocol->inner.highest_window_index;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      wi->shred_index = shred_index;
      //FD_LOG_INFO(( "repair request for %lu, %lu", wi->slot, wi->shred_index ));
      return 1;
    }

    case fd_needed_orphan: {
      glob->metrics.sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_ORPHAN_IDX]++;
      fd_repair_protocol_new_disc( protocol, fd_repair_protocol_enum_orphan );
      fd_repair_orphan_t * wi = &protocol->inner.orphan;
      wi->header.sender = *glob->public_key;
      wi->header.recipient = *recipient;
      wi->header.timestamp = (ulong)now/1000000L;
      wi->header.nonce = nonce;
      wi->slot = slot;
      //FD_LOG_INFO(( "repair request for %lu", ele->dupkey.slot));
      return 1;
    }
  }
  return 0;
}

/* Returns 1 if its valid to send a request for the given shred. 0 if
   it is not, i.e., there is an inflight request for it that was sent
   within the last x ms. */
static int
fd_repair_create_inflight_request( fd_repair_t * glob, int type, ulong slot, uint shred_index, long now ) {

  /* If there are no active sticky peers from which to send requests to, refresh the sticky peers
     selection. It may be that stake weights were not available before, and now they are. */

  fd_inflight_key_t    dupkey  = { .type = (enum fd_needed_elem_type)type, .slot = slot, .shred_index = shred_index };
  fd_inflight_elem_t * dupelem = fd_inflight_table_query( glob->dupdetect, &dupkey, NULL );

  if( dupelem == NULL ) {
    dupelem = fd_inflight_table_insert( glob->dupdetect, &dupkey );

    if ( FD_UNLIKELY( dupelem == NULL ) ) {
      FD_LOG_ERR(( "Eviction unimplemented. Failed to insert duplicate detection element for slot %lu, shred_index %u", slot, shred_index ));
      return 0;
    }

    dupelem->last_send_time = 0L;
  }

  if( FD_LIKELY( dupelem->last_send_time+(long)80e6  < now ) ) { /* 80ms */
    dupelem->last_send_time = now;
    dupelem->req_cnt        = FD_REPAIR_NUM_NEEDED_PEERS;
    return 1;
  }
  return 0;
}

int
fd_repair_inflight_remove( fd_repair_t * glob,
                           ulong         slot,
                           uint          shred_index ) {
  /* If we have a shred, we can remove it from the inflight table */
  // FIXME: might be worth adding eviction logic here for orphan / highest window reqs

  fd_inflight_key_t    dupkey  = { .type = fd_needed_window_index, .slot = slot, .shred_index = shred_index };
  fd_inflight_elem_t * dupelem = fd_inflight_table_query( glob->dupdetect, &dupkey, NULL );
  if( dupelem ) {
    /* Remove the element from the inflight table */
    fd_inflight_table_remove( glob->dupdetect, &dupkey );
  }
  return 0;
}


static int
fd_write_good_peer_cache_file( fd_repair_t * repair ) {
  // return 0;

  if ( repair->good_peer_cache_file_fd == -1 ) {
    return 0;
  }

  if ( repair->actives_sticky_cnt == 0 ) {
    return 0;
  }

  /* Truncate the file before we write it */
  int err = ftruncate( repair->good_peer_cache_file_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_WARNING(( "Failed to truncate the good peer cache file (%i-%s)", errno, fd_io_strerror( errno ) ));
    return 1;
  }
  long seek = lseek( repair->good_peer_cache_file_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_WARNING(( "Failed to seek to the beginning of the good peer cache file" ));
    return 1;
  }

  /* Write the active sticky peers to file in the format:
     "base58EncodedPubkey/ipAddr/port"

     Where ipAddr is in dotted-decimal (e.g. "1.2.3.4")
     and port is decimal, in host order (e.g. "8001").
  */
  for( ulong i = 0UL; i < repair->actives_sticky_cnt; i++ ) {
    fd_pubkey_t *      id   = &repair->actives_sticky[ i ];
    fd_active_elem_t * peer = fd_active_table_query( repair->actives, id, NULL );
    if ( peer == NULL ) {
      continue;
    }

    /* Convert the public key to base58 */
    char base58_str[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( peer->key.uc, NULL, base58_str );

    /* Convert the IP address to dotted-decimal string.  The address
       in peer->addr.addr is already in network byte order. */
    struct in_addr addr_parsed;
    addr_parsed.s_addr = peer->addr.addr; /* net-order -> struct in_addr */
    char * ip_str = inet_ntoa( addr_parsed );

    /* Convert port from network byte order to host byte order. */
    ushort port = fd_ushort_bswap( peer->addr.port );

    /* Write out line: base58EncodedPubkey/ipAddr/port */
    dprintf( repair->good_peer_cache_file_fd, "%s/%s/%u\n", base58_str, ip_str, (uint)port );
  }

  return 0;
}

int
fd_repair_need_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  // FD_LOG_NOTICE(( "[%s] need window %lu, shred_index %u", __func__, slot, shred_index ));
  return fd_repair_create_inflight_request( glob, fd_needed_window_index, slot, shred_index, glob->now );
}

int
fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  //FD_LOG_DEBUG(( "[%s] need highest %lu", __func__, slot ));
  return fd_repair_create_inflight_request( glob, fd_needed_highest_window_index, slot, shred_index, glob->now );
}

int
fd_repair_need_orphan( fd_repair_t * glob, ulong slot ) {
  // FD_LOG_NOTICE( ( "[repair] need orphan %lu", slot ) );
  return fd_repair_create_inflight_request( glob, fd_needed_orphan, slot, UINT_MAX, glob->now );
}

static void
print_stats( fd_active_elem_t * val ) {
  fd_pubkey_t const * id = &val->key;
  if( FD_UNLIKELY( NULL == val ) ) return;
  if( val->avg_reqs == 0 )
    FD_LOG_INFO(( "repair peer %s: no requests sent, stake=%lu", FD_BASE58_ENC_32_ALLOCA( id ), val->stake / (ulong)1e9 ));
  else if( val->avg_reps == 0 )
    FD_LOG_INFO(( "repair peer %s: avg_requests=%lu, no responses received, stake=%lu", FD_BASE58_ENC_32_ALLOCA( id ), val->avg_reqs, val->stake / (ulong)1e9 ));
  else
    FD_LOG_INFO(( "repair peer %s: avg_requests=%lu, response_rate=%f, latency=%f, stake=%lu",
                    FD_BASE58_ENC_32_ALLOCA( id ),
                    val->avg_reqs,
                    ((double)val->avg_reps)/((double)val->avg_reqs),
                    1.0e-9*((double)val->avg_lat)/((double)val->avg_reps),
                    val->stake / (ulong)1e9 ));
}

static void
fd_repair_print_all_stats( fd_repair_t * glob ) {
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * val = fd_active_table_iter_ele( glob->actives, iter );
    print_stats( val );
  }
  FD_LOG_INFO( ( "peer count: %lu", fd_active_table_key_cnt( glob->actives ) ) );
}

void fd_repair_add_sticky( fd_repair_t * glob, fd_pubkey_t const * id ) {
  glob->actives_sticky[glob->actives_sticky_cnt++] = *id;

}

void
fd_repair_set_stake_weights_init( fd_repair_t * repair,
                                  fd_vote_stake_weight_t const * stake_weights,
                                  ulong stake_weights_cnt ) {
  if( stake_weights == NULL ) {
    FD_LOG_ERR(( "stake weights NULL" ));
  }
  if( stake_weights_cnt > FD_STAKE_WEIGHTS_MAX ) {
    FD_LOG_ERR(( "too many stake weights" ));
  }

  fd_memcpy( repair->stake_weights_temp, stake_weights, stake_weights_cnt * sizeof(fd_vote_stake_weight_t) );
  repair->stake_weights_temp_cnt = stake_weights_cnt;
}

void
fd_repair_set_stake_weights_fini( fd_repair_t * repair ) {
  fd_swap( repair->stake_weights, repair->stake_weights_temp );
  repair->stake_weights_cnt = repair->stake_weights_temp_cnt;
}


fd_repair_metrics_t *
fd_repair_get_metrics( fd_repair_t * repair ) {
  return &repair->metrics;
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
  if( FD_UNLIKELY( fd_repair_pending_sign_req_pool_free( repair->pending_sign_req_pool ) == 0 ) ) {
    return NULL;
  }

  fd_repair_pending_sign_req_t * pending = fd_repair_pending_sign_req_pool_ele_acquire( repair->pending_sign_req_pool );
  if (FD_UNLIKELY( !pending ) ) {
    return NULL;
  }

  pending->nonce =       repair->next_nonce;

  fd_repair_pending_sign_req_map_ele_insert( repair->pending_sign_req_map, pending, repair->pending_sign_req_pool );

  fd_repair_construct_request_protocol( repair, protocol, type, slot, shred_index, recipient, repair->next_nonce, now );

  pending->sig_offset =  4;
  pending->dst_ip_addr = dst_ip_addr;
  pending->dst_port =    dst_port;
  pending->recipient =   *recipient;

  repair->metrics.send_pkt_cnt++;
  repair->next_nonce++;
  return pending;
}

fd_repair_pending_sign_req_t *
fd_repair_query_pending_request( fd_repair_t * repair,
                                 ulong         nonce ) {
  return fd_repair_pending_sign_req_map_ele_query( repair->pending_sign_req_map, &nonce, NULL, repair->pending_sign_req_pool );
}

int
fd_repair_remove_pending_request( fd_repair_t * repair,
                                  ulong         nonce ) {
  fd_repair_pending_sign_req_t * pending = fd_repair_pending_sign_req_map_ele_query( repair->pending_sign_req_map, &nonce, NULL, repair->pending_sign_req_pool );
  if( FD_UNLIKELY( !pending ) ) {
    return -1;
  }

  fd_repair_pending_sign_req_map_ele_remove( repair->pending_sign_req_map, &nonce, NULL, repair->pending_sign_req_pool );
  fd_repair_pending_sign_req_pool_ele_release( repair->pending_sign_req_pool, pending );
  return 0;
}
