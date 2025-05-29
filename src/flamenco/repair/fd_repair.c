#define _GNU_SOURCE 1
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../util/rng/fd_rng.h"
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
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_needed_table_align(), fd_needed_table_footprint(FD_NEEDED_KEY_MAX) );
  glob->needed = fd_needed_table_join(fd_needed_table_new(shm, FD_NEEDED_KEY_MAX, seed));
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_dupdetect_table_align(), fd_dupdetect_table_footprint(FD_NEEDED_KEY_MAX) );
  glob->dupdetect = fd_dupdetect_table_join(fd_dupdetect_table_new(shm, FD_NEEDED_KEY_MAX, seed));
  shm = FD_SCRATCH_ALLOC_APPEND( l, fd_pinged_table_align(), fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX) );
  glob->pinged = fd_pinged_table_join(fd_pinged_table_new(shm, FD_REPAIR_PINGED_MAX, seed));
  glob->stake_weights = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_stake_weight_t) );
  glob->stake_weights_temp = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_stake_weight_t) );
  glob->stake_weights_cnt = 0;
  glob->last_sends = 0;
  glob->last_decay = 0;
  glob->last_print = 0;
  glob->last_good_peer_cache_file_write = 0;
  glob->oldest_nonce = glob->current_nonce = glob->next_nonce = 0;
  fd_rng_new(glob->rng, (uint)seed, 0UL);

  glob->actives_sticky_cnt   = 0;
  glob->actives_random_seed  = 0;

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
  fd_needed_table_delete( fd_needed_table_leave( glob->needed ) );
  fd_dupdetect_table_delete( fd_dupdetect_table_leave( glob->dupdetect ) );
  fd_pinged_table_delete( fd_pinged_table_leave( glob->pinged ) );
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
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( id->uc, NULL, keystr );
  FD_LOG_DEBUG(("adding active peer address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), addr), keystr));

  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      FD_LOG_WARNING(("too many active repair peers, discarding new peer"));
      return -1;
    }
    val = fd_active_table_insert(glob->actives, id);
    fd_repair_peer_addr_copy(&val->addr, addr);
    val->avg_reqs = 0;
    val->avg_reps = 0;
    val->avg_lat = 0;
    val->sticky = 0;
    val->first_request_time = 0;
    val->stake = 0UL;
    FD_LOG_DEBUG(( "adding repair peer %s", FD_BASE58_ENC_32_ALLOCA( val->key.uc ) ));
  }

  return 0;
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
    uint ip_addr = (uint)addr_parsed.s_addr;

    /* Convert the port */
    char * endptr = NULL;
    long   port   = strtol( port_str, &endptr, 10 );
    if( (port<=0L) || (port>65535L) || (endptr && *endptr!='\0') ) {
      FD_LOG_WARNING(( "Invalid port '%s', skipping", port_str ));
      continue;
    }

    /* Create the peer address struct (byte-swap the port to network order). */
    fd_repair_peer_addr_t peer_addr;
    /* already in network byte order from inet_aton */
    peer_addr.addr = ip_addr;
    /* Flip to big-endian for network order */
    peer_addr.port = fd_ushort_bswap( (ushort)port );

    /* Add to active peers in the repair tile. */
    fd_repair_add_active_peer( repair, &peer_addr, &pubkey );

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
static void fd_actives_shuffle( fd_repair_t * repair );
static int fd_write_good_peer_cache_file( fd_repair_t * repair );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_repair_continue( fd_repair_t * glob ) {
  if ( glob->now - glob->last_print > (long)30e9 ) { /* 30 seconds */
    fd_repair_print_all_stats( glob );
    glob->last_print = glob->now;
    fd_actives_shuffle( glob );
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_decay > (long)15e9 ) { /* 15 seconds */
    fd_actives_shuffle( glob );
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_good_peer_cache_file_write > (long)60e9 ) { /* 1 minute */
    fd_write_good_peer_cache_file( glob );
    glob->last_good_peer_cache_file_write = glob->now;
  }
  return 0;
}


int
fd_repair_is_full( fd_repair_t * glob ) {
  return fd_needed_table_is_full(glob->needed);
}

/* Test if a peer is good. Returns 1 if the peer is "great", 0 if the peer is "good", and -1 if the peer sucks */
static int
is_good_peer( fd_active_elem_t * val ) {
  if( FD_UNLIKELY( NULL == val ) ) return -1;                          /* Very bad */
  if( val->avg_reqs > 10U && val->avg_reps == 0U )  return -1;         /* Bad, no response after 10 requests */
  if( val->avg_reqs < 20U ) return 0;                                  /* Not sure yet, good enough for now */
  if( (float)val->avg_reps < 0.01f*((float)val->avg_reqs) ) return -1; /* Very bad */
  if( (float)val->avg_reps < 0.8f*((float)val->avg_reqs) ) return 0;   /* 80%, Good but not great */
  if( (float)val->avg_lat > 2500e9f*((float)val->avg_reps) ) return 0;  /* 300ms, Good but not great */
  return 1;                                                            /* Great! */
}

#define SORT_NAME        fd_latency_sort
#define SORT_KEY_T       long
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

static void
fd_actives_shuffle( fd_repair_t * repair ) {
  /* Since we now have stake weights very quickly after reading the manifest, we wait
     until we have the stake weights before we start repairing. This ensures that we always
     sample from the available peers using stake weights. */
  if( repair->stake_weights_cnt == 0 ) {
    FD_LOG_NOTICE(( "repair does not have stake weights yet, not selecting any sticky peers" ));
    return;
  }

  FD_SCRATCH_SCOPE_BEGIN {
    ulong prev_sticky_cnt = repair->actives_sticky_cnt;
    /* Find all the usable stake holders */
    fd_active_elem_t ** leftovers = fd_scratch_alloc(
        alignof( fd_active_elem_t * ),
        sizeof( fd_active_elem_t * ) * repair->stake_weights_cnt );
    ulong leftovers_cnt = 0;

    ulong total_stake = 0UL;
    if( repair->stake_weights_cnt==0 ) {
      leftovers = fd_scratch_alloc(
        alignof( fd_active_elem_t * ),
        sizeof( fd_active_elem_t * ) * fd_active_table_key_cnt( repair->actives ) );

      for( fd_active_table_iter_t iter = fd_active_table_iter_init( repair->actives );
         !fd_active_table_iter_done( repair->actives, iter );
         iter = fd_active_table_iter_next( repair->actives, iter ) ) {
        fd_active_elem_t * peer = fd_active_table_iter_ele( repair->actives, iter );
        if( peer->sticky ) continue;
        leftovers[leftovers_cnt++] = peer;
      }
    } else {
      leftovers = fd_scratch_alloc(
        alignof( fd_active_elem_t * ),
        sizeof( fd_active_elem_t * ) * repair->stake_weights_cnt );

      for( ulong i = 0; i < repair->stake_weights_cnt; i++ ) {
        fd_stake_weight_t const * stake_weight = &repair->stake_weights[i];
        ulong stake = stake_weight->stake;
        if( !stake ) continue;
        fd_pubkey_t const * key = &stake_weight->key;
        fd_active_elem_t * peer = fd_active_table_query( repair->actives, key, NULL );
        if( peer!=NULL ) {
          peer->stake = stake;
          total_stake = fd_ulong_sat_add( total_stake, stake );
        }
        if( NULL == peer || peer->sticky ) continue;
        leftovers[leftovers_cnt++] = peer;
      }
    }

    fd_active_elem_t * best[FD_REPAIR_STICKY_MAX];
    ulong              best_cnt = 0;
    fd_active_elem_t * good[FD_REPAIR_STICKY_MAX];
    ulong              good_cnt = 0;

    long  latencies[ FD_REPAIR_STICKY_MAX ];
    ulong latencies_cnt = 0UL;

    long first_quartile_latency = LONG_MAX;

    /* fetch all latencies */
    for( fd_active_table_iter_t iter = fd_active_table_iter_init( repair->actives );
            !fd_active_table_iter_done( repair->actives, iter );
            iter = fd_active_table_iter_next( repair->actives, iter ) ) {
            fd_active_elem_t * peer = fd_active_table_iter_ele( repair->actives, iter );

      if( !peer->sticky ) {
        continue;
      }

      if( peer->avg_lat==0L || peer->avg_reps==0UL ) {
        continue;
      }

      latencies[ latencies_cnt++ ] = peer->avg_lat/(long)peer->avg_reps;
    }

    if( latencies_cnt >= 4 ) {
      /* we probably want a few peers before sorting and pruning them based on
         latency. */
      fd_latency_sort_inplace( latencies, latencies_cnt );
      first_quartile_latency = latencies[ latencies_cnt / 4UL ];
      FD_LOG_NOTICE(( "repair peers first quartile latency - latency: %6.6f ms", (double)first_quartile_latency * 1e-6 ));
    }

    /* Build the new sticky peers set based on the latency and stake weight */

    /* select an upper bound */
    /* acceptable latency is 2 * first quartile latency  */
    long acceptable_latency = first_quartile_latency != LONG_MAX ? 2L * first_quartile_latency : LONG_MAX;
    for( fd_active_table_iter_t iter = fd_active_table_iter_init( repair->actives );
         !fd_active_table_iter_done( repair->actives, iter );
         iter = fd_active_table_iter_next( repair->actives, iter ) ) {
      fd_active_elem_t * peer = fd_active_table_iter_ele( repair->actives, iter );
      uchar sticky = peer->sticky;
      peer->sticky = 0; /* Already clear the sticky bit */
      if( sticky ) {
        /* See if we still like this peer */
        if( peer->avg_reps>0UL && ( peer->avg_lat/(long)peer->avg_reps ) >= acceptable_latency ) {
          continue;
        }
        int r = is_good_peer( peer );
        if( r == 1 ) best[best_cnt++] = peer;
        else if( r == 0 ) good[good_cnt++] = peer;
      }
    }

    ulong tot_cnt = 0;
    for( ulong i = 0; i < best_cnt && tot_cnt < FD_REPAIR_STICKY_MAX - 2U; ++i ) {
      repair->actives_sticky[tot_cnt++] = best[i]->key;
      best[i]->sticky                       = (uchar)1;
    }
    for( ulong i = 0; i < good_cnt && tot_cnt < FD_REPAIR_STICKY_MAX - 2U; ++i ) {
      repair->actives_sticky[tot_cnt++] = good[i]->key;
      good[i]->sticky                       = (uchar)1;
    }
    if( leftovers_cnt ) {
      /* Sample 64 new sticky peers using stake-weighted sampling */
      for( ulong i = 0; i < 64 && tot_cnt < FD_REPAIR_STICKY_MAX && tot_cnt < fd_active_table_key_cnt( repair->actives ); ++i ) {
        /* Generate a random amount of culmative stake at which to sample the peer */
        ulong target_culm_stake = fd_rng_ulong( repair->rng ) % total_stake;

        /* Iterate over the active peers until we find the randomly selected peer */
        ulong culm_stake = 0UL;
        fd_active_elem_t * peer = NULL;
        for( fd_active_table_iter_t iter = fd_active_table_iter_init( repair->actives );
          !fd_active_table_iter_done( repair->actives, iter );
          iter = fd_active_table_iter_next( repair->actives, iter ) ) {
            peer = fd_active_table_iter_ele( repair->actives, iter );
            culm_stake = fd_ulong_sat_add( culm_stake, peer->stake );
            if( FD_UNLIKELY(( culm_stake >= target_culm_stake )) ) {
              break;
            }
        }

        /* Select this peer as sticky */
        if( FD_LIKELY(( peer && !peer->sticky )) ) {
          repair->actives_sticky[tot_cnt++] = peer->key;
          peer->sticky                      = (uchar)1;
        }
      }

    }
    repair->actives_sticky_cnt = tot_cnt;

    FD_LOG_NOTICE(
        ( "selected %lu (previously: %lu) peers for repair (best was %lu, good was %lu, leftovers was %lu) (nonce_diff: %u)",
          tot_cnt,
          prev_sticky_cnt,
          best_cnt,
          good_cnt,
          leftovers_cnt,
          repair->next_nonce - repair->current_nonce ) );
  }
  FD_SCRATCH_SCOPE_END;
}

static fd_active_elem_t *
actives_sample( fd_repair_t * repair ) {
  ulong seed = repair->actives_random_seed;
  ulong actives_sticky_cnt = repair->actives_sticky_cnt;
  while( actives_sticky_cnt ) {
    seed += 774583887101UL;
    fd_pubkey_t *      id   = &repair->actives_sticky[seed % actives_sticky_cnt];
    fd_active_elem_t * peer = fd_active_table_query( repair->actives, id, NULL );
    if( NULL != peer ) {
      if( peer->first_request_time == 0U ) peer->first_request_time = repair->now;
      /* Aggressively throw away bad peers */
      if( repair->now - peer->first_request_time < (long)5e9 || /* Sample the peer for at least 5 seconds */
          is_good_peer( peer ) != -1 ) {
        repair->actives_random_seed = seed;
        return peer;
      }
      peer->sticky = 0;
    }
    *id = repair->actives_sticky[--( actives_sticky_cnt )];
  }
  return NULL;
}

static int
fd_repair_create_needed_request( fd_repair_t * glob, int type, ulong slot, uint shred_index ) {

  /* If there are no active sticky peers from which to send requests to, refresh the sticky peers
     selection. It may be that stake weights were not available before, and now they are. */
  if ( glob->actives_sticky_cnt == 0 ) {
    fd_actives_shuffle( glob );
  }

  fd_pubkey_t * ids[FD_REPAIR_NUM_NEEDED_PEERS] = {0};
  uint found_peer = 0;
  uint peer_cnt = fd_uint_min( (uint)glob->actives_sticky_cnt, FD_REPAIR_NUM_NEEDED_PEERS );
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    fd_active_elem_t * peer = actives_sample( glob );
    if(!peer) continue;
    found_peer = 1;

    ids[i] = &peer->key;
  }

  if (!found_peer) {
    /* maybe atp we should just... send it. TODO: reevaluate wth testnet */

    for( ulong i=0UL; i<peer_cnt; i++ ) {
      fd_pubkey_t *      id   = &glob->actives_sticky[i];
      fd_active_elem_t * peer = fd_active_table_query( glob->actives, id, NULL );
      if( peer ){
        peer->first_request_time = glob->now;
      }
    }

    // Can guarantee found peers now! lol
    for( ulong i=0UL; i<peer_cnt; i++ ) {
      fd_active_elem_t * peer = actives_sample( glob );
      if(!peer) continue;
      ids[i] = &peer->key;
    }
    //
    //return -1;
  };

  fd_dupdetect_key_t dupkey = { .type = (enum fd_needed_elem_type)type, .slot = slot, .shred_index = shred_index };
  fd_dupdetect_elem_t * dupelem = fd_dupdetect_table_query( glob->dupdetect, &dupkey, NULL );
  if( dupelem == NULL ) {
    dupelem = fd_dupdetect_table_insert( glob->dupdetect, &dupkey );
    dupelem->last_send_time = 0L;
  } else if( ( dupelem->last_send_time+(long)20e6 )>glob->now ) {
    // if last send time > now - 100ms. then we don't want to add another.

    //FD_LOG_INFO(("deduped request for %lu, %u", slot, shred_index));
    return 0;
  }

  dupelem->last_send_time = glob->now;
  dupelem->req_cnt = peer_cnt;

  if (fd_needed_table_is_full(glob->needed)) {
    FD_LOG_DEBUG(( "repair failed to get shred - slot: %lu, shred_index: %u, reason: %d", slot, shred_index, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED ));
    return -1;
  }
  for( ulong i=0UL; i<fd_ulong_min( fd_needed_table_key_max( glob->needed ) - fd_needed_table_key_cnt( glob->needed ), peer_cnt ); i++ ) {
    fd_repair_nonce_t key = glob->next_nonce++;
    fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
    val->id = *ids[i];
    val->dupkey = dupkey;
    val->when = glob->now;
  }
  FD_LOG_INFO(("added request for %lu, %u", slot, shred_index));

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
  return fd_repair_create_needed_request( glob, fd_needed_window_index, slot, shred_index );
}

int
fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  FD_LOG_DEBUG(( "[%s] need highest %lu", __func__, slot ));
  return fd_repair_create_needed_request( glob, fd_needed_highest_window_index, slot, shred_index );
}

int
fd_repair_need_orphan( fd_repair_t * glob, ulong slot ) {
  // FD_LOG_NOTICE( ( "[repair] need orphan %lu", slot ) );
  return fd_repair_create_needed_request( glob, fd_needed_orphan, slot, UINT_MAX );
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
    if( !val->sticky ) continue;
    print_stats( val );
  }
  FD_LOG_INFO( ( "peer count: %lu", fd_active_table_key_cnt( glob->actives ) ) );
}

void fd_repair_add_sticky( fd_repair_t * glob, fd_pubkey_t const * id ) {
  glob->actives_sticky[glob->actives_sticky_cnt++] = *id;

}

void
fd_repair_set_stake_weights_init( fd_repair_t * repair,
                                  fd_stake_weight_t const * stake_weights,
                                  ulong stake_weights_cnt ) {
  if( stake_weights == NULL ) {
    FD_LOG_ERR(( "stake weights NULL" ));
  }
  if( stake_weights_cnt > FD_STAKE_WEIGHTS_MAX ) {
    FD_LOG_ERR(( "too many stake weights" ));
  }

  fd_memcpy( repair->stake_weights_temp, stake_weights, stake_weights_cnt * sizeof(fd_stake_weight_t) );
  repair->stake_weights_temp_cnt = stake_weights_cnt;
}

void
fd_repair_set_stake_weights_fini( fd_repair_t * repair ) {
  fd_memcpy( repair->stake_weights, repair->stake_weights_temp, repair->stake_weights_temp_cnt * sizeof(fd_stake_weight_t) );
  repair->stake_weights_cnt = repair->stake_weights_temp_cnt;
}


fd_repair_metrics_t *
fd_repair_get_metrics( fd_repair_t * repair ) {
  return &repair->metrics;
}
