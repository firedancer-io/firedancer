#include "fd_gossip.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../ballet/base58/fd_base58.h"
#include <sys/random.h>
#include <unistd.h>
#include <signal.h>

/* Number of bloom filter bits in an outgoing pull request packet */
#define FD_BLOOM_NUM_BITS (512U*8U) /* 0.5 Kbyte */
/* Max number of bloom filter keys in an outgoing pull request packet */
#define FD_BLOOM_MAX_KEYS 32U
/* Max number of packets in an outgoing pull request batch */
#define FD_BLOOM_MAX_PACKETS 32U
/* How long do we remember values (in millisecs) */
#define FD_GOSSIP_VALUE_EXPIRE ((ulong)(60e3))   /* 1 minute */

static void
send_packet( uchar const * data, size_t sz, fd_gossip_peer_addr_t const * addr, void * arg ) {
  (void)arg;
  (void)addr;
  (void)sz;
  (void)data;
  FD_LOG_DEBUG(("Send %lu", sz));
}

static void 
deliver_fun( fd_crds_data_t * data, void * arg ) {
  (void)data;
  (void)arg;
  FD_LOG_DEBUG(("Deliver %u", data->discriminant));
}

/* Copy a hash value */
static void fd_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

/* Convert a hash to a bloom filter bit position */
static ulong
fd_gossip_bloom_pos( fd_hash_t * hash, ulong key, ulong nbits) {
  for ( ulong i = 0; i < 32U; ++i) {
    key ^= (ulong)(hash->uc[i]);
    key *= 1099511628211UL;
  }
  return key % nbits;
}

static void recv_random_pull_req( fd_gossip_t * glob, fd_rng_t * rng, fd_gossip_peer_addr_t * from, fd_pubkey_t * public_key ) {
  /* Compute the number of packets needed for all the bloom filter parts */
  ulong nitems = 5;
  ulong nkeys = 1;
  ulong npackets = 1;
  uint nmaskbits = 0;
  double e = 0;
  if (nitems > 0) {
    do {
      double n = ((double)nitems)/((double)npackets); /* Assume even division of values */
      double m = (double)FD_BLOOM_NUM_BITS;
      nkeys = fd_ulong_max(1U, (ulong)((m/n)*0.69314718055994530941723212145818 /* ln(2) */));
      nkeys = fd_ulong_min(nkeys, FD_BLOOM_MAX_KEYS);
      if (npackets == FD_BLOOM_MAX_PACKETS)
        break;
      double k = (double)nkeys;
      e = pow(1.0 - exp(-k*n/m), k);
      if (e < 0.001)
        break;
      nmaskbits++;
      npackets = 1U<<nmaskbits;
    } while (1);
  }
  FD_LOG_DEBUG(("making bloom filter for %lu items with %lu packets and %lu keys %g error", nitems, npackets, nkeys, e));

  /* Generate random keys */
  ulong keys[FD_BLOOM_MAX_KEYS];
  for (ulong i = 0; i < nkeys; ++i)
    keys[i] = fd_rng_ulong(rng);
  /* Set all the bits */
  ulong num_bits_set[FD_BLOOM_MAX_PACKETS];
  for (ulong i = 0; i < npackets; ++i)
    num_bits_set[i] = 0;
#define CHUNKSIZE (FD_BLOOM_NUM_BITS/64U)
  ulong bits[CHUNKSIZE * FD_BLOOM_MAX_PACKETS];
  fd_memset(bits, 0, CHUNKSIZE*8U*npackets);
  fd_hash_t hash;
  for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i )
    hash.ul[i] = fd_rng_ulong( rng );

  /* Choose which filter packet based on the high bits in the hash */
  ulong index = (nmaskbits == 0 ? 0UL : ( hash.ul[0] >> (64U - nmaskbits) ));
  ulong * chunk = bits + (index*CHUNKSIZE);
  for (ulong i = 0; i < nkeys; ++i) {
    ulong pos = fd_gossip_bloom_pos(&hash, keys[i], FD_BLOOM_NUM_BITS);
    ulong * j = chunk + (pos>>6U); /* divide by 64 */
    ulong bit = 1UL<<(pos & 63U);
    if (!((*j) & bit)) {
      *j |= bit;
      num_bits_set[index]++;
    }
  }

  /* Assemble the packets */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pull_req);
  fd_gossip_pull_req_t * req = &gmsg.inner.pull_req;
  fd_crds_filter_t * filter = &req->filter;
  filter->mask_bits = nmaskbits;
  filter->filter.keys_len = nkeys;
  filter->filter.keys = keys;
  fd_gossip_bitvec_u64_t * bitvec = &filter->filter.bits;
  bitvec->len = FD_BLOOM_NUM_BITS;
  bitvec->has_bits = 1;
  bitvec->bits.vec_len = FD_BLOOM_NUM_BITS/64U;

  /* The "value" in the request is always my own contact info */
  fd_crds_value_t * value = &req->value;
  fd_crds_data_new_disc(&value->data, fd_crds_data_enum_accounts_hashes);
  fd_gossip_slot_hashes_t * slot_hashes = &value->data.inner.accounts_hashes;
  slot_hashes->from = *public_key;
  slot_hashes->hashes_len = 1;
  fd_slot_hash_t slot_hash;
  slot_hash.slot = 145;
  fd_hash_copy(&slot_hash.hash, &hash);
  slot_hashes->hashes = &slot_hash;
  slot_hashes->wallclock = (ulong)fd_log_wallclock();
  fd_gossip_sign_crds_value(glob, value);

  for (uint i = 0; i < npackets; ++i) {
    /* Update the filter mask specific part */
    filter->mask = (nmaskbits == 0 ? ~0UL : ((i << (64U - nmaskbits)) | (~0UL >> nmaskbits)));
    filter->filter.num_bits_set = num_bits_set[i];
    bitvec->bits.vec = bits + (i*CHUNKSIZE);

    uchar buf[FD_ETH_PAYLOAD_MAX];
    fd_memset(buf, 0, FD_ETH_PAYLOAD_MAX);
    fd_bincode_encode_ctx_t encode = {.data = buf, .dataend= buf + FD_ETH_PAYLOAD_MAX};
    fd_gossip_msg_encode( &gmsg, &encode );
    ulong sz = fd_gossip_msg_size( &gmsg );
    fd_gossip_recv_packet( glob, buf, sz, from );
  }
}

// SIGINT signal handler
volatile int stopflag = 0;
static void stop(int sig) { (void)sig; stopflag = 1; }

static int
main_loop( fd_gossip_t * glob, uchar * private_key, fd_gossip_peer_addr_t * from, volatile int * stopflag ) {

  fd_gossip_settime(glob, fd_log_wallclock());
  fd_gossip_start(glob);
  fd_rng_t rng[1];
  fd_rng_new(rng, (uint)1234, 0UL);

  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  fd_ed25519_public_from_private( public_key.uc, private_key, sha );

  while ( !*stopflag ) {
    fd_gossip_settime(glob, fd_log_wallclock());
    fd_gossip_continue(glob);
    recv_random_pull_req( glob, rng, from, &public_key );
    // // Uncomment for random ping receives
    // fd_gossip_msg_t gmsg;
    // fd_memset( &gmsg, 0xFF, sizeof(fd_gossip_msg_t));
    // gmsg.discriminant = fd_gossip_msg_enum_ping;
    // fd_gossip_ping_t * ping = &gmsg.inner.ping;
    // fd_hash_t pingtoken;
    // for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i )
    //   pingtoken.ul[i] = fd_rng_ulong( rng );

    // fd_hash_copy( &ping->from, &public_key );
    // fd_hash_copy( &ping->token, &pingtoken );

    // fd_ed25519_sign( /* sig */ ping->signature.uc,
    //                /* msg */ ping->token.uc,
    //                /* sz  */ 32UL,
    //                /* public_key  */ &public_key,
    //                /* private_key */ private_key,
    //                sha );

    // uchar buf[FD_ETH_PAYLOAD_MAX];
    // fd_bincode_encode_ctx_t encode = {.data = buf, .dataend= buf + FD_ETH_PAYLOAD_MAX};
    // fd_gossip_msg_encode( &gmsg, &encode );
    // ulong sz = fd_gossip_msg_size( &gmsg );
    // fd_gossip_recv_packet( glob, buf, FD_ETH_PAYLOAD_MAX, from );
  }

  return 0;
}

int 
main( int     argc, 
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_valloc_t valloc = fd_libc_alloc_virtual();
  void * shm = fd_valloc_malloc(valloc, fd_gossip_align(), fd_gossip_footprint());

  ulong seed = 42;
  fd_gossip_t * glob = fd_gossip_join(fd_gossip_new(shm, seed, valloc));

  fd_gossip_config_t config;
  fd_memset(&config, 0, sizeof(config));

  uchar private_key[32];
  FD_TEST( 32UL==getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

  config.private_key = private_key;
  config.public_key = &public_key;

  char hostname[64];
  gethostname(hostname, sizeof(hostname));

  config.shred_version = 4200;
  config.send_fun = send_packet;
  config.deliver_fun = deliver_fun;
  config.my_addr.addr = 0;
  config.my_addr.port = 1000;

  if ( fd_gossip_set_config(glob, &config) )
    return 1;

  fd_gossip_peer_addr_t peer_addr = { .addr = 0, .port = 1024 };
  if ( fd_gossip_add_active_peer(glob, &peer_addr) )
    return 1;

  signal(SIGINT, stop);

  fd_gossip_settime( glob, fd_log_wallclock() );
  fd_gossip_start( glob );

  if ( main_loop(glob, private_key, &peer_addr, &stopflag ) )
    return 1;

  fd_valloc_free(valloc, fd_gossip_delete(fd_gossip_leave(glob), valloc));
}