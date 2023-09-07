#ifndef HEADER_fd_src_tango_quic_fd_quic_stake_h
#define HEADER_fd_src_tango_quic_fd_quic_stake_h

#define FD_QUIC_STAKE_PUBKEY_SZ 32UL

struct fd_quic_stake_pubkey {
  uchar pubkey[FD_QUIC_STAKE_PUBKEY_SZ];
};

typedef struct fd_quic_stake_pubkey fd_quic_stake_pubkey_t;
static fd_quic_stake_pubkey_t       pubkey_null = { 0 };

struct fd_quic_stake {
  fd_quic_stake_pubkey_t key;
  uint                   hash;
  ulong                  stake;
};
typedef struct fd_quic_stake fd_quic_stake_t;

#define MAP_NAME                fd_quic_stake
#define MAP_T                   fd_quic_stake_t
#define MAP_KEY_T               fd_quic_stake_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_quic_stake_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( k0.pubkey ), ( k1.pubkey ), FD_QUIC_STAKE_PUBKEY_SZ ) )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH( key )   ( (uint)( fd_hash( 0UL, key.pubkey, FD_QUIC_STAKE_PUBKEY_SZ ) ) )
#include "../../util/tmpl/fd_map_dynamic.c"
#undef MAP_NAME
#undef MAP_T
#undef MAP_KEY_T
#undef MAP_KEY_NULL
#undef MAP_KEY_INVAL
#undef MAP_KEY_EQUAL
#undef MAP_KEY_EQUAL_IS_SLOW
#undef MAP_KEY_HASH

#endif /* HEADER_fd_src_tango_quic_fd_quic_stake_h */
