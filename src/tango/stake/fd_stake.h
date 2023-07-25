#ifndef HEADER_fd_src_tango_stake_fd_stake_h
#define HEADER_fd_src_tango_stake_fd_stake_h

#include "../../ballet/txn/fd_txn.h"

#define FD_STAKE_ALIGN               ( 128 )
#define FD_STAKE_LG_MAX_STAKED_NODES ( 16 )

struct fd_stake_pubkey {
  uchar pubkey[FD_TXN_PUBKEY_SZ];
};
typedef struct fd_stake_pubkey fd_stake_pubkey_t;
static fd_stake_pubkey_t       pubkey_null = { 0 };

/* Staked node map */
struct fd_stake_staked_node {
  fd_stake_pubkey_t key;
  uint              hash;
  ulong             stake;
};
typedef struct fd_stake_staked_node fd_stake_staked_node_t;

#define MAP_NAME                fd_stake_staked_node
#define MAP_T                   fd_stake_staked_node_t
#define MAP_KEY_T               fd_stake_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_stake_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( k0.pubkey ), ( k1.pubkey ), FD_TXN_PUBKEY_SZ ) )
// #define MAP_KEY_EQUAL( k0, k1 ) (sizeof(k0.pubkey) == sizeof(k1.pubkey))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH( key )   ( (uint)( fd_hash( 0UL, key.pubkey, FD_TXN_PUBKEY_SZ ) ) )
// #define MAP_KEY_HASH( key ) ( fd_uint_load_4( &key.pubkey ) )
// #define MAP_KEY_HASH( key )     ( *(uint *)( fd_type_pun( &key.pubkey ) ) )  /* FIXME UB */
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_stake {
  ulong                    version; /* MVCC version */
  ulong                    total_stake;
  fd_stake_staked_node_t * staked_nodes;
};
typedef struct fd_stake fd_stake_t;

ulong
fd_stake_align( void );

ulong
fd_stake_footprint( ulong lg_max_node_cnt );

void *
fd_stake_new( void * mem, ulong lg_max_node_cnt );

fd_stake_t *
fd_stake_join( void * mem );

/* for FFI */
ulong *
fd_stake_version( fd_stake_t * stake );

/* updates using the (serialized) staked nodes from the labs client */
void
fd_stake_update( fd_stake_t * stake, uchar * staked_nodes_ser, ulong sz );

#endif /* HEADER_fd_src_tango_stake_fd_stake_h */
