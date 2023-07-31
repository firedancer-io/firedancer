#ifndef HEADER_fd_src_tango_stake_fd_stake_h
#define HEADER_fd_src_tango_stake_fd_stake_h

#include "../../ballet/txn/fd_txn.h"
#include "../mvcc/fd_mvcc.h"

/* double cache line */
#define FD_STAKE_ALIGN ( 128 )

/* maximum lg # of staked nodes we can track */
#define FD_STAKE_LG_SLOT_CNT ( 16 )

/* opaque */
#define FD_STAKE_MAGIC ( 0xF17EDA2CE757A1E0 ) /* FIREDANCER STAKE V0 */

struct fd_stake_private {
  ulong     magic; /* == FD_STAKE_MAGIC */
  fd_mvcc_t mvcc;
  ulong     total_stake; /* total amount of stake */
  ulong     nodes_off;   /* offset to map region */
};
typedef struct fd_stake_private fd_stake_t;

struct fd_stake_pubkey {
  uchar pubkey[FD_TXN_PUBKEY_SZ];
};

typedef struct fd_stake_pubkey fd_stake_pubkey_t;
static fd_stake_pubkey_t       pubkey_null = { 0 };

/* Staked node map */
struct fd_stake_node {
  fd_stake_pubkey_t key;
  uint              hash;
  ulong             stake;
};
typedef struct fd_stake_node fd_stake_node_t;

#define MAP_NAME                fd_stake_node
#define MAP_T                   fd_stake_node_t
#define MAP_KEY_T               fd_stake_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_stake_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( k0.pubkey ), ( k1.pubkey ), FD_TXN_PUBKEY_SZ ) )
// #define MAP_KEY_EQUAL( k0, k1 ) map_key_equal(k0, k1)
// #define MAP_KEY_EQUAL( k0, k1 ) (sizeof(k0.pubkey) == sizeof(k1.pubkey))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH( key )   ( (uint)( fd_hash( 0UL, key.pubkey, FD_TXN_PUBKEY_SZ ) ) )
// #define MAP_KEY_HASH( key ) ( fd_uint_load_4( fd_type_pun( &key.pubkey ) ) )
// #define MAP_KEY_HASH( key )     ( *(uint *)( fd_type_pun( &key.pubkey ) ) )  /* FIXME UB */
#include "../../util/tmpl/fd_map_dynamic.c"

ulong
fd_stake_align( void );

ulong
fd_stake_footprint( int lg_slot_cnt );

/* fd_stake_new formats an unused memory region for use as an fd_stake_t. `nodes_off` points to the
   first slot, which is past the map header. The layout is diagrammed below:

   ------------------ <- (fd_stake_t * stake)
   private hdr region
   ------------------
   nodes map region

   .....   hdr  .....
   ..... node 0 ..... <- (fd_stake_t * stake) + nodes_off
   ..... node 1 .....
   ..... ...... .....
   ..... node n .....

   ------------------ */
void *
fd_stake_new( void * mem, int lg_slot_cnt );

/* fd_stake_t is designed to be shared across multiple joins.

   Therefore, it maintains an offset for the staked nodes region (which itself requires a join),
   which is located within the stake region itself. It uses an offset in lieu of pointers, because
   the pointer addresses would otherwise be local to each joined process. Note this is a pointer to
   the first slot in the map, rather than the start of the map region itself, as `fd_map_dynamic`
   expects slot pointers in its API.

   See `fd_stake_new` for the layout. */
fd_stake_t *
fd_stake_join( void * shstake );

ulong
fd_stake_version( fd_stake_t * stake );

ulong *
fd_stake_version_laddr( fd_stake_t * stake );

fd_stake_node_t *
fd_stake_nodes_laddr( fd_stake_t * stake );

/* updates using the (serialized) staked nodes from the labs client */
void
fd_stake_update( fd_stake_t * stake, uchar * staked_nodes_ser, ulong sz );

void
fd_stake_dump( fd_stake_t * stake );

#endif /* HEADER_fd_src_tango_stake_fd_stake_h */
