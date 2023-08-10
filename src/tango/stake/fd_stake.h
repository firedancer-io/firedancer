#ifndef HEADER_fd_src_tango_stake_fd_stake_h
#define HEADER_fd_src_tango_stake_fd_stake_h

#include "../mvcc/fd_mvcc.h"

/* double cache line */
#define FD_STAKE_ALIGN 128UL

/* maximum lg # of staked nodes we can track */
#define FD_STAKE_LG_SLOT_CNT 16UL

/* 32-bytes, as with all Solana pubkeys */
#define FD_STAKE_PUBKEY_SZ 32UL

/* opaque */
#define FD_STAKE_MAGIC 0xF17EDA2CE757A1E0 /* FIREDANCER STAKE V0 */

struct fd_stake_private {
  ulong     magic; /* == FD_STAKE_MAGIC */
  fd_mvcc_t mvcc;
  ulong     total_stake; /* total amount of stake */
  ulong     nodes_off;   /* offset to map region */
};
typedef struct fd_stake_private fd_stake_t;

struct fd_stake_pubkey {
  uchar pubkey[FD_STAKE_PUBKEY_SZ];
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
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( k0.pubkey ), ( k1.pubkey ), FD_STAKE_PUBKEY_SZ ) )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH( key )   ( (uint)( fd_hash( 0UL, key.pubkey, FD_STAKE_PUBKEY_SZ ) ) )
#include "../../util/tmpl/fd_map_dynamic.c"

ulong
fd_stake_align( void );

ulong
fd_stake_footprint( int lg_slot_cnt );

/* fd_stake_new formats an unused memory region for use as a stake object. `nodes_off` points to the
   first slot, which is past the map header. The layout is diagrammed below:

   ------------------ <- (fd_stake_t * stake)  // returned by fd_stake_new
   private hdr region
   ------------------
   nodes map region

   .....   hdr  .....
   ..... node 0 .....
   ..... node 1 .....
   ..... ...... .....
   ..... node n .....

   ------------------ */
void *
fd_stake_new( void * mem, int lg_slot_cnt );

/* fd_stake_join joins the caller to the stake object.

   fd_stake_t is designed to be shared across multiple joins. Therefore, it maintains an offset for
   the staked nodes region (which itself requires a join), which is located within the stake region
   itself. It uses an offset in lieu of pointers, because the pointer addresses would otherwise be
   local to each joined process. Note this is a pointer to the first slot in the map, rather than
   the start of the map region itself, as `fd_map_dynamic` expects slot pointers in its API.

  -------------------
   private hdr region
   ------------------
   nodes map region

   .....   hdr  .....
   ..... node 0 ..... <- (fd_stake_t * stake) + nodes_off  // set by fd_stake_join
   ..... node 1 .....
   ..... ...... .....
   ..... node n .....

   ------------------ */
fd_stake_t *
fd_stake_join( void * shstake );

ulong
fd_stake_version( fd_stake_t * stake );

ulong *
fd_stake_version_laddr( fd_stake_t * stake );

fd_stake_node_t *
fd_stake_nodes_laddr( fd_stake_t * stake );

/* fd_stake_read performs an mvcc-fenced read of the stake structure. `fd_stake_t` is a single-producer,
 * multiple-consumer concurrency structure and an odd version number indicates the writer is
 * currently writing to the structure. */
fd_stake_t *
fd_stake_read( fd_stake_t * stake);

/* fd_stake_write performs an mvcc-fenced write of the stake structure. Assumes there is a single
   writer and does not check for safe concurrency with multiple writers.

   `data` is a pointer to a bincode-serialized byte representation of stakes from the labs client.

   Serialization format:
   -----------
   total stake  (8 bytes, le)
   node0 pubkey (32 bytes, le)
   node0 stake  (8 bytes, le)
   node1 pubkey (32 bytes, le)
   node1 stake  (8 bytes, le)
   ...
   ----------- */
void
fd_stake_deser( fd_stake_t * stake, uchar * data, ulong sz );

void
fd_stake_dump( fd_stake_t * stake );

#endif /* HEADER_fd_src_tango_stake_fd_stake_h */
