#ifndef HEADER_fd_src_disco_repair_fd_rserve_h
#define HEADER_fd_src_disco_repair_fd_rserve_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"

/* Repair server. */

/* TODO: We want to consider not using a ping-cache, and instead rely on
   the existing set of "good" nodes we'd need to know about from Gossip.
   A ping-cache is a simple solution for the time being. */

/* Ping cache TTL in nanoseconds (1280 seconds). */
#define FD_RSERVE_PING_CACHE_TTL_NS (1280UL * 1000000000UL)
/* Token rotation period in nanoseconds (640 seconds, half of TTL). */
#define FD_RSERVE_TOKEN_ROTATE_NS   (640UL * 1000000000UL)


struct __attribute__((packed)) ping_cache_key {
  fd_pubkey_t pubkey; /* pubkey of the node which sent the ping */
  uint        ip4;    /* source ipv4 address of the pong */
  ushort      port;   /* source udp port of the pong */
};
typedef struct ping_cache_key ping_cache_key_t;

typedef struct {
  ping_cache_key_t key;  /* (pubkey, address) that completed a ping */
  ulong       next;      /* Pool free-list next. */
  struct {
    ulong prev;
    ulong next;
  } map;                 /* fd_map_chain prev/next. */
  struct {
    ulong prev;
    ulong next;
  } dlist;               /* LRU dlist prev/next. */
  ulong       timestamp; /* The time at which the pong was received. Stored in nanoseconds. */
} ping_cache_entry_t;

#define POOL_NAME  ping_pool
#define POOL_T     ping_cache_entry_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           ping_map
#define MAP_ELE_T                          ping_cache_entry_t
#define MAP_KEY_T                          ping_cache_key_t
#define MAP_KEY                            key
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0),(k1),sizeof(ping_cache_key_t)))
#define MAP_KEY_HASH(key,seed)             fd_ulong_hash( fd_hash( (seed), key->pubkey.uc, sizeof(fd_pubkey_t) ) ^ ((ulong)(key)->ip4) ^ (((ulong)(key)->port)<<32) ^ (seed) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  ping_dlist
#define DLIST_ELE_T ping_cache_entry_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

typedef struct {
  ping_cache_entry_t * ping_pool;
  ping_map_t         * ping_map;
  ping_dlist_t       * ping_dlist;

  uchar secret_master[ 32 ];
  uchar secret_cur   [ 32 ];
  uchar secret_prev  [ 32 ];
  ulong token_idx;
  ulong last_rotate_ts;

  ulong seed;
} fd_rserve_t;

FD_FN_CONST static inline ulong
fd_rserve_align( void ) {
  return 128UL;
}

ulong
fd_rserve_footprint( ulong ping_cache_entries );

void *
fd_rserve_new( void      * shmem,
               ulong       ping_cache_entries,
               ulong       seed,
               uchar const secret[ 32 ] );

fd_rserve_t *
fd_rserve_join( void * shrserve );

void *
fd_rserve_leave( fd_rserve_t const * rserve );

void *
fd_rserve_delete( void * rserve );

void
fd_rserve_ping_token( fd_rserve_t const * rserve,
                      uchar               token[ 32 ],
                      fd_pubkey_t const * from,
                      uint                ip4,
                      ushort              port );

int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash,
                             fd_pubkey_t const * from,
                             uint                ip4,
                             ushort              port );

void
fd_rserve_maybe_rotate( fd_rserve_t * rserve,
                        ulong         now_ns );

/* fd_blockdb stores metadata of completed blocks, keyed by
   (slot, block_id), for serving Alpenglow block id repair requests.
   Entries live in a fixed array and are overwritten oldest-first. */

#define FD_BLOCKDB_ALIGN (128UL)

/* The double-merkle tree has at most FD_FEC_BLK_MAX+1 leaves (FEC roots
   plus the parent-info leaf), so at most 11 layers and 10 proof nodes. */

#define FD_BLOCKDB_TREE_LAYER_MAX (11UL)
#define FD_BLOCKDB_PROOF_NODE_MAX (FD_BLOCKDB_TREE_LAYER_MAX-1UL)

struct fd_blockdb_key {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_blockdb_key fd_blockdb_key_t;

FD_STATIC_ASSERT( sizeof(fd_blockdb_key_t)==40UL, fd_blockdb_key_t );

/* merkle_roots holds the first FD_SHRED_MERKLE_NODE_SZ bytes of each FEC
   set's merkle root, the only bytes the block id commits to.  Only the
   first fec_set_cnt entries are meaningful. */

struct fd_blockdb_blk {
  fd_blockdb_key_t key;
  ulong            parent_slot;
  fd_hash_t        parent_block_id;
  uint             fec_set_cnt;
  uint             next; /* map chain */
  uint             prev; /* map chain */
  uchar            merkle_roots[ FD_FEC_BLK_MAX ][ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_blockdb_blk fd_blockdb_blk_t;

struct fd_blockdb {
  ulong              ele_max;
  ulong              seq;     /* total inserts, next slot is seq%ele_max */
  fd_blockdb_blk_t * ele;
  void *             map;
  void *             tree;    /* scratch for building proofs */
};
typedef struct fd_blockdb fd_blockdb_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_blockdb_align( void ) {
  return FD_BLOCKDB_ALIGN;
}

/* fd_blockdb_footprint returns the footprint for ele_max entries, or 0
   if ele_max is zero or not less than UINT_MAX. */

ulong
fd_blockdb_footprint( ulong ele_max );

void *
fd_blockdb_new( void * shmem,
                ulong  ele_max,
                ulong  seed );

fd_blockdb_t *
fd_blockdb_join( void * shblockdb );

void *
fd_blockdb_leave( fd_blockdb_t const * blockdb );

void *
fd_blockdb_delete( void * shblockdb );

/* fd_blockdb_insert stores a block, overwriting the oldest entry when
   full.  Re-inserting an existing key updates it in place.
   merkle_roots points to fec_set_cnt 20B roots.  Returns NULL if
   fec_set_cnt is 0 or exceeds FD_FEC_BLK_MAX. */

fd_blockdb_blk_t *
fd_blockdb_insert( fd_blockdb_t *    blockdb,
                   ulong             slot,
                   fd_hash_t const * block_id,
                   ulong             parent_slot,
                   fd_hash_t const * parent_block_id,
                   uint              fec_set_cnt,
                   uchar const *     merkle_roots );

/* fd_blockdb_query returns the entry for (slot, block_id), or NULL.
   The pointer is invalidated by the next insert. */

fd_blockdb_blk_t const *
fd_blockdb_query( fd_blockdb_t const * blockdb,
                  ulong                slot,
                  fd_hash_t const *    block_id );

/* fd_blockdb_proof writes blk's double-merkle inclusion proof for leaf
   leaf_idx to proof, as 20B nodes from leaf to root.  Leaves are the FEC
   roots, then the parent-info leaf at fec_set_cnt.  Returns the node
   count, or -1 if leaf_idx>fec_set_cnt. */

int
fd_blockdb_proof( fd_blockdb_t *           blockdb,
                  fd_blockdb_blk_t const * blk,
                  ulong                    leaf_idx,
                  uchar                    proof[ FD_BLOCKDB_PROOF_NODE_MAX*FD_SHRED_MERKLE_NODE_SZ ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_repair_fd_rserve_h */
