#include "fd_hfork.h"

struct bank_hash {
  fd_hash_t bank_hash;
  ulong     next;
};
typedef struct bank_hash bank_hash_t;

#define POOL_NAME bank_hash_pool
#define POOL_T    bank_hash_t
#include "../../util/tmpl/fd_pool.c"

struct blk {
  fd_hash_t     block_id;
  uint          hash;
  int           forked;        /* whether this block id has hard forked (multiple candidate bank hashes) */
  int           replayed;      /* whether we've replayed */
  int           dead;          /* whether we marked the block as dead during replay (must ignore our_bank_hash) */
  fd_hash_t     our_bank_hash; /* our bank hash for this block_id after replay */
  bank_hash_t * bank_hashes;
};
typedef struct blk blk_t;

#define MAP_NAME               blk_map
#define MAP_T                  blk_t
#define MAP_KEY                block_id
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_NULL           hash_null
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_INVAL(k)       MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)   (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key,seed) ((MAP_HASH_T)( (key).ul[1] )) /* FIXME: use seed? */
#include "../../util/tmpl/fd_map_dynamic.c"

struct vote {
  fd_hash_t block_id;
  fd_hash_t bank_hash;
  ulong     slot;
  ulong     stake;
};
typedef struct vote vote_t;

#define DEQUE_NAME votes
#define DEQUE_T    vote_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct vtr {
  fd_pubkey_t vote_acc;
  uint        hash;
  vote_t *    votes;
};
typedef struct vtr vtr_t;

#define MAP_NAME               vtr_map
#define MAP_T                  vtr_t
#define MAP_KEY                vote_acc
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           pubkey_null
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_INVAL(k)       MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)   (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key,seed) ((MAP_HASH_T)( (key).ul[1] )) /* FIXME: use seed? */
#include "../../util/tmpl/fd_map_dynamic.c"

struct candidate_key {
  fd_pubkey_t block_id;
  fd_pubkey_t bank_hash;
};
typedef struct candidate_key candidate_key_t;

struct candidate {
  candidate_key_t key;
  uint            hash;
  ulong           slot;
  ulong           stake;
  ulong           cnt;
  int             checked;
};
typedef struct candidate candidate_t;

static const candidate_key_t candidate_key_null = { 0 };

#define MAP_NAME               candidate_map
#define MAP_KEY                key
#define MAP_T                  candidate_t
#define MAP_KEY_T              candidate_key_t
#define MAP_KEY_NULL           candidate_key_null
#define MAP_KEY_INVAL(k)       MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)   (fd_pubkey_eq( &((k0).block_id),  &((k1).block_id )   ) &\
                                fd_pubkey_eq( &((k0).bank_hash), &((k1).bank_hash) ) )
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key,seed) (fd_uint_load_4( (key).block_id.uc ) ^ fd_uint_load_4( (key).bank_hash.uc ) ) /* FIXME: use seed? */
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_hfork {
  blk_t *       blk_map;
  vtr_t *       vtr_map;
  candidate_t * candidate_map;
  bank_hash_t * bank_hash_pool;
  int           fatal;
};
typedef struct fd_hfork fd_hfork_t;
