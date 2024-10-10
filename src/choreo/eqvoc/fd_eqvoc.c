#include "fd_eqvoc.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/runtime/fd_blockstore.h"

/* FD_EQVOC_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EQVOC_USE_HANDHOLDING
#define FD_EQVOC_USE_HANDHOLDING 1
#endif

struct fd_eqvoc_key {
  ulong slot;
  uint  fec_set_idx;
};
typedef struct fd_eqvoc_key fd_eqvoc_key_t;

/* clang-format off */
// static const fd_eqvoc_key_t     fd_eqvoc_key_null = { 0 };
#define FD_EQVOC_KEY_NULL       fd_eqvoc_key_null
#define FD_EQVOC_KEY_INVAL(key) (!((key).slot) & !((key).fec_set_idx))
#define FD_EQVOC_KEY_EQ(k0,k1)  (!(((k0).slot) ^ ((k1).slot))) & !(((k0).fec_set_idx) ^ (((k1).fec_set_idx)))
#define FD_EQVOC_KEY_HASH(key)  ((uint)(((key).slot)<<15UL) | (((key).fec_set_idx)))
/* clang-format on */

struct fd_eqvoc_entry {
  fd_eqvoc_key_t   key;
  ulong            next;
  fd_ed25519_sig_t sig;
};
typedef struct fd_eqvoc_entry fd_eqvoc_entry_t;

#define POOL_NAME fd_eqvoc_pool
#define POOL_T    fd_eqvoc_entry_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_eqvoc_map
#define MAP_ELE_T              fd_eqvoc_entry_t
#define MAP_KEY_T              fd_eqvoc_key_t
#define MAP_KEY_EQ(k0,k1)      FD_EQVOC_KEY_EQ(*k0,*k1)
#define MAP_KEY_HASH(key,seed) (FD_EQVOC_KEY_HASH(*key) ^ seed)
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

struct fd_eqvoc {
  fd_eqvoc_map_t *   map;
  fd_eqvoc_entry_t * pool;
};
typedef struct fd_eqvoc fd_eqvoc_t;

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_entry_t * ele = fd_eqvoc_pool_ele_acquire( eqvoc->pool );
  ele->key.slot          = shred->slot;
  ele->key.fec_set_idx   = shred->fec_set_idx;
  memcpy( ele->sig, shred->signature, FD_ED25519_SIG_SZ );
  fd_eqvoc_map_ele_insert( eqvoc->map, ele, eqvoc->pool );
}

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_key_t           key = { shred->slot, shred->fec_set_idx };
  fd_eqvoc_entry_t const * ele = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                               &key,
                                                               NULL,
                                                               eqvoc->pool );
  return 0 == memcmp( ele->sig, shred->signature, FD_ED25519_SIG_SZ );
}
