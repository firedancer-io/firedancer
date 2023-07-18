struct txn_map_key {
    fd_ed25519_sig_t v;
};
struct txn_map_elem {
    struct txn_map_key key;
    ulong slot;
    ulong txn_off;
    ulong txn_sz;
    ulong txn_stat_off;
    ulong txn_stat_sz;
    ulong next;
};
typedef struct txn_map_elem txn_map_elem_t;
extern txn_map_elem_t * txn_map;

static inline ulong fd_ed25519_quickhash(const struct txn_map_key * key, ulong seed) {
  const ulong* x = (const ulong*)key;
  for (ulong i = 0; i < sizeof(struct txn_map_key)/sizeof(ulong); ++i)
    seed ^= x[i];
  return seed;
}

static inline void fd_ed25519_quickcpy(struct txn_map_key * keydest, const struct txn_map_key * keysrc) {
  ulong* x = (ulong*)keydest;
  const ulong* y = (const ulong*)keysrc;
  for (ulong i = 0; i < sizeof(struct txn_map_key)/sizeof(ulong); ++i)
    x[i] = y[i];
}

static inline int fd_ed25519_quickeq(const struct txn_map_key * key1, const struct txn_map_key * key2) {
  const ulong* x = (const ulong*)key1;
  const ulong* y = (const ulong*)key2;
  for (ulong i = 0; i < sizeof(struct txn_map_key)/sizeof(ulong); ++i)
    if (x[i] != y[i]) return 0;
  return 1;
}

#define MAP_KEY_T struct txn_map_key
#define MAP_NAME  txn_map_elem
#define MAP_T     txn_map_elem_t
#define MAP_KEY_HASH(key,seed) fd_ed25519_quickhash(key, seed)
#define MAP_KEY_COPY(keydest,keysrc) fd_ed25519_quickcpy(keydest, keysrc)
#define MAP_KEY_EQ(k0,k1) fd_ed25519_quickeq(k0, k1)
#include "../../util/tmpl/fd_map_giant.c"

enum fd_block_encoding { FD_BLOCK_ENC_BASE58, FD_BLOCK_ENC_BASE64, FD_BLOCK_ENC_JSON, FD_BLOCK_ENC_JSON_PARSED };

enum fd_block_detail { FD_BLOCK_DETAIL_FULL, FD_BLOCK_DETAIL_ACCTS, FD_BLOCK_DETAIL_SIGS, FD_BLOCK_DETAIL_NONE };

int fd_txn_to_json( fd_textstream_t * ts,
                    fd_txn_t* txn,
                    const uchar* raw,
                    const void * meta_raw,
                    ulong meta_raw_sz,
                    enum fd_block_encoding encoding,
                    long maxvers,
                    enum fd_block_detail detail,
                    int rewards );

int fd_block_to_json( fd_textstream_t * ts,
                      long call_id,
                      const void* block,
                      ulong block_sz,
                      const void* stat_block,
                      ulong stat_block_sz,
                      enum fd_block_encoding encoding,
                      long maxvers,
                      enum fd_block_detail detail,
                      int rewards);
