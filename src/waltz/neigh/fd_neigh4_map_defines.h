#define MAP_NAME               fd_neigh4_hmap
#define MAP_T                  fd_neigh4_entry_t
#define MAP_KEY_T              uint
#define MAP_KEY                ip4_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( key ) ^ ((uint)seed)
#define MAP_KEY_NULL           ((uint)0U)
#define MAP_KEY_INVAL(k)       !(k)
#define MAP_KEY_EQUAL(a,b)     ((a)==(b))
#define MAP_KEY_EQUAL_IS_SLOW  0
#define MAP_QUERY_OPT          1
#define MAP_MEMOIZE            0
#define MAP_MOVE(d,s)          fd_neigh4_entry_atomic_ld(&(d),&(s))
