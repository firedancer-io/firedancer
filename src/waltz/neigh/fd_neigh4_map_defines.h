#define MAP_NAME               fd_neigh4_hmap
#define MAP_ELE_T              fd_neigh4_entry_t
#define MAP_KEY_T              uint
#define MAP_KEY                ip4_addr
#define MAP_KEY_HASH(key,seed) fd_uint_hash( (*(key)) ^ ((uint)seed) )
#define MAP_ELE_MOVE(c,d,s)     do { \
                                  fd_neigh4_entry_t * _src = (s); \
                                  fd_neigh4_entry_atomic_st((d),_src); \
                                  _src->ip4_addr = 0U; \
                                } while(0)
