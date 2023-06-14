#ifndef HEADER_fd_src_ballet_runtime_fd_types_custom
#define HEADER_fd_src_ballet_runtime_fd_types_custom

#include "../../ballet/fd_ballet_base.h"
#include "fd_bincode.h"

typedef void (*fd_walk_fun_t)(void *arg, const char* name, int type, const char *type_name, int level);

#define FD_HASH_FOOTPRINT (32UL)
#define FD_HASH_ALIGN (8UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
#define FD_PUBKEY_ALIGN FD_HASH_ALIGN

union __attribute__((aligned(FD_HASH_ALIGN))) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangable

  // Generic type specific accessors
  ulong ul  [ FD_HASH_FOOTPRINT / sizeof(ulong) ];
  uchar uc  [ FD_HASH_FOOTPRINT ];
};

typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_PROTOTYPES_BEGIN

static inline
void fd_hash_new(FD_FN_UNUSED fd_hash_t* self) {
}

static inline
int fd_hash_decode(fd_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  return fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), ctx);
}

static inline
void fd_hash_destroy(FD_FN_UNUSED fd_hash_t const * self, FD_FN_UNUSED fd_bincode_destroy_ctx_t * ctx) {
}

static inline
ulong fd_hash_size(FD_FN_UNUSED fd_hash_t const * self) {
  return 32;
}

static inline
int fd_hash_encode(fd_hash_t const * self, fd_bincode_encode_ctx_t * ctx) {
  return fd_bincode_bytes_encode(&self->hash[0], sizeof(self->hash), ctx);
}

static inline
void fd_hash_walk(FD_FN_UNUSED fd_hash_t* self, FD_FN_UNUSED fd_walk_fun_t fun, FD_FN_UNUSED const char *name, FD_FN_UNUSED int level) {
  fun(self->hash, name, 35, name, level);
}

#define fd_hash_check_zero(_x)           (!((_x)->ul[0] | (_x)->ul[1] | (_x)->ul[2] | (_x)->ul[3]))
#define fd_hash_set_zero(_x)             {((_x)->ul[0] = 0); ((_x)->ul[1] = 0); ((_x)->ul[2] = 0); ((_x)->ul[3] = 0);}

#define fd_pubkey_new(_x)                fd_hash_new(_x)
#define fd_pubkey_decode(_x,_y)          fd_hash_decode(_x, _y)
#define fd_pubkey_encode(_x, _y)         fd_hash_encode(_x, _y)
#define fd_pubkey_destroy(_x, _y)        fd_hash_destroy(_x, _y)
#define fd_pubkey_size(_x)               fd_hash_size(_x)
#define fd_pubkey_check_zero(_x)         fd_hash_check_zero(_x)
#define fd_pubkey_set_zero(_x)           fd_hash_set_zero(_x)
#define fd_pubkey_walk(_x, _y, _z, _l)   fd_hash_walk(_x, _y, _z, _l)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_types_custom */

