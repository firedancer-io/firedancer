#include "fd_types.h"

void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}
void fd_hash_destroy(FD_FN_UNUSED fd_hash_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

ulong fd_hash_size(FD_FN_UNUSED fd_hash_t* self) {
  ulong size = 0;
  size += sizeof(char) * 32;
  return size;
}

void fd_hash_encode(fd_hash_t* self, void const** data) {
  fd_bincode_bytes_encode(&self->hash[0], sizeof(self->hash), data);
}
