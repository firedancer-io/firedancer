#ifndef HEADER_fd_src_util_encoders_fd_bincode_h
#define HEADER_fd_src_util_encoders_fd_bincode_h

// TODO:
//    add _unchecked versions
//    return the underflow status verses errors?!

void fd_bincode_uint128_decode(uint128* self, void const** data, void const* dataend) {
  const uint128 *ptr = (const uint128 *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint64_decode(ulong* self, void const** data, void const* dataend) {
  const ulong *ptr = (const ulong *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_double_decode(double* self, void const** data, void const* dataend) {
  const double *ptr = (const double *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint32_decode(unsigned int* self, void const** data, void const* dataend) {
  const unsigned int *ptr = (const unsigned int *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint8_decode(unsigned char* self, void const** data, void const* dataend) {
  const unsigned char *ptr = (const unsigned char *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_bytes_decode(unsigned char* self, ulong len, void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + len) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  memcpy(self, ptr, len); // what is the FD way?
  *data = ptr + len;
}

unsigned char fd_bincode_option_decode(void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  unsigned char ret = *ptr;
  *data = ptr + 1;
  return ret;
}

#endif /* HEADER_fd_src_util_encoders_fd_bincode_h */
