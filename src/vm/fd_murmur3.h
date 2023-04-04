#ifndef HEADER_fd_src_vm_fd_murmur3_h
#define HEADER_fd_src_vm_fd_murmur3_h

#include "../util/fd_util.h"

FD_PROTOTYPES_BEGIN

uint fd_murmur3_hash_cstr_to_uint(char const * key, ulong key_len, uint seed);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_murmur3_h */
