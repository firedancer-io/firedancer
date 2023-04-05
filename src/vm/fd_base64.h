#ifndef HEADER_fd_src_vm_fd_base64_h
#define HEADER_fd_src_vm_fd_base64_h

#include "../util/fd_util.h"

FD_PROTOTYPES_BEGIN

char * fd_base64_encode(uchar * data, ulong data_len, char * out, ulong out_len, ulong * out_len_used);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_base64_h */
