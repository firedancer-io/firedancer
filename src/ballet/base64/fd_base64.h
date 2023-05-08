#ifndef HEADER_fd_src_ballet_base64_fd_base64_h
#define HEADER_fd_src_ballet_base64_fd_base64_h

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

char *
fd_base64_encode( uchar const * data,
                  ulong         data_sz,
                  char *        out,
                  ulong         out_sz,
                  ulong *       out_sz_used );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_base64_fd_base64_h */
