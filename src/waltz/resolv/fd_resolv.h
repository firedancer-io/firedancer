#ifndef HEADER_fd_src_waltz_resolv_fd_resolv_h
#define HEADER_fd_src_waltz_resolv_fd_resolv_h

#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

__attribute__((__visibility__("hidden"))) int
fd_dn_expand( uchar const * base,
              uchar const * end,
              uchar const * src,
              char *        dest,
              int           space );

__attribute__((__visibility__("hidden"))) int
fd_res_mkquery( int           op,
                char const *  dname,
                int           class,
                int           type,
                uchar *       buf,
                int           buflen );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_resolv_fd_resolv_h */
