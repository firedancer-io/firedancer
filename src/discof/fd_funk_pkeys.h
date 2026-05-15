#ifndef HEADER_fd_src_discof_fd_funk_pkeys_h
#define HEADER_fd_src_discof_fd_funk_pkeys_h

#include "../util/fd_util_base.h"
#include "../util/wksp/fd_wksp.h"

FD_PROTOTYPES_BEGIN

/* fd_funk_pkey_setup installs a memory protection key on the Funk
   workspace and returns the pkey.  Returns -1 if pkeys are unavailable
   for this process or platform. */

int
fd_funk_pkey_setup( fd_wksp_t * funk_wksp );

void
fd_funk_pkey_protect( int funk_pkey );

void
fd_funk_pkey_unprotect( int funk_pkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_fd_funk_pkeys_h */
