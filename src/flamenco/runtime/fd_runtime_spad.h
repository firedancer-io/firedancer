#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_spad_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_spad_h

#include "../../util/log/fd_log.h"
#include "../../util/spad/fd_spad.h"
#include "../../util/valloc/fd_valloc.h"

FD_PROTOTYPES_BEGIN

/* fd_valloc virtual function table for the runtime spad */
extern const fd_valloc_vtable_t fd_runtime_spad_vtable;

/* Returns an fd_valloc handle to the fd_spad join.
   Valid for lifetime of the current spad frame. Handle invalid if spad
   frame changes or spad detaches. */
FD_FN_PURE static inline fd_valloc_t
fd_runtime_spad_virtual( fd_spad_t * spad ) {
  fd_valloc_t valloc = { spad, &fd_runtime_spad_vtable };
  return valloc;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_spad_h */
