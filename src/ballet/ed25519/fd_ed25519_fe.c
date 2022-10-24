#include "fd_ed25519_private.h"

#if FD_ED25519_FE_IMPL==0 /* reference */
#include "ref/fd_ed25519_fe.c"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

