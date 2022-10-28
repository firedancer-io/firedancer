#include "fd_ed25519_private.h"

#if FD_ED25519_FE_IMPL==0
#include "ref/fd_ed25519_ge.c"
#elif FD_ED25519_FE_IMPL==1
#include "avx/fd_ed25519_ge.c"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

