#include "fd_secp256r1_private.h"

#define PCURVE_NAME       fd_secp256r1
#define PCURVE_SCALAR_SZ  32
#define PCURVE_SCALAR_T   fd_secp256r1_scalar_t
#define PCURVE_POINT_T    fd_secp256r1_point_t
#define PCURVE_SHA_NAME   fd_sha256
#define PCURVE_SHA_T      fd_sha256_t
#define PCURVE_SHA_SZ     FD_SHA256_HASH_SZ
#define PCURVE_SUCCESS    FD_SECP256R1_SUCCESS
#define PCURVE_FAILURE    FD_SECP256R1_FAILURE

#include "../pcurves/fd_pcurve_tmpl.c"
