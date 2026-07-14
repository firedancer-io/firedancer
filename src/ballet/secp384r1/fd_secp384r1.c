#include "fd_secp384r1_private.h"

#define PCURVE_NAME       fd_secp384r1
#define PCURVE_SCALAR_SZ  48
#define PCURVE_SCALAR_T   fd_secp384r1_scalar_t
#define PCURVE_POINT_T    fd_secp384r1_point_t
#define PCURVE_SHA_NAME   fd_sha384
#define PCURVE_SHA_T      fd_sha512_t
#define PCURVE_SHA_SZ     FD_SHA384_HASH_SZ
#define PCURVE_SUCCESS    FD_SECP384R1_SUCCESS
#define PCURVE_FAILURE    FD_SECP384R1_FAILURE

#include "../pcurves/fd_pcurve_tmpl.c"
