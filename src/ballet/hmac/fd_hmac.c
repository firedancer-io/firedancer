#include "fd_hmac.h"

#include "../sha256/fd_sha256.h"
#include "../sha512/fd_sha512.h"

#define HASH_ALG      sha256
#define HASH_BLOCK_SZ FD_SHA256_BLOCK_SZ
#define HASH_SZ       FD_SHA256_HASH_SZ
#include "fd_hmac_tmpl.c"

#define HASH_ALG      sha384
#define HASH_BLOCK_SZ FD_SHA384_BLOCK_SZ
#define HASH_SZ       FD_SHA384_HASH_SZ
#include "fd_hmac_tmpl.c"

#define HASH_ALG      sha512
#define HASH_BLOCK_SZ FD_SHA512_BLOCK_SZ
#define HASH_SZ       FD_SHA512_HASH_SZ
#include "fd_hmac_tmpl.c"
