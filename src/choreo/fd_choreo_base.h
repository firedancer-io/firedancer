#ifndef HEADER_fd_src_choreo_fd_choreo_base_h
#define HEADER_fd_src_choreo_fd_choreo_base_h

/* Choreo consensus library:

  - votor: Alpenglow consensus.

  */

#include "../flamenco/fd_flamenco.h"

static const fd_pubkey_t pubkey_null  = { { 0 } };
static const fd_hash_t   hash_null    = { { 0 } };
static const fd_hash_t   hash_invalid = { .ul = { ULONG_MAX, ULONG_MAX, ULONG_MAX, ULONG_MAX } };

#endif /* HEADER_fd_src_choreo_fd_choreo_base_h */
