#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_base_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_base_h

#include "../../util/fd_util_base.h"

#define FD_ACCDB_SUCCESS        ( 0)
#define FD_ACCDB_ERR_KEY        (-1) /* key not found */
#define FD_ACCDB_ERR_BUFSZ      (-2) /* buffer too small */
#define FD_ACCDB_ERR_MALLOC     (-3) /* malloc failed */
#define FD_ACCDB_ERR_DISK_FULL  (-4) /* database full */
#define FD_ACCDB_ERR_CACHE_FULL (-5) /* in-memory cache full */
#define FD_ACCDB_ERR_KEY_RACE   (-6) /* failed due to concurrent key-level operation */

struct fd_accdb_meta {
  uchar owner[ 32 ];
  ulong lamports;
  ulong slot;
  uint  data_sz;
  uint  executable : 1;

  uchar * acct_buf;
  ulong   acct_stride;
};

typedef struct fd_accdb_meta fd_accdb_meta_t;

/* Forward declarations */

struct fd_accdb_client;
typedef struct fd_accdb_client fd_accdb_client_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST char const *
fd_accdb_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_base_h */
