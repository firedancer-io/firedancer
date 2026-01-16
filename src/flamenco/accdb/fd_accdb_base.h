#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_base_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_base_h

#include "../../util/fd_util_base.h"

struct fd_accdb_user;
typedef struct fd_accdb_user fd_accdb_user_t;

#define FD_ACCDB_TYPE_NONE  (0U) /* marks an account as not managed by accdb */
#define FD_ACCDB_TYPE_V0   (80U) /* minimal single chain */
#define FD_ACCDB_TYPE_V1    (1U) /* funk */
#define FD_ACCDB_TYPE_V2    (2U) /* read-only vinyl + read-write funk */

#define FD_ACCDB_REF_INVAL 0 /* not a valid reference */
#define FD_ACCDB_REF_RO    1 /* read only */
#define FD_ACCDB_REF_RW    2 /* read write */

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_base_h */
