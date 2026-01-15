#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_base_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_base_h

#include "../../util/fd_util_base.h"

struct fd_accdb_user;
typedef struct fd_accdb_user fd_accdb_user_t;

struct fd_accdb_ro_pipe;
typedef struct fd_accdb_ro_pipe fd_accdb_ro_pipe_t;

#define FD_ACCDB_TYPE_INVAL (0U) /* sentinel */
#define FD_ACCDB_TYPE_V0   (80U) /* minimal single chain */
#define FD_ACCDB_TYPE_V1    (1U) /* funk */
#define FD_ACCDB_TYPE_V2    (2U) /* read-only vinyl + read-write funk */
#define FD_ACCDB_TYPE_NONE (79U) /* marks an account as not managed by accdb */

#define FD_ACCDB_REF_RO 1
#define FD_ACCDB_REF_RW 2

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_base_h */
