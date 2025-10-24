#ifndef HEADER_snp_private_h
#define HEADER_snp_private_h

/* snp_private.h contains private functions, used e.g. in tests. */

#include "fd_snp_v1.h"

FD_PROTOTYPES_BEGIN

int
fd_snp_conn_delete( fd_snp_t *      snp,
                    fd_snp_conn_t * conn );

FD_PROTOTYPES_END

#endif /* HEADER_snp_private_h */
