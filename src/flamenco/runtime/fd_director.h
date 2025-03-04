#ifndef HEADER_fd_src_flamenco_runtime_fd_director_h
#define HEADER_fd_src_flamenco_runtime_fd_director_h

#include "../../funk/fd_funk.h"
#include "../fd_flamenco_base.h"

/* Director is responsible for managing where an account is stored. An account can either be:
   - In the hot store (Funk, the in-memory transactional database)
   - In the cold store (a Groove volume, could be backed by NVME or SSD)
   
   Director will move accounts between the hot and cold stores using a simple LRU scheme.
*/

#define FD_DIRECTOR_ACCOUNT_SUCCESS (0)
#define FD_DIRECTOR_ACCOUNT_MISSING (1)

struct fd_director;
typedef struct fd_director fd_director_t;

int
fd_director_load_account_into_funk( fd_director_t      * director,
                                    fd_funk_txn_t const * txn,
                                    fd_pubkey_t   const * pubkey );

#endif /* HEADER_fd_src_flamenco_runtime_fd_director_h */
