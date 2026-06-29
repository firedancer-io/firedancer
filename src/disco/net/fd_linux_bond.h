#ifndef HEADER_fd_src_disco_net_fd_linux_bond_h
#define HEADER_fd_src_disco_net_fd_linux_bond_h

/* fd_linux_bond.h provides APIs for managing bonded network interfaces
   on Linux. */

#include "../../util/fd_util.h"

FD_PROTOTYPES_BEGIN

/* fd_bonding_is_master returns 1 if the given network device is a bond
   master.  Returns 0 if not.  Terminates with FD_LOG_ERR if device was
   not found or another error occurred. */

int
fd_bonding_is_master( char const * device );

/* fd_bonding_slave_cnt returns the number of slave devices of the given
   bond master.  Terminates with FD_LOG_ERR if device was not found, is
   not a bond master, or another error occurred. */

uint
fd_bonding_slave_cnt( char const * device );

/* fd_bonding_slave_iter provides an API to iterate over the slave
   devices of a network bond. */

struct fd_bonding_slave_iter {
  char   line[ 4096 ];
  char * saveptr;
  char * tok;
};

typedef struct fd_bonding_slave_iter fd_bonding_slave_iter_t;

fd_bonding_slave_iter_t *
fd_bonding_slave_iter_init(
    fd_bonding_slave_iter_t * iter,
    char const * device
);

int
fd_bonding_slave_iter_done( fd_bonding_slave_iter_t const * iter );

void
fd_bonding_slave_iter_next(
    fd_bonding_slave_iter_t * iter
);

char const *
fd_bonding_slave_iter_ele(
    fd_bonding_slave_iter_t const * iter
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_linux_bond_h */
