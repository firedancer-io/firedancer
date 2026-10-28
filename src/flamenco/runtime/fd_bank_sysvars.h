#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_sysvars_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_sysvars_h

/* fd_bank_sysvars_t is a tile's local copy of the sysvars of one bank,
   read from the account database when the tile asks for a bank it does
   not hold.  A bank's sysvar accounts change while its block is
   prepared and again when it is frozen, so a bank should be queried
   only between those points or after freezing, and refreshed if its
   sysvars may have changed since it was last read. */

#include "fd_bank.h"

struct fd_bank_sysvars {
  fd_accdb_t *      accdb;
  uchar *           nocache_buf; /* non-NULL if accdb is a readonly join */
  ulong             bank_seq;    /* bank whose sysvars cache holds, 0 if none */
  fd_sysvar_cache_t cache[1];
};
typedef struct fd_bank_sysvars fd_bank_sysvars_t;

FD_PROTOTYPES_BEGIN

/* fd_bank_sysvars_init initializes sysvars to hold no bank.  If accdb
   is a readonly join, nocache_buf is an FD_RUNTIME_ACC_SZ_MAX byte
   buffer that accounts are read through; otherwise it is NULL. */

fd_bank_sysvars_t *
fd_bank_sysvars_init( fd_bank_sysvars_t * sysvars,
                      fd_accdb_t *        accdb,
                      uchar *             nocache_buf );

/* fd_bank_sysvars_query returns the sysvars of bank, reading them from
   accdb unless sysvars already holds them. */

fd_sysvar_cache_t *
fd_bank_sysvars_query( fd_bank_sysvars_t * sysvars,
                       fd_bank_t const *   bank );

/* fd_bank_sysvars_refresh reads the sysvars of bank from accdb and
   returns them. */

fd_sysvar_cache_t *
fd_bank_sysvars_refresh( fd_bank_sysvars_t * sysvars,
                         fd_bank_t const *   bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_sysvars_h */
