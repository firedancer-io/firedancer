#ifndef HEADER_fd_src_flamenco_fd_progcache_fd_prog_load_h
#define HEADER_fd_src_flamenco_fd_progcache_fd_prog_load_h

/* fd_prog_load.h provides high-level APIs for loading Solana programs
   from the account database. */

#include "../../funk/fd_funk_rec.h"
#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

/* fd_prog_load_elf loads a reference to program data from a funk-backed
   account database.  *prog_addr gives the account address of the
   program account (NOT the program data account).  Returns a pointer to
   the first byte of the ELF binary on success.  *out_sz is set to the
   size of the program data account.  *out_xid is set to the the txn
   XID the program data account was written to.  On failure, returns
   NULL.  Reasons for failure include: program account not found,
   program not deployed, program data account not found, etc */

uchar const *
fd_prog_load_elf( fd_funk_t const *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  void const *              prog_addr,
                  ulong *                   out_sz,
                  fd_funk_txn_xid_t *       out_xid );
/* FIXME provide an API to detect data race */
/* FIXME clarify edge case where program account and program data
         account were modified in different funk txns */

/* fd_prog_versions derives sBPF versions from the current feature set. */

struct fd_prog_versions {
  uint min_sbpf_version;
  uint max_sbpf_version;
};
typedef struct fd_prog_versions fd_prog_versions_t;

fd_prog_versions_t
fd_prog_versions( fd_features_t const * features,
                  ulong                 slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_progcache_fd_prog_load_h */
