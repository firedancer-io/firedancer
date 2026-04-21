#ifndef HEADER_fd_src_flamenco_progcache_fd_prog_load_h
#define HEADER_fd_src_flamenco_progcache_fd_prog_load_h

/* fd_prog_load.h provides high-level APIs for loading Solana programs
   from the account database. */

#include "../accdb/fd_accdb.h"
#include "../types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

/* fd_prog_info derives executable info from a program data account.
   progdata_ro is a handle to the program data account (ownership stays
   with caller). program_owner is the owner pubkey of the program account
   (NOT the programdata account). This is used to determine the loader type.
   Populates *out and returns out on success.
   On failure, logs warning and returns NULL. */

struct fd_prog_info {
  /* Byte range within the account's data yielding ELF file */
  ulong elf_off;
  ulong elf_sz;

  /* deploy_slot meaning depends on program loader version:
     - v1, v2: always zero
     - v3: slot at which this program was deployed at */
  ulong deploy_slot;
};

typedef struct fd_prog_info fd_prog_info_t;

fd_prog_info_t *
fd_prog_info( fd_prog_info_t    *      out,
              fd_accdb_entry_t const * entry,
              fd_pubkey_t const *      program_owner );

/* fd_prog_versions derives sBPF versions from the current feature set. */

struct fd_prog_versions {
  uint min_sbpf_version;
  uint max_sbpf_version;
};
typedef struct fd_prog_versions fd_prog_versions_t;

FD_FN_PURE fd_prog_versions_t
fd_prog_versions( fd_features_t const * features,
                  ulong                 slot );

FD_PROTOTYPES_END

struct fd_prog_load_env {
  fd_features_t const * features;

  ulong epoch;        /* current epoch */
  ulong epoch_slot0;  /* slot0 of current epoch */
};

typedef struct fd_prog_load_env fd_prog_load_env_t;

FD_PROTOTYPES_BEGIN

fd_prog_load_env_t *
fd_prog_load_env_from_bank( fd_prog_load_env_t * env,
                            fd_bank_t const *    bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_prog_load_h */
