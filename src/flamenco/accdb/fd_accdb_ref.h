#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h

/* fd_accdb_ref.h provides account database handle classes.

   - accdb_ref is an opaque handle to an account database cache entry.
   - accdb_ro (extends accdb_ref) represents a read-only handle.
   - accdb_rw (extends accdb_ro) represents a read-write handle. */

#include "fd_accdb_base.h"

struct fd_accdb_ref {
  ulong meta_laddr;
};
typedef struct fd_accdb_ref fd_accdb_ref_t;

FD_PROTOTYPES_BEGIN

void
fd_accdb_ref_delete( fd_accdb_ref_t * ref );

FD_PROTOTYPES_END

union fd_accdb_ro {
  fd_accdb_ref_t ref[1];
  struct {
    fd_accdb_meta_t const * meta;
  };
};
typedef union fd_accdb_ro fd_accdb_ro_t;

FD_PROTOTYPES_BEGIN

void const *
fd_accdb_ref_data_const( fd_accdb_ro_t const * ro );

ulong
fd_accdb_ref_data_sz( fd_accdb_ro_t const * ro );

ulong
fd_accdb_ref_lamports( fd_accdb_ro_t const * ro );

void const *
fd_accdb_ref_owner( fd_accdb_ro_t const * ro );

uint
fd_accdb_ref_exec_bit( fd_accdb_ro_t const * ro );

ulong
fd_accdb_ref_slot( fd_accdb_ro_t const * ro );

void
fd_accdb_ref_lthash( fd_accdb_ro_t const * ro,
                     void *                lthash );

FD_PROTOTYPES_END

union fd_accdb_rw {
  fd_accdb_ref_t ref[1];
  fd_accdb_ro_t  ro [1];
};
typedef union fd_accdb_rw fd_accdb_rw_t;

FD_PROTOTYPES_BEGIN

void
fd_accdb_ref_clear( fd_accdb_rw_t * rw );

void
fd_accdb_ref_data_max( fd_accdb_rw_t * rw );

void
fd_accdb_ref_data_set( fd_accdb_rw_t * rw,
                       void const *    data,
                       ulong           data_sz );

void *
fd_accdb_ref_data( fd_accdb_rw_t * rw );

void
fd_accdb_ref_data_sz_set( fd_accdb_rw_t * rw,
                          ulong           data_sz );

void
fd_accdb_ref_lamports_set( fd_accdb_rw_t * rw,
                           ulong           lamports );

void
fd_accdb_ref_owner_set( fd_accdb_rw_t * rw,
                        void const *    owner );

void
fd_accdb_ref_exec_bit_set( fd_accdb_rw_t * rw,
                           uint            exec_bit );

void
fd_accdb_ref_slot_set( fd_accdb_rw_t * rw,
                       ulong           slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h */
