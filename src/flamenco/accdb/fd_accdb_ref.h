#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h

/* fd_accdb_ref.h provides account database handle classes.

   - accdb_ref is an opaque handle to an account database cache entry.
   - accdb_ro (extends accdb_ref) represents a read-only handle.
   - accdb_rw (extends accdb_ro) represents a read-write handle.
   - accdb_spec is an account speculative read guard

   These APIs sit between the database layer (abstracts away backing
   stores and DB specifics) and the runtime layer (offer no runtime
   protections). */

#include "fd_accdb_base.h"
#include "../fd_flamenco_base.h"

/* fd_accdb_ref_t is an opaque account database handle. */

struct fd_accdb_ref {
  ulong meta_laddr;
  ulong user_data;
  ulong user_data2;
  uchar address[32];
  uint  accdb_type;  /* FD_ACCDB_TYPE_* */
  uchar ref_type;    /* FD_ACCDB_REF_* */
};
typedef struct fd_accdb_ref fd_accdb_ref_t;

/* fd_accdb_ro_t is a readonly account database handle. */

union fd_accdb_ro {
  fd_accdb_ref_t ref[1];
  struct {
    fd_account_meta_t const * meta;
  };
};
typedef union fd_accdb_ro fd_accdb_ro_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_ro_init_nodb creates a read-only account reference to an
   account that is not managed by an account database.  This is useful
   for local caching (e.g. cross-program invocations). */

static inline fd_accdb_ro_t *
fd_accdb_ro_init_nodb( fd_accdb_ro_t *           ro,
                       void const *              address,
                       fd_account_meta_t const * meta ) {
  ro->meta = meta;
  ro->ref->user_data  = 0UL;
  ro->ref->user_data2 = 0UL;
  memcpy( ro->ref->address, address, 32UL );
  ro->ref->accdb_type = FD_ACCDB_TYPE_NONE;
  ro->ref->ref_type   = FD_ACCDB_REF_RO;
  return ro;
}

/* fd_accdb_ro_init_empty creates a read-only account reference to a
   non-existent account. */

extern fd_account_meta_t const fd_accdb_meta_empty;

static inline fd_accdb_ro_t *
fd_accdb_ro_init_empty( fd_accdb_ro_t * ro,
                        void const *    address ) {
  ro->meta = &fd_accdb_meta_empty;
  ro->ref->user_data  = 0UL;
  ro->ref->user_data2 = 0UL;
  memcpy( ro->ref->address, address, 32UL );
  ro->ref->accdb_type = FD_ACCDB_TYPE_NONE;
  ro->ref->ref_type   = FD_ACCDB_REF_RO;
  return ro;
}

static inline void const *
fd_accdb_ref_address( fd_accdb_ro_t const * ro ) {
  return ro->ref->address;
}

static inline void const *
fd_accdb_ref_data_const( fd_accdb_ro_t const * ro ) {
  return (void *)( ro->meta+1 );
}

static inline ulong
fd_accdb_ref_data_sz( fd_accdb_ro_t const * ro ) {
  return ro->meta->dlen;
}

static inline ulong
fd_accdb_ref_lamports( fd_accdb_ro_t const * ro ) {
  return ro->meta->lamports;
}

static inline void const *
fd_accdb_ref_owner( fd_accdb_ro_t const * ro ) {
  return ro->meta->owner;
}

static inline uint
fd_accdb_ref_exec_bit( fd_accdb_ro_t const * ro ) {
  return !!ro->meta->executable;
}

static inline ulong
fd_accdb_ref_slot( fd_accdb_ro_t const * ro ) {
  return ro->meta->slot;
}

// void
// fd_accdb_ref_lthash( fd_accdb_ro_t const * ro,
//                      void *                lthash );

FD_PROTOTYPES_END

/* fd_accdb_rw_t is a writable database handle.  Typically, writable
   handles are only available for invisible/in-prepartion records.
   In rare cases (e.g. when booting up), components may directly write
   to globally visible writable records. */

union fd_accdb_rw {
  fd_accdb_ref_t ref[1];
  fd_accdb_ro_t  ro [1];
  struct {
    fd_account_meta_t * meta;
  };
};
typedef union fd_accdb_rw fd_accdb_rw_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_rw_init_nodb creates a writable account reference to an
   account that is not managed by an account database.  This is useful
   for local caching (e.g. cross-program invocations). */

static inline fd_accdb_rw_t *
fd_accdb_rw_init_nodb( fd_accdb_rw_t *           rw,
                       void const *              address,
                       fd_account_meta_t const * meta,
                       ulong                     data_max ) {
  rw->meta = (fd_account_meta_t *)meta;
  rw->ref->user_data = data_max;
  memcpy( rw->ref->address, address, 32UL );
  rw->ref->accdb_type = FD_ACCDB_TYPE_NONE;
  return rw;
}

// void
// fd_accdb_ref_clear( fd_accdb_rw_t * rw );

static inline void *
fd_accdb_ref_data( fd_accdb_rw_t * rw ) {
  return (void *)( rw->meta+1 );
}

static inline void
fd_accdb_ref_lamports_set( fd_accdb_rw_t * rw,
                           ulong           lamports ) {
  rw->meta->lamports = lamports;
}

static inline void
fd_accdb_ref_owner_set( fd_accdb_rw_t * rw,
                        void const *    owner ) {
  memcpy( rw->meta->owner, owner, 32UL );
}

static inline void
fd_accdb_ref_exec_bit_set( fd_accdb_rw_t * rw,
                           uint            exec_bit ) {
  rw->meta->executable = !!exec_bit;
}

static inline void
fd_accdb_ref_slot_set( fd_accdb_rw_t * rw,
                       ulong           slot ) {
  rw->meta->slot = slot;
}

FD_PROTOTYPES_END

FD_STATIC_ASSERT( sizeof(fd_accdb_ref_t)==sizeof(fd_accdb_ro_t), layout );
FD_STATIC_ASSERT( sizeof(fd_accdb_ref_t)==sizeof(fd_accdb_rw_t), layout );

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h */
