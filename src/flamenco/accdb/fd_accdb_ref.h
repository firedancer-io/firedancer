#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h

/* fd_accdb_ref.h provides account database handle classes.

   - accdb_ref is an opaque handle to an account database cache entry.
   - accdb_ro (extends accdb_ref) represents a read-only handle.
   - accdb_rw (extends accdb_ro) represents a read-write handle.

   - accdb_guardr is a read-only account lock guard
   - accdb_guardw is an exclusive account lock guard
   - accdb_spec is an account speculative read guard

   These APIs sit between the database layer (abstracts away backing
   stores and DB specifics) and the runtime layer (offer no runtime
   protections). */

#include "../fd_flamenco_base.h"
#include "../../funk/fd_funk_rec.h"
#include "../../funk/fd_funk_val.h"

/* fd_accdb_ref_t is an opaque account database handle. */

struct fd_accdb_ref {
  ulong rec_laddr;
  ulong meta_laddr;
  uchar address[32];  /* only for vinyl requests */
};
typedef struct fd_accdb_ref fd_accdb_ref_t;

/* fd_accdb_ro_t is a readonly account database handle. */

union fd_accdb_ro {
  fd_accdb_ref_t ref[1];
  struct {
    fd_funk_rec_t const *     rec;
    fd_account_meta_t const * meta;
  };
};
typedef union fd_accdb_ro fd_accdb_ro_t;

FD_PROTOTYPES_BEGIN

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
    fd_funk_rec_t *     rec;
    fd_account_meta_t * meta;
    uint                published : 1;
  };
};
typedef union fd_accdb_rw fd_accdb_rw_t;

FD_PROTOTYPES_BEGIN

// void
// fd_accdb_ref_clear( fd_accdb_rw_t * rw );

static inline ulong
fd_accdb_ref_data_max( fd_accdb_rw_t * rw ) {
  ulong data_max;
  if( FD_UNLIKELY( __builtin_usubl_overflow( rw->rec->val_max, sizeof(fd_account_meta_t), &data_max ) ) ) {
    FD_LOG_CRIT(( "invalid rec->val_max %lu for account at rec %p", (ulong)rw->rec->val_max, (void *)rw->rec ));
  }
  return data_max;
}

static inline void *
fd_accdb_ref_data( fd_accdb_rw_t * rw ) {
  return (void *)( rw->meta+1 );
}

static inline void
fd_accdb_ref_data_set( fd_accdb_rw_t * rw,
                       void const *    data,
                       ulong           data_sz ) {
  ulong data_max = fd_accdb_ref_data_max( rw );
  if( FD_UNLIKELY( data_sz>data_max ) ) {
    FD_LOG_CRIT(( "attempted to write %lu bytes into a rec %p with only %lu bytes of data space",
                  data_sz, (void *)rw->rec, data_max ));
  }
  fd_memcpy( fd_accdb_ref_data( rw ), data, data_sz );
  rw->meta->dlen  = (uint)data_sz;
  rw->rec->val_sz = (uint)( sizeof(fd_account_meta_t)+data_sz ) & FD_FUNK_REC_VAL_MAX;
}

FD_FN_UNUSED static void
fd_accdb_ref_data_sz_set( fd_accdb_rw_t * rw,
                          ulong           data_sz ) {
  ulong prev_sz = rw->meta->dlen;
  if( data_sz>prev_sz ) {
    /* Increasing size, zero out tail */
    ulong data_max = fd_accdb_ref_data_max( rw );
    if( FD_UNLIKELY( data_sz>data_max ) ) {
      FD_LOG_CRIT(( "attempted to write %lu bytes into a rec %p with only %lu bytes of data space",
                    data_sz, (void *)rw->rec, data_max ));
    }
    void * tail = (uchar *)fd_accdb_ref_data( rw ) + prev_sz;
    fd_memset( tail, 0, data_sz-prev_sz );
  }
  rw->meta->dlen  = (uint)data_sz;
  rw->rec->val_sz = (uint)( sizeof(fd_account_meta_t)+data_sz ) & FD_FUNK_REC_VAL_MAX;
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

/* fd_accdb_guardr_t tracks a rwlock being held as read-only.
   Destroying this guard object detaches the caller's thread from the
   rwlock. */

struct fd_accbd_guardr {
  fd_rwlock_t * rwlock;
};

typedef struct fd_accdb_guardr fd_accdb_guardr_t;

/* fd_accdb_guardw_t tracks an rwlock being held exclusively.
   Destroying this guard object detaches the caller's thread from the
   lock. */

struct fd_accdb_guardw {
  fd_rwlock_t * rwlock;
};

typedef struct fd_accdb_guardw fd_accdb_guardw_t;

/* fd_accdb_spec_t tracks a speculative access to a shared resource.
   Destroying this guard object marks the end of a speculative access. */

struct fd_accdb_spec {
  fd_funk_rec_key_t * keyp;       /* shared key */
  fd_funk_rec_key_t   key;        /* expected key */
};

typedef struct fd_accdb_spec fd_accdb_spec_t;

/* fd_accdb_spec_test returns 1 if the shared resources has not been
   invalidated up until now.  Returns 0 if the speculative access may
   have possibly seen a conflict (e.g. a torn read, a use-after-free,
   etc). */

static inline int
fd_accdb_spec_test( fd_accdb_spec_t const * spec ) {
  fd_funk_rec_key_t key_found = FD_VOLATILE_CONST( *spec->keyp );
  return !!fd_funk_rec_key_eq( &key_found, &spec->key );
}

/* fd_accdb_spec_drop marks the end of a speculative access. */

static inline void
fd_accdb_spec_drop( fd_accdb_spec_t * spec ) {
  /* Speculative accesses do not need central synchronization, so no
     need to inform the holder of the resource of this drop. */
  (void)spec;
}

/* fd_accdb_peek_t is an ephemeral lock-free read-only pointer to an
   account in database cache. */

struct fd_accdb_peek {
  fd_accdb_ro_t   acc[1];
  fd_accdb_spec_t spec[1];
};

typedef struct fd_accdb_peek fd_accdb_peek_t;

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_ref_h */
