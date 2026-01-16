#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v0_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v0_h

/* fd_accdb_impl_v0.h is a tiny minimal accdb implementation.  Does not
   support fork awareness.  Mostly useful for tests.  Suppports basic
   multi-threaded accesses via a global spinlock. */

#include "fd_accdb_user.h"
#include "../runtime/fd_runtime_const.h"

struct fd_accdb_v0_rec {
  uint reader_cnt : 31;
  uint writer_cnt :  1;

  fd_pubkey_t       key;
  fd_account_meta_t meta;
  uchar             data[ FD_RUNTIME_ACC_SZ_MAX ];
};

typedef struct fd_accdb_v0_rec fd_accdb_v0_rec_t;

struct fd_accdb_v0 {
  ulong magic;
# define FD_ACCDB_V0_MAGIC 0xc75c2e65fdfcc880UL

  fd_rwlock_t lock;

  ulong             rec_cnt;
  ulong             rec_max;
  fd_accdb_v0_rec_t rec[];
};

typedef struct fd_accdb_v0 fd_accdb_v0_t;

struct fd_accdb_user_v0 {
  fd_accdb_user_base_t base;

  fd_accdb_v0_t * v0;
};

typedef struct fd_accdb_user_v0 fd_accdb_user_v0_t;

FD_PROTOTYPES_BEGIN

extern fd_accdb_user_vt_t const fd_accdb_user_v0_vt;

FD_FN_CONST ulong
fd_accdb_v0_align( void );

ulong
fd_accdb_v0_footprint( ulong rec_cnt );

void *
fd_accdb_v0_new( void * shmem,
                 ulong  rec_cnt );

fd_accdb_v0_t *
fd_accdb_v0_join( void * v0 );

void *
fd_accdb_v0_leave( fd_accdb_v0_t * v0 );

void *
fd_accdb_v0_delete( void * mem );

fd_accdb_user_t *
fd_accdb_user_v0_init( fd_accdb_user_t * ljoin,
                       fd_accdb_v0_t *   v0 );

void
fd_accdb_user_v0_fini( fd_accdb_user_t * accdb );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_impl_v0_h */
