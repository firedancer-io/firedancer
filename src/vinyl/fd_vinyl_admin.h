#ifndef HEADER_fd_src_vinyl_fd_vinyl_admin_h
#define HEADER_fd_src_vinyl_fd_vinyl_admin_h

#include "../flamenco/fd_rwlock.h"
#include "../util/log/fd_log.h"

FD_PROTOTYPES_BEGIN

#define FD_VINYL_ADMIN_MAGIC (0XF17EDA2C7E412AD8) /* FIREDANCER VINYL ADMIN */

/* TODO documentation
*/
#define FD_VINYL_ADMIN_BSTREAM_SEQ_CNT_MAX  (8UL)

#define FD_VINYL_ADMIN_ALIGN                (8UL)
#define FD_VINYL_ADMIN_FOOTPRINT            (104UL)

#define FD_VINYL_ADMIN_STATUS_INIT_PENDING  (0UL)
#define FD_VINYL_ADMIN_STATUS_INIT_DONE     (1UL)
#define FD_VINYL_ADMIN_STATUS_REWIND        (2UL)

struct fd_vinyl_admin {
  ulong       magic; /* ==FD_VINYL_ADMIN_MAGIC */

  /* rwlock protected */
  struct {
    ulong     past;
    ulong     present;
  } bstream_seq;
  ulong       status;
  fd_rwlock_t lock;

  /* unprotected */
  ulong       wr_seq[FD_VINYL_ADMIN_BSTREAM_SEQ_CNT_MAX];
};
typedef struct fd_vinyl_admin fd_vinyl_admin_t;

/* TODO
*/

static inline ulong
fd_vinyl_admin_align( void ) {
  return FD_VINYL_ADMIN_ALIGN;
}

/* TODO
*/

static inline ulong
fd_vinyl_admin_footprint( void ){
  FD_STATIC_ASSERT(sizeof(fd_vinyl_admin_t)==FD_VINYL_ADMIN_FOOTPRINT, "incorrect vinyl admin footprint" );
  return FD_VINYL_ADMIN_FOOTPRINT;
}

/* fd_vinyl_admin_init initializes ... TODO */

static inline void *
fd_vinyl_admin_new( void * mem ) {
  fd_vinyl_admin_t * admin = (fd_vinyl_admin_t *)mem;

  memset( admin, 0UL, FD_VINYL_ADMIN_FOOTPRINT );

  admin->magic = FD_VINYL_ADMIN_MAGIC;

  fd_rwlock_new( &admin->lock );

  return (void *)admin;
}

/* fd_banks_join ... TODO */

static inline fd_vinyl_admin_t *
fd_vinyl_admin_join( void * _admin ) {
  fd_vinyl_admin_t * admin = (fd_vinyl_admin_t *)_admin;
  if( FD_UNLIKELY( admin->magic!=FD_VINYL_ADMIN_MAGIC ) ) return NULL;
  return admin;
}

static inline void *
fd_vinyl_admin_leave( fd_vinyl_admin_t * _admin ) {
  return (void *)_admin;
}

static inline void *
fd_vinyl_admin_delete( void * _admin ) {
  return (void *)_admin;
}

static inline ulong
fd_vinyl_admin_ulong_query( ulong const * _field ) {
  FD_COMPILER_MFENCE();
  ulong field = FD_VOLATILE_CONST( *_field );
  FD_COMPILER_MFENCE();
  return field;
}

static inline void
fd_vinyl_admin_ulong_update( ulong * _field,
                             ulong   value ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *_field ) = value;
  FD_COMPILER_MFENCE();
}

static inline void
fd_vinyl_admin_wait_for_status( fd_vinyl_admin_t * admin,
                                ulong              status, /* FD_VINYL_ADMIN_STATUS_... */
                                long               sleep_ns ) {
  FD_TEST( admin!=NULL );
  for(;;) {
    fd_rwlock_read( &admin->lock );
    int found = fd_vinyl_admin_ulong_query( &admin->status )==status;
    fd_rwlock_unread( &admin->lock );
    if( FD_LIKELY( found ) ) break;

    fd_log_sleep( sleep_ns );
    FD_SPIN_PAUSE();
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_fd_vinyl_admin_h */
