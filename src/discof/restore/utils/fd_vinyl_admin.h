#ifndef HEADER_fd_src_discof_restore_utils_fd_vinyl_admin_h
#define HEADER_fd_src_discof_restore_utils_fd_vinyl_admin_h

#include "../../../flamenco/fd_rwlock.h"

#define FD_VINYL_ADMIN_MAGIC (0XF17EDA2C7E412AD8) /* FIREDANCER VINYL ADMIN */

/* Vinyl admin synchronization object. */
#define FD_VINYL_ADMIN_WR_SEQ_CNT_MAX       (8UL)

#define FD_VINYL_ADMIN_STATUS_INIT_PENDING  (0UL)
#define FD_VINYL_ADMIN_STATUS_INIT_DONE     (1UL)
#define FD_VINYL_ADMIN_STATUS_UPDATING      (2UL)
#define FD_VINYL_ADMIN_STATUS_SNAPSHOT_FULL (3UL)
#define FD_VINYL_ADMIN_STATUS_SNAPSHOT_INCR (4UL)
#define FD_VINYL_ADMIN_STATUS_ERROR         (ULONG_MAX)

struct fd_vinyl_admin {
  ulong       magic; /* ==FD_VINYL_ADMIN_MAGIC */

  ulong       status;

  struct {
    ulong     past;
    ulong     present;
  } bstream_seq;

  ulong       wr_seq[FD_VINYL_ADMIN_WR_SEQ_CNT_MAX];
  ulong       wr_cnt;

  fd_rwlock_t lock;
};
typedef struct fd_vinyl_admin fd_vinyl_admin_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_admin_{align, footprint} return align and footprint */

ulong
fd_vinyl_admin_align( void );

ulong
fd_vinyl_admin_footprint( void );

/* fd_vinyl_admin_new initializes a new vinyl admin object.  It returns
   a void pointer to the base of the fd_vinyl_admin_t in memory.  On
   return, it does not retain ownership of the memory. */

void *
fd_vinyl_admin_new( void * mem );

/* fd_vinyl_admin_join return a fd_vinyl_admin_t pointer on success,
   NULL otherwise.  A condition for failure is e.g. an incorrect
   magic value (meaning the memory region does not correspond to a
   properly initialized vinyl admin object).  On return, it does not
   retain ownership of the memory.*/

fd_vinyl_admin_t *
fd_vinyl_admin_join( void * _admin );

/* fd_vinyl_admin_leave leaves the vinyl admin object, returning a void
   pointer to the memory region. */

void *
fd_vinyl_admin_leave( fd_vinyl_admin_t * _admin );

/* fd_vinyl_admin_delete leaves the memory region, returning a void
   pointer to the memory region. */

void *
fd_vinyl_admin_delete( void * _admin );

/* fd_vinyl_admin_query does a volatile read of the vinyl admin object
   field.  It does not handle the rwlock. */

ulong
fd_vinyl_admin_ulong_query( ulong const * _field );

/* fd_vinyl_admin_update modifies the given field of a vinyl admin
   object.  It does not handle the rwlock. */

void
fd_vinyl_admin_ulong_update( ulong * _field,
                             ulong   value );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_vinyl_admin_h */
