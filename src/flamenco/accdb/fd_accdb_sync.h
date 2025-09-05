#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h

/* fd_accdb_sync.h provides a synchronous client API for the Firedancer
   account database. */

#include "fd_accdb_client.h"
#include "../../funk/fd_funk.h"
#include "../../util/valloc/fd_valloc.h"

/* Copying Read API ****************************************************

   This API is the simplest way to read accounts.  Does a full account
   copy on every query.  May block and spin the caller.  Has few error
   edge cases. */

FD_PROTOTYPES_BEGIN

/* fd_accdb_read does a copying read.  Queries the account database for
   the given address.  The caller provides a buffer to hold account
   data, and data_max is the byte size of that buffer.  If an account
   was found, fills *meta and *data.

   Side effects:
   - Fills in-memory account cache
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks, cache pressure, or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS:   account found
   - FD_ACCDB_ERR_KEY:   account not found
   - FD_ACCDB_ERR_BUFSZ: buffer too small */

int
fd_accdb_read( fd_accdb_client_t * client,
               void const *        address, /* 32 bytes */
               fd_accdb_meta_t *   meta,
               void *              data,
               ulong               data_max );

int
fd_accdb_read_meta( fd_accdb_client_t * client,
                    void const *        address,
                    fd_accdb_meta_t *   meta );

/* fd_accdb_read_valloc does a copy read.  Queries the account database
   for the given address.  Allocates a sufficiently sized buffer using
   the given heap allocator.  If an account was found, fills *meta and
   points *data to the heap allocation.  Ownership of this heap-
   allocated buffer is transferred over to the caller (it is the
   caller's responsibility to free the buffer).  Optionally, minimum
   alignment for the data buffer can be specified (data_align must be
   zero (default align) or a power of 2).  data_min specifies the
   minimum allocation size (the actual allocation may be larger if the
   account is big).

   Side effects:
   - Fills in-memory account cache
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS:    account found
   - FD_ACCDB_ERR_KEY:    account not found
   - FD_ACCDB_ERR_MALLOC: fd_valloc_malloc failed */

int
fd_accdb_read_valloc( fd_accdb_client_t * client,
                      void const *        address,
                      fd_accdb_meta_t *   meta,
                      void **             data,
                      ulong               data_align,
                      ulong               data_min,
                      fd_valloc_t const * valloc );

FD_PROTOTYPES_END

/* Locking zero-copy read API ******************************************

   Allows zero-copy reading of large accounts.  May block and spin the
   caller.  Notably can fail if there is too much cache pressure.

   Usage like:

     fd_accdb_ref_t ref[1];
     if( fd_accdb_borrow( client, ref, address )!=FD_ACCDB_SUCCESS ) {
       ... account borrow failed ...
       return;
     }
     ... process the account data ...
     fd_accdb_release( client, ref ); */

/* fd_accdb_ref_t is an ephemeral counted reference to an account in
   the database cache. */

struct fd_accdb_ref {
  fd_funk_rec_t const * rec;
};

typedef struct fd_accdb_ref fd_accdb_ref_t;

/* fd_accdb_borrow does a zero-copy read.  Queries the account database
   for the given address.  If an account was found, fills *ref.
   The underlying account is guaranteed to stay in cache for as long the
   ref is held.  It is the caller's responsibility to call
   fd_accdb_release to drop the account reference.

   Side effects:
   - Fills in-memory account cache
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS:        account found
   - FD_ACCDB_ERR_KEY:        account not found
   - FD_ACCDB_ERR_CACHE_FULL: cache heap is full, cannot fill cache */

int
fd_accdb_borrow( fd_accdb_client_t * client,
                 fd_accdb_ref_t *    ref,
                 void const *        address );

/* fd_accdb_release releases an account reference.
   Attempts to detect double release of the same ref and crashes with
   FD_LOG_CRIT (core dumps) in that case. */

void
fd_accdb_release( fd_accdb_client_t * client,
                  fd_accdb_ref_t *    ref );

/* Speculative non-blocking zero-copy read API ************************/

/* fd_accdb_peek_t is an ephemeral lock-free read-only pointer to an
   account in the database cache. */

struct fd_accdb_peek {
  fd_funk_rec_t const * rec;
};

typedef struct fd_accdb_peek fd_accdb_peek_t;

/* fd_accdb_peek_try starts a speculative read of an account.  Queries
   the account database cache for the given address (DOES NOT FILL CACHE
   FROM DISK).  If an account was found, fills *peek.  On return, peek
   refers to account data that was valid at some point, but is going to
   be overwritten with unrelated garbage in the near future.  Use
   fd_accdb_peek_test to confirm whether peek is still valid.

   Typical usage like:

     fd_accdb_peek_t peek[1];
     if( fd_accdb_peek_try( client, ... )!=FD_ACCDB_SUCCESS ) {
       ... account not found ...
       return;
     }
     ... speculatively process account ...
     if( fd_accdb_peek_test( peek )!=FD_ACCDB_SUCCESS ) {
       ... data race detected ...
       return;
     }
     ... happy path ... */

int
fd_accdb_peek_try( fd_accdb_client_t const * client,
                   fd_accdb_peek_t *         peek,
                   void const *              address );

/* fd_accdb_peek_test verifies whether a previously taken peek still
   refers to valid account data. */

FD_FN_PURE int
fd_accdb_peek_test( fd_accdb_peek_t const * peek );

/* Copying write API ***************************************************

   Simple one-shot method to write accounts. */

FD_PROTOTYPES_BEGIN

/* fd_accdb_write does a copying write.  Sets the content of an account
   at the accdb_client's current database transaction.

   Side effects:
   - Lazily evicts old cache entries
   - Blocks the calling thread on locks, cache pressure, or I/O

   Possible return values:
   - FD_ACCDB_SUCCESS:        account written
   - FD_ACCDB_ERR_DISK_FULL:  database persistent storage full (FIXME is this return value possible?)
   - FD_ACCDB_ERR_CACHE_FULL: cache full, tried to evict to no avail */

void
fd_accdb_write( fd_accdb_client_t *     client,
                fd_accdb_meta_t const * meta,
                void const *            data,
                ulong                   data_sz );

FD_PROTOTYPES_END

/* In-place transactional write APIs ***********************************

   Transactional zero-copy method to write accounts.  Changes done via
   this API appear atomic to other clients (invisible until publish is
   called). */

struct fd_accdb_refmut {
  fd_funk_rec_t * rec;
};

typedef struct fd_accdb_refmut fd_accdb_refmut_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_write_prepare prepares an account write.  On success,
   allocates a buffer for the account in the database cache's heap, and
   populates *write.

   Possible return values:
   - FD_ACCDB_SUCCESS:        write prepared
   - FD_ACCDB_ERR_CACHE_FULL: */

int
fd_accdb_write_prepare( fd_accdb_client_t * client,
                        fd_accdb_refmut_t * refmut,
                        void const *        address,
                        ulong               data_sz );

/* fd_accdb_modify_prepare prepares an account modification.  Creates a
   copy of the previous revision of the account.  If no account exists,
   creates an empty account.  FIXME document ...

   Possible return values:
   - FD_ACCDB_SUCCESS
   - FD_ACCDB_ERR_CACHE_FULL */

int
fd_accdb_modify_prepare( fd_accdb_client_t * client,
                         fd_accdb_refmut_t * refmut,
                         void const *        address,
                         ulong               data_min );

/* fd_accdb_write_cancel undoes all allocations done by an earlier
   prepare.  Attempts to detect a double cancel of the same buffer and
   crashes with FD_LOG_CRIT (core dumps) in that case. */

void
fd_accdb_write_cancel( fd_accdb_client_t * client,
                       fd_accdb_refmut_t * write );

/* fd_accdb_write_publish publishes a previously prepared account write.

   Possible return values:
   - FD_ACCDB_SUCCESS:
   - FD_ACCDB_ERR_KEY_RACE: detected conflicting write to this record
     between prepare and publish. */

int
fd_accdb_write_publish( fd_accdb_client_t * client,
                        fd_accdb_refmut_t * write ); /* destroyed */

/* fd_accdb_write_publish_demote is like fd_accdb_write_publish, but
   atomically creates a accdb_borrow read-only handle to the just
   published account. */

int
fd_accdb_write_publish_demote( fd_accdb_client_t * client,
                               fd_accdb_refmut_t * refmut,   /* destroyed */
                               fd_accdb_ref_t *    borrow ); /* created */

/* fd_accdb_write_data_copy copies account data bytes from the provided
   buffer into the account. */

/* Cache fill APIs *****************************************************

   An account cache fill copies an account from database to in-memory
   cache. */

/* fd_accdb_cache_fill performs a cache fill for a list of account
   addresses.  Silently ignores non-existent accounts. */

int
fd_accdb_cache_fill( fd_accdb_client_t * client,
                     void const *        address, /* flat array of 32 byte addresses */
                     ulong               address_cnt );

/* Syntax sugar for accessors *****************************************/

#define FD_ACCDB_READ_BEGIN( client, address, handle ) \
  __extension__({ \
    fd_accdb_ref_t handle[1]; \
    do

#define FD_ACCDB_READ_END \
    while(0); \
    0; \
  })

#define FD_ACCDB_WRITE_BEGIN( client, address, handle ) \
  __extension__({ \
    fd_accdb_refmut_t handle[1]; \
    do

#define FD_ACCDB_WRITE_END \
    while(0); \
    0; \
  })

/* Reference accessors *************************************************

   These are lightweight accessors to const/mutable account references.
   FIXME use GCC extension builtin_choose_expr to make const accessors
         usable for const and mut references */

void const * /* 32 bytes */
fd_accdb_ref_address( fd_accdb_ref_t const * ref );

void const *
fd_accdb_ref_data( fd_accdb_ref_t const * ref );

ulong
fd_accdb_ref_data_sz( fd_accdb_ref_t const * ref );

ulong
fd_accdb_ref_slot( fd_accdb_ref_t const * ref );

ulong
fd_accdb_ref_lamports( fd_accdb_ref_t const * ref );

void const * /* 32 bytes */
fd_accdb_ref_owner( fd_accdb_ref_t const * ref );

uint
fd_accdb_ref_exec_bit( fd_accdb_ref_t const * ref );

void
fd_accdb_ref_lthash( fd_accdb_refmut_t const * refmut,
                     void *                    lthash ); /* 2048 bytes */

void *
fd_accdb_refmut_data_copy( fd_accdb_refmut_t * refmut,
                           void const *        data,
                           ulong               data_sz );

void *
fd_accdb_refmut_data_buf( fd_accdb_refmut_t * refmut );

ulong
fd_accdb_refmut_slot( fd_accdb_refmut_t const * refmut );

void
fd_accdb_refmut_slot_set( fd_accdb_refmut_t * refmut,
                         ulong                slot );

ulong
fd_accdb_refmut_lamports( fd_accdb_refmut_t const * refmut );

void
fd_accdb_refmut_lamports_set( fd_accdb_refmut_t * refmut,
                              ulong               lamports );

void const *
fd_accdb_refmut_owner( fd_accdb_refmut_t const * refmut );

void
fd_accdb_refmut_owner_set( fd_accdb_refmut_t * refmut,
                           void const *        owner ); /* 32 bytes */

uint
fd_accdb_refmut_exec_bit( fd_accdb_refmut_t const * refmut );

void
fd_accdb_refmut_exec_bit_set( fd_accdb_refmut_t * refmut,
                              uint                executable ); /* in [0,1] */

void
fd_accdb_refmut_lthash( fd_accdb_refmut_t const * refmut,
                        void *                    lthash ); /* 2048 bytes */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_sync_h */
