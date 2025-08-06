#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_logger_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_logger_h

#include "../../util/fd_util_base.h"

/* fd_solcap_logger is a handle to a solcap event capture object that
   sends solcap events to a writer backend.  The writer backend can be a
   solcap writer tile or a file.  The solcap writer tile is used when
   logging events in the full topology, while the file writer backend is
   used when running single-threaded ledger replay or solfuzz. */
struct fd_solcap_logger;
typedef struct fd_solcap_logger fd_solcap_logger_t;

FD_PROTOTYPES_BEGIN

/* fd_solcap_logger_align returns the alignment requirements for the
   memory region backing the fd_solcap_logger_t object.  Returns a power
   of two. */

FD_FN_CONST ulong
fd_solcap_logger_align( void );

/* fd_solcap_logger_footprint returns the footprint requirments for the
   memory region backing the fd_solcap_logger_t object.  is_tile
   represents whether the fd_solcap_logger_t object is created in a tile
   topology context.  If is_tile is false, then a single-threaded
   environment is assumed.  Returns a non-zero byte count.*/

FD_FN_CONST ulong
fd_solcap_logger_footprint( int is_tile );

/* fd_solcap_logger_new creates a new fd_solcap_logger_t object using
   the given memory region.  mem points to a memory region with matching
   align and footprint.  Returns a pointer to the logger object within
   the memory region.  Returned pointer should not be assumed to be a
   simple cast of mem.  On failure, logs error and returns NULL.
   Reasons for failure include mem==NULL or invalid alignment. */

void *
fd_solcap_logger_new( void * shlogger );

/* fd_solcap_logger_join joins the caller to the fd_solcap_logger_t
   object.  shlogger points to the first byte of the memory region
   backing the fd_solcap_logger_t object.  Returns a fd_solcap_logger_t
   pointer on success and NULL on failure. */

fd_solcap_logger_t *
fd_solcap_logger_join( void * shlogger );

/* fd_solcap_logger_leave unformats a memory region used as a
   fd_solcap_logger_t object.  Returns a pointer to the underlying
   shared memory region on success and NULL on failure. */

void *
fd_solcap_logger_leave( fd_solcap_logger_t * logger );

/* fd_solcap_logger_delete unformats a memory region used as a
   fd_solcap_logger_t object.  Assumes nobody is joined to the region.
   Returns a pointer to the underlying shared memory region or NULL on
   failure.  The ownership of the memory region is transferred to the
   caller. */

void *
fd_solcap_logger_delete( void * shlogger );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_logger_h */
