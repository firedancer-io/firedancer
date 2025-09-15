#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_session_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_session_h

/* fd_accdb_session.h provides APIs for inspecting account database
   client sessions. */

#include "fd_accdb_base.h"
#include "../../funk/fd_funk_base.h"

/* An fd_accdb_session_t object tracks funk transaction references and
   metrics of a database client. */

struct __attribute__((aligned(64))) fd_accdb_session {
  fd_funk_txn_xid_t txn_active;
  ushort            next;
  ushort            tile_id;
};

typedef struct fd_accdb_session fd_accdb_session_t;

#define SLIST_NAME  ses_list
#define SLIST_ELE_T fd_accdb_session_t
#define SLIST_IDX_T ushort
#include "../../util/tmpl/fd_slist.c"

/* fd_accdb_sestab is a table of accdb_session objects.  Lives in shared
   memory, supports concurrent access, and is position-independent. */

struct fd_accdb_sestab {
  fd_accdb_session_t * sessions;
  ulong                session_max;

  ses_list_t free_list;
  ses_list_t used_list;
};

typedef struct fd_accdb_sestab fd_accdb_sestab_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

ulong
fd_accdb_sestab_align( void );

ulong
fd_accdb_sestab_footprint( ulong session_max );

void *
fd_accdb_sestab_new( void * shmem,
                     ulong  session_max );

fd_accdb_sestab_t *
fd_accdb_sestab_join( void * shmem );

void *
fd_accdb_sestab_leave( fd_accdb_sestab_t * sestab );

void *
fd_accdb_sestab_delete( void * shmem );

/* fd_accdb_sestab_is_used returns 1 if any session is actively using
   the given txn XID.  This is useful for draining users from database
   transactions.  Typically, the caller first signals all threads to
   stop sending new queries against an XID, then polls for all remaining
   users to leave. */

int
fd_accdb_sestab_is_used( fd_accdb_sestab_t const * sestab,
                         fd_funk_txn_xid_t         xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_session_h */
