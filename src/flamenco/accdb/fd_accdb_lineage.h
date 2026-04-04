#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_lineage_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_lineage_h

/* fd_accdb_lineage.h provides an API for filtering account database
   records by fork graph lineage. */

#include "../../funk/fd_funk_txn.h"


#define FD_ACCDB_MAX_DEPTH_MAX (8192UL)

struct fd_accdb_lineage {

  /* Current fork cache */
  fd_funk_txn_xid_t fork[ FD_ACCDB_MAX_DEPTH_MAX ];
  ulong             fork_depth;

  uint txn_idx[ FD_ACCDB_MAX_DEPTH_MAX ];

  /* Current funk txn cache */
  ulong tip_txn_idx; /* ==ULONG_MAX if tip is root */

  ulong max_depth;
};

#define FD_ACCDB_LINEAGE_FOOTPRINT (sizeof(fd_accdb_lineage_t))

typedef struct fd_accdb_lineage fd_accdb_lineage_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_lineage_has_xid returns 1 if the given record XID is part of
   the current lineage, otherwise 0. */

FD_FN_UNUSED static int
fd_accdb_lineage_has_xid( fd_accdb_lineage_t const * lineage,
                          fd_funk_txn_xid_t const *  rec_xid ) {
  ulong const fork_depth = lineage->fork_depth;
  if( fd_funk_txn_xid_eq_root( rec_xid ) ) return 1;
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( fd_funk_txn_xid_eq( &lineage->fork[i], rec_xid ) ) return 1;
  }
  return 0;
}

/* fd_accdb_lineage_set_fork pivots the lineage object to the lineage
   from database root to the given XID (tip). */

void
fd_accdb_lineage_set_fork_slow( fd_accdb_lineage_t *      lineage,
                                fd_funk_t const *         funk,
                                fd_funk_txn_xid_t const * xid );

static inline void
fd_accdb_lineage_set_fork( fd_accdb_lineage_t *      lineage,
                           fd_funk_t const *         funk,
                           fd_funk_txn_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!lineage->fork_depth) & (!!fd_funk_txn_xid_eq( &lineage->fork[ 0 ], xid ) ) ) ) return;
  fd_accdb_lineage_set_fork_slow( lineage, funk, xid ); /* switch fork */
}

/* fd_accdb_lineage_is_tip returns 1 if xid equals the tip of the
   current lineage, otherwise 0. */

static inline int
fd_accdb_lineage_is_tip( fd_accdb_lineage_t const * lineage,
                         fd_funk_txn_xid_t const *  xid ) {
  if( lineage->fork_depth==0UL ) return 0;
  return fd_funk_txn_xid_eq( &lineage->fork[ 0 ], xid );
}

/* fd_accdb_lineage_write_check verifies whether the tip of the current
   lineage is writable (not frozen).  Aborts the app with FD_LOG_CRIT
   if writes to the tip of this lineage are not allowed. */

fd_funk_txn_t *
fd_accdb_lineage_write_check( fd_accdb_lineage_t const * lineage,
                              fd_funk_t const *          funk );

/* fd_lineage_xid returns the record XID of the given slot number.
   In other words, all records that were created at this slot number
   are tagged with this XID.  Possible return values:
   - NULL: slot skipped or rooted slot
   - else: slot part of lineage, non-rooted slot */

fd_xid_t const *
fd_lineage_xid( fd_accdb_lineage_t const * lineage,
                ulong                      slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_lineage_h */
