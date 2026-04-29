#ifndef HEADER_fd_src_discof_backtest_fd_backtest_src_h
#define HEADER_fd_src_discof_backtest_fd_backtest_src_h

#include "../../flamenco/types/fd_types_custom.h"

struct fd_backt_slot_info {
  ulong     slot;
  fd_hash_t bank_hash;
  uint      bank_hash_set : 1;
  uint      optimistic_confirmed : 1;
  uint      rooted : 1;
  uint      dead : 1;
};
typedef struct fd_backt_slot_info fd_backt_slot_info_t;

typedef struct fd_backt_src_vt fd_backt_src_vt_t;

struct fd_backt_src {
  fd_backt_src_vt_t const * vt;
};
typedef struct fd_backt_src fd_backt_src_t;

struct fd_backt_src_vt {

  void
  (* destroy)( fd_backt_src_t * this );

  ulong
  (* first_shred)( fd_backt_src_t * this,
                   uchar  *         buf,
                   ulong            buf_sz );

  ulong
  (* shred)( fd_backt_src_t * this,
             uchar  *         buf,
             ulong            buf_sz );

  fd_backt_slot_info_t *
  (* slot_info)( fd_backt_src_t *       this,
                 fd_backt_slot_info_t * out,
                 ulong                  slot );

};

struct fd_backtest_src_opts {
  char const * format;
  char const * path;

  uint rooted_only : 1;
  uint code_shreds : 1;
};
typedef struct fd_backtest_src_opts fd_backtest_src_opts_t;

FD_PROTOTYPES_BEGIN

/* fd_backtest_src_first_shred peeks the first shred of the source.
   Returns the size of the shred (non-zero) on success or zero on
   failure (logs warning).  Writes the shred payload to buf. */

ulong
fd_backtest_src_first_shred( fd_backtest_src_opts_t const * opts,
                             uchar *                        buf,
                             ulong                          buf_sz );

/* fd_backtest_src_create constructs a ledger shred source with the
   given options.  Returns a newly allocated backtest_src object on
   success, or NULL on failure (logs warning). */

fd_backt_src_t *
fd_backtest_src_create( fd_backtest_src_opts_t const * opts );

/* fd_backtest_src_destroy frees backtest_src and all its resources. */

static inline void
fd_backtest_src_destroy( fd_backt_src_t * db ) {
  db->vt->destroy( db );
}

/* fd_backtest_src_shred consumes the backtest_src's next shred. */

static inline ulong
fd_backtest_src_shred( fd_backt_src_t * db,
                       uchar *          buf,
                       ulong            buf_sz ) {
  return db->vt->shred( db, buf, buf_sz );
}

/* fd_backtest_src_slot_info queries consensus info for the given slot. */

static inline fd_backt_slot_info_t *
fd_backtest_src_slot_info( fd_backt_src_t *       db,
                           fd_backt_slot_info_t * out,
                           ulong                  slot ) {
  return db->vt->slot_info( db, out, slot );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backtest_fd_backtest_src_h */
