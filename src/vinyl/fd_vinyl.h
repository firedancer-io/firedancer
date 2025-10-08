#ifndef HEADER_fd_src_vinyl_fd_vinyl_h
#define HEADER_fd_src_vinyl_fd_vinyl_h

//#include "fd_vinyl_base.h"            /* includes ../tango/fd_tango.h, ../util/tmpl/fd_map.h */
//#include "bstream/fd_vinyl_bstream.h" /* includes fd_vinyl_base.h */
//#include "io/fd_vinyl_io.h"           /* includes bstream/fd_vinyl_bstream.h */
//#include "meta/fd_vinyl_meta.h"       /* includes bstream/fd_vinyl_bstream.h */
//#include "data/fd_vinyl_data.h"       /* includes io/fd_vinyl_io.h */
#include "line/fd_vinyl_line.h"         /* includes meta/fd_vinyl_meta.h data/fd_vinyl_data.h */
#include "rq/fd_vinyl_rq.h"             /* includes fd_vinyl_base.h */
#include "cq/fd_vinyl_cq.h"             /* includes fd_vinyl_base.h */

#define FD_VINYL_CNC_TYPE (0xFDC12C2CUL) /* FD VIN CNC */

#define FD_VINYL_CNC_SIGNAL_RUN          FD_CNC_SIGNAL_RUN
#define FD_VINYL_CNC_SIGNAL_BOOT         FD_CNC_SIGNAL_BOOT
#define FD_VINYL_CNC_SIGNAL_FAIL         FD_CNC_SIGNAL_FAIL
#define FD_VINYL_CNC_SIGNAL_HALT         FD_CNC_SIGNAL_HALT
#define FD_VINYL_CNC_SIGNAL_SYNC         (4UL) /* Signal that recovery should resume from the current bstream past */
#define FD_VINYL_CNC_SIGNAL_GET          (5UL) /* Get the value of the given option */
#define FD_VINYL_CNC_SIGNAL_SET          (6UL) /* Set the value of the given option */
#define FD_VINYL_CNC_SIGNAL_CLIENT_JOIN  (7UL) /* Have a client join the vinyl tile */
#define FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE (8UL) /* Have a client leave the vinyl tile */

#define FD_VINYL_OPT_PART_THRESH (0)
#define FD_VINYL_OPT_GC_THRESH   (1)
#define FD_VINYL_OPT_GC_EAGER    (2)
#define FD_VINYL_OPT_STYLE       (3)

union fd_vinyl_cmd {
  struct {
    int   err;
    ulong link_id;
    ulong burst_max;
    ulong quota_max;
    char  rq  [ FD_WKSP_CSTR_MAX  ];
    char  cq  [ FD_WKSP_CSTR_MAX  ];
    char  wksp[ FD_SHMEM_NAME_MAX ];
  } join;
  struct {
    int   err;
    ulong link_id;
  } leave;
  struct {
    int   err;
    int   opt;
    ulong val;
  } get;
  struct {
    int   err;
    int   opt;
    ulong val;
  } set;
};

typedef union fd_vinyl_cmd fd_vinyl_cmd_t;

/* FIXME: ADD ADDITIONAL DIAGNOSTICS (LIKE DISK USAGE, PAIR_CNT, ETC) */

#define FD_VINYL_DIAG_DROP_LINK (0)
#define FD_VINYL_DIAG_DROP_COMP (1)
#define FD_VINYL_DIAG_CNT (2UL)

#define FD_VINYL_CNC_APP_SZ (sizeof(fd_vinyl_cmd_t) + sizeof(ulong)*FD_VINYL_DIAG_CNT)

struct __attribute__((aligned(128))) fd_vinyl_private {

  /* Underlying shared objects */

  fd_cnc_t *        cnc;
  fd_vinyl_line_t * line; /* Indexed [0,line_cnt) */
  fd_vinyl_io_t *   io;

  /* Config */

  ulong line_cnt;  /* Max pairs data that can be cached, in [3,min(pair_max,FD_VINYL_LINE_MAX)] */
  ulong pair_max;  /* Max pairs that can be tracked globally, in [3,meta->ele_max) */
  ulong async_min; /* Min run loop iterations per async handling, positive */
  ulong async_max; /* Max run loop iterations per async handling, >=async_min */

  /* State */

  ulong part_thresh;  /* Insert partition blocks roughly every part_thresh bytes for parallel recovery */
  ulong gc_thresh;    /* Only compact if past_sz > gc_thresh */
  int   gc_eager;     /* Compact until <~ 2^-gc_eager fraction is garbage, in [-1,63], -1 disables */
  int   style;        /* Preferred bstream io encoding (i.e. is background compressed enabled) */
  uint  line_idx_lru; /* Index of the least recently used cache line, in [0,line_cnt] */
  ulong pair_cnt;     /* Num pair meta cached, in [0,pair_max] */
  ulong garbage_sz;   /* Num bytes garbage in the bstream's past */

  fd_vinyl_meta_t meta[1]; /* probe_max==ele_max, ele_max is a power 2 of at least 4, seed is meta_seed */
  fd_vinyl_data_t data[1]; /* data_laddr0 is local address of data cache gaddr0, obj contains data volumes */

  ulong cnc_footprint;
  ulong meta_footprint;
  ulong line_footprint;
  ulong ele_footprint;
  ulong obj_footprint;

  /* Padding to 128 byte aligned */

};

typedef struct fd_vinyl_private fd_vinyl_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_vinyl_align    ( void );
FD_FN_CONST ulong fd_vinyl_footprint( void );

/* fd_vinyl_init uses the the caller (typically tpool thread t0) and
   tpool threads (t0,t1) to init the vinyl structure (this structure can
   be extremely large ... hundreds of gigabytes to terabytes in memory
   for petabytes or more in persistent storage ... so it is worthwhile
   to parallelize the initialization).  The bstream's past will be used
   to recover the vinyl instance to the bstream's seq_present.  The
   recovery level is given by level (see fd_vinyl_recover below).
   Assumes tpool threads (t0,t1) are available for dispatch.  These
   threads will be avaialble for dispatch on return.  Retain no interest
   in tpool.  If tpool is NULL and/or the set [t0,t1) is empty/invalid,
   uses a serial algorithm for initialization. */

fd_vinyl_t *
fd_vinyl_init( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
               void * lmem,                         /* memory region to hold the vinyl's state */
               void * shcnc,  ulong cnc_footprint,  /* memory region to use for the tile cnc */
               void * shmeta, ulong meta_footprint, /* memory region to use for the cached pair metadata state */
               void * shline, ulong line_footprint, /* memory region to use for the cached pair state */
               void * shele,  ulong ele_footprint,  /* memory region to use for the cached pair metadata */
               void * shobj,  ulong obj_footprint,  /* memory region to use for the cached pairs */
               fd_vinyl_io_t * io,                  /* interface to the underlying bstream */
               ulong  seed,
               void * obj_laddr0,
               ulong  async_min,
               ulong  async_max,
               ulong  part_thresh,
               ulong  gc_thresh,
               int    gc_eager,
               int    style );

void *
fd_vinyl_fini( fd_vinyl_t * vinyl );

/* Accessors */

/* fd_vinyl_* return the eponymous field.  Where applicable
   fd_vinyl_*_const are const correct versions.  These assume vinyl is
   valid.  fd_vinyl_pair_cnt returns the num live pairs in the vinyl
   instance (e.g. all pairs that exist at bstream's seq_present and all
   pairs in the process of being created).  Will be in [0,pair_max].
   Assumes vinyl is valid. */

FD_FN_PURE static inline void *
fd_vinyl_shcnc( fd_vinyl_t const * vinyl ) {
  return (void *)fd_cnc_shmem_const( vinyl->cnc );
}

FD_FN_PURE static inline void *
fd_vinyl_shmeta( fd_vinyl_t const * vinyl ) {
  return (void *)fd_vinyl_meta_shmap_const( vinyl->meta );
}

FD_FN_PURE static inline void *
fd_vinyl_shline( fd_vinyl_t const * vinyl ) {
  return (void *)vinyl->line;
}

FD_FN_PURE static inline void *
fd_vinyl_shele( fd_vinyl_t const * vinyl ) {
  return (void *)fd_vinyl_meta_shele_const( vinyl->meta );
}

FD_FN_PURE static inline void *
fd_vinyl_shobj( fd_vinyl_t const * vinyl ) {
  return fd_vinyl_data_shmem( vinyl->data );
}

FD_FN_PURE static inline ulong fd_vinyl_cnc_footprint  ( fd_vinyl_t const * vinyl ) { return vinyl->cnc_footprint;  }
FD_FN_PURE static inline ulong fd_vinyl_meta_footprint_( fd_vinyl_t const * vinyl ) { return vinyl->meta_footprint; } /* FIXME: sigh */
FD_FN_PURE static inline ulong fd_vinyl_line_footprint ( fd_vinyl_t const * vinyl ) { return vinyl->line_footprint; }
FD_FN_PURE static inline ulong fd_vinyl_ele_footprint  ( fd_vinyl_t const * vinyl ) { return vinyl->ele_footprint;  }
FD_FN_PURE static inline ulong fd_vinyl_obj_footprint  ( fd_vinyl_t const * vinyl ) { return vinyl->obj_footprint;  }

FD_FN_PURE static inline fd_vinyl_io_t *
fd_vinyl_io( fd_vinyl_t const * vinyl ) {
  return (fd_vinyl_io_t *)vinyl->io;
}

FD_FN_PURE static inline ulong
fd_vinyl_seed( fd_vinyl_t const * vinyl ) {
  return fd_vinyl_meta_seed( vinyl->meta );
}

FD_FN_PURE static inline void *
fd_vinyl_obj_laddr0( fd_vinyl_t const * vinyl ) {
  return fd_vinyl_data_laddr0( vinyl->data );
}

FD_FN_PURE static inline ulong fd_vinyl_async_min  ( fd_vinyl_t const * vinyl ) { return vinyl->async_min;   }
FD_FN_PURE static inline ulong fd_vinyl_async_max  ( fd_vinyl_t const * vinyl ) { return vinyl->async_max;   }
FD_FN_PURE static inline ulong fd_vinyl_part_thresh( fd_vinyl_t const * vinyl ) { return vinyl->part_thresh; }
FD_FN_PURE static inline ulong fd_vinyl_gc_thresh  ( fd_vinyl_t const * vinyl ) { return vinyl->gc_thresh;   }
FD_FN_PURE static inline int   fd_vinyl_gc_eager   ( fd_vinyl_t const * vinyl ) { return vinyl->gc_eager;    }
FD_FN_PURE static inline int   fd_vinyl_style      ( fd_vinyl_t const * vinyl ) { return vinyl->style;       }

/* fd_vinyl_compact does up to compact_max rounds of compaction to the
   bstream's past.  This cannot fail from the caller's perspective (will
   FD_LOG_CRIT if any corruption is detected). */
/* FIXME: PRIVATE */

void
fd_vinyl_compact( fd_vinyl_t * vinyl,
                  ulong        compact_max );

/* fd_vinyl_recover uses the caller (typically tpool thread t0) and
   tpool threads (t0,t1) to reset the vinyl meta cache, reset the vinyl
   data cache, reset vinyl cache line eviction priorities and repopulate
   the vinyl meta data cache from the current state of the bstream's
   past to the bstream's seq_present.  level zero/non-zero indicates to
   do a soft/hard reset.  In a soft reset, the data cache region is
   minimally cleared.  In a hard reset, it is fully cleared.  A hard
   reset is recommended for most usage but a soft reset can allow faster
   startup for rapid iteration during development.

   Returns the bstream sequence number of how far recovery got (if this
   is not seq_present, the recovery was partial and it is theoretically
   moves in the recovery were not processed atomically).  Logs details
   of any issues encoutered.

   Assumes the tpool threads (t0,t1) are available for dispatch.
   Retains no interest in tpool and threads (t0,t1) will be available
   for dispatch on return. */
/* FIXME: PRIVATE */

ulong
fd_vinyl_recover( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
                  fd_vinyl_t * vinyl );

/* fd_vinyl_exec runs a vinyl tile on the caller. */

void
fd_vinyl_exec( fd_vinyl_t * vinyl );

int
fd_vinyl_halt( fd_cnc_t * cnc );

int
fd_vinyl_sync( fd_cnc_t * cnc );

int
fd_vinyl_get( fd_cnc_t * cnc,
              int        opt,
              ulong *    opt_val );

int
fd_vinyl_set( fd_cnc_t * cnc,
              int        opt,
              ulong      val,
              ulong *    opt_val );

int
fd_vinyl_client_join( fd_cnc_t *      cnc,
                      fd_vinyl_rq_t * rq,
                      fd_vinyl_cq_t * cq,
                      fd_wksp_t *     wksp,
                      ulong           link_id,
                      ulong           burst_max,
                      ulong           quota_max );

int
fd_vinyl_client_leave( fd_cnc_t * cnc,
                       ulong      link_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_fd_vinyl_h */
