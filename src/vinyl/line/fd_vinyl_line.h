#ifndef HEADER_fd_src_vinyl_line_fd_vinyl_line_h
#define HEADER_fd_src_vinyl_line_fd_vinyl_line_h

/* A vinyl tile caches key-val pairs in DRAM for performance reasons
   and to facilitate operations like creating a new pair or asynchronous
   I/O.  This cache can be _completely_ lost without impacting the
   recoverabilty exactly key-val state at the time the bstream was most
   recently sync'd.

   This cache is logically organized into line_cnt cache lines.

   An eviction sequence gives the preferred order in which lines should
   be reused.  Though a line always has a position in the eviction
   sequence, a given line may not be evictable due to acquires for read
   or modify on that line.  A quota system bounds the worst case number
   of acquired lines in order to guarantee there are always some
   evictable lines.

   When a pair is evicted from a line, the line is moved to the least
   recently used (LRU) position in the eviction sequence so that unused
   lines can be quickly found and preferentially reused before any lines
   caching pairs.

   The eviction sequence is given by a circular doubly linked list and a
   cursor positioned at the LRU line.  Given the above, the sequence
   always contains exactly line_cnt lines.  Given the LRU line is
   tracked explicitly and circular list, the most recently used (MRU)
   line is tracked implicitly as the line "older" than the LRU line. */

#include "../meta/fd_vinyl_meta.h"
#include "../data/fd_vinyl_data.h"

/* FD_VINYL_LINE_EVICT_PRIO_* specify eviction priorities.  These should
   be compatible with fd_vinyl_req_evict_prio and FD_VINYL_REQ_FLAG_* */

#define FD_VINYL_LINE_EVICT_PRIO_MRU (0) /* <0 also treated as MRU */
#define FD_VINYL_LINE_EVICT_PRIO_LRU (1)
#define FD_VINYL_LINE_EVICT_PRIO_UNC (2) /* >2 also treated as UNC */

/* FD_VINYL_LINE_MAX gives the maximum number of lines that can be
   handled by a vinyl tile.  This is a large power of 2 minus 1.  The
   below value ensures that a value in [0,line_cnt] can be represented
   in 32-bits.  Note that larger is possible but requires more DRAM
   overhead.  For typical applications (where pair vals sizes are
   measured in KiB to MiB), a line_cnt at this LINE_MAX would require
   impractically large amounts of DRAM for the vinyl cache ... TiB to
   PiB). */

#define FD_VINYL_LINE_MAX ((1UL<<32)-1UL)

/* FD_VINYL_LINE_REF_MAX gives the max acquires-for-read allowed on a
   vinyl cache line.  Like LINE_MAX, this could be made larger at the
   expense of more DRAM overhead (and, more theoretical, more frequent
   line version wrapping for speculative reads).  The current value is
   sufficient to support an impractical number of concurrent clients
   acquiring the same pair for concurrently read. */

#define FD_VINYL_LINE_REF_MAX ((1L<<32)-2L)

/* FD_VINYL_LINE_VER_MAX gives the maximum number of versions a line
   can have before its version number gets reused.  This is a large
   power of 2 minus 1 such that version number reuse is impractical over
   the duration of any speculative reads. */

#define FD_VINYL_LINE_VER_MAX ((1UL<<32)-1UL)

/* FD_VINYL_LINE_SRC_* define the bit layout of specread_ctl (uint):

     bits [0,24)   specread reference count  (up to ~16M concurrent readers)
     bit  24       CHANCE flag               (CLOCK second-chance)
     bit  25       EVICTING flag             (vinyl tile claiming line)
     bits [26,32)  reserved (zero)

   specread_ctl is accessed atomically by cross-tile speculative readers
   (LOCK XADD to pin/unpin, LOCK OR to promote) and by the vinyl tile
   (LOCK CMPXCHG to claim for eviction, LOCK AND to clear chance). */

#define FD_VINYL_LINE_SRC_REF_MASK  (0x00FFFFFFU)
#define FD_VINYL_LINE_SRC_CHANCE    (0x01000000U)
#define FD_VINYL_LINE_SRC_EVICTING  (0x02000000U)

/* A fd_vinyl_line_t stores information the vinyl tile uses to track
   how a key-val pair has been cached in DRAM.  If the obj field is
   NULL, there is no pair cached in that line and all other fields are
   ignored.  Practically speaking, the vinyl tile uses this (local)
   structure to tie together the (shared) pair meta map and the (shared)
   data cache region.

   ctl contains:

     ver: This is bumped every time the line is changed to allow clients
     to do reliable lockfree speculative reads of the line under the
     assumption speculative reader will complete and test their
     speculative read before the version number can wrap.

     ref: -1 - the line is acquired for modify, 0 - the line is not
     acquired for anything (and thus is evictable), >0 - the line is
     acquired-for-read ref times.

   specread_ctl packs chance, specread reference count, and an evicting
   flag into a single atomic uint for cross-tile in-place speculative
   reads (see FD_VINYL_LINE_SRC_* above). */

struct __attribute__((aligned(64))) fd_vinyl_line {

  /* Reader-visible fields (cross-tile speculative readers) */

  ulong                 ctl;            /* packs the line version and line reference count */
  ulong                 ele_idx;        /* map element storing key and the pair metadata (app and key), in [0,ele_max), ULONG_MAX if unassigned */
  ulong                 val_gaddr;      /* gaddr of val in data wksp, 0 if not ready */
  uint                  specread_ctl;   /* atomic: packs chance + ref + evicting */
  uchar                 _pad0[4];

  /* Vinyl-tile-only fields */

  fd_vinyl_data_obj_t * obj;            /* location in the data cache of the data_obj storing val, NULL if not caching a pair */
  uint                  line_idx_older; /* older line in eviction sequence, in [0,line_cnt) */
  uint                  line_idx_newer; /* newer line in eviction sequence, in [0,line_cnt) */
  uchar                 _pad1[16];
};

typedef struct fd_vinyl_line fd_vinyl_line_t;

FD_STATIC_ASSERT( sizeof(fd_vinyl_line_t)==64UL, layout );

FD_PROTOTYPES_BEGIN

/* fd_vinyl_line_ctl returns ver and ref encoded as a line ctl.  ver is
   wrapped to be in [0,FD_VINYL_LINE_VER_MAX].  ref is assumed to be in
   [-1,FD_VINYL_LINE_REF_MAX].

   fd_vinyl_line_ctl_{ver,ref} returns the decoded eponymous field from
   a line ctl.  The return will be in
   {[0,FD_VINYL_LINE_VER_MAX]),[-1,FD_VINYL_LINE_REF_MAX]}. */

FD_FN_CONST static inline ulong
fd_vinyl_line_ctl( ulong ver,
                   long  ref ) {
  return (ver<<32) | ((ulong)(ref+1L));
}

FD_FN_CONST static inline ulong fd_vinyl_line_ctl_ver( ulong ctl ) { return ctl>>32; }
FD_FN_CONST static inline long  fd_vinyl_line_ctl_ref( ulong ctl ) { return ((long)(ctl & ((1UL<<32)-1UL)))-1L; }

/* fd_vinyl_line_evict_prio changes the eviction priority of line
   line_idx to evict_prio.  Cannot fail from the caller's perspective
   (will FD_LOG_CRIT if line corruption was detected). */

void
fd_vinyl_line_evict_prio( uint *            _line_idx_lru, /* Pointer to the LRU line idx */
                          fd_vinyl_line_t * line,          /* Indexed [0,line_cnt) */
                          ulong             _line_cnt,     /* In [3,FD_VINYL_LINE_MAX] */
                          ulong             _line_idx,     /* In [0,line_cnt) */
                          int               evict_prio );  /* FD_VINYL_LINE_EVICT_PRIO_* */

/* fd_vinyl_line_evict_lru finds the least recently used evictable line
   and evicts it.  Returns the line_idx of that line (will be free to
   use).  Cannot fail from the caller's perspective (will FD_LOG_CRIT if
   corruption was detected or quotas were misconfigured). */

ulong
fd_vinyl_line_evict_lru( uint *                _line_idx_lru, /* Pointer to the LRU line idx */
                         fd_vinyl_line_t *     line,          /* Indexed [0,line_cnt) */
                         ulong                 line_cnt,      /* In [3,FD_VINYL_LINE_MAX] */
                         fd_vinyl_meta_ele_t * ele0,          /* Indexed [0,ele_max) */
                         ulong                 ele_max,
                         fd_vinyl_data_t *     data );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_line_fd_vinyl_line_h */
