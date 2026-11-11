#ifndef HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_h
#define HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_h

/* fd_dasm is a run time assembler for code generators, derived from
   DynASM (https://luajit.org/dynasm.html).

   Copyright (C) 2005-2026 Mike Pall. All rights reserved.
   Released under the MIT license, see NOTICE.

   fd_dasm.py turns assembly embedded in C into a constant "action
   list" and calls to fd_dasm_put.  Assembling is three passes:

     fd_dasm_put     appends one chunk of the action list, with the run
                     time values of its operands, to a buffer
     fd_dasm_link    resolves labels and computes the code size
     fd_dasm_encode  writes the machine code

   All memory is provided by the caller up front.  Errors are sticky:
   after the first error, fd_dasm_put does nothing, and fd_dasm_link
   returns the error.  So the caller does not have to check each put.

   This header is architecture independent.  The passes are in
   fd_dasm_x86.h and fd_dasm_arm64.h. */

#include "../../../../util/bits/fd_bits.h"

/* FD_DASM_VERSION changes whenever the action list encoding does (the
   generator and the passes must agree on it). */

#define FD_DASM_VERSION (1)

/* FD_DASM_PUT_POS_MAX is the max number of buffer elements a single
   fd_dasm_put appends. */

#define FD_DASM_PUT_POS_MAX (25)

/* FD_DASM_LG_MAX is the size of the local/global label table. */

#define FD_DASM_LG_MAX (2048)

#define FD_DASM_SUCCESS    ( 0)
#define FD_DASM_ERR_FULL   (-1) /* buffer is full */
#define FD_DASM_ERR_IMM    (-2) /* immediate operand out of range */
#define FD_DASM_ERR_REG    (-3) /* register number out of range */
#define FD_DASM_ERR_LABEL  (-4) /* pc label index out of range, or backward reference to a missing local label */
#define FD_DASM_ERR_UNDEF  (-5) /* label is referenced but never defined */
#define FD_DASM_ERR_REL    (-6) /* branch target too far away */
#define FD_DASM_ERR_PHASE  (-7) /* encoded size differs from linked size (internal error) */

/* fd_dasm_t is the assembler state.

   A label table entry is 0 if the label is unused, -pos if the label
   is defined (buf[pos] then holds its code offset), or pos>0 if it is
   referenced but not yet defined (buf[pos] is the most recent
   reference, which links to the one before, ending in 0). */

struct fd_dasm {
  void const * actions;
  int *        pclabels; /* indexed [0,pc_cnt) */
  ulong        pc_cnt;
  int *        buf;      /* indexed [1,pos), element 0 is unused */
  int          buf_cnt;
  int          pos;
  int          ofs;      /* put: upper bound of code offset.  link: code size */
  int          err;      /* FD_DASM_{SUCCESS,ERR_*} */
  int          err_arg;  /* action list offset of the chunk that failed (label index if FD_DASM_ERR_UNDEF) */
  int          lglabels[ FD_DASM_LG_MAX ];
};

typedef struct fd_dasm fd_dasm_t;

FD_PROTOTYPES_BEGIN

/* fd_dasm_init starts assembling.  actions is the action list emitted
   by fd_dasm.py.  pclabels has room for pc_cnt labels (pc labels are
   the `=>idx` labels, numbered [0,pc_cnt)).  buf has room for buf_cnt
   ints, buf_cnt in [FD_DASM_PUT_POS_MAX,INT_MAX].  Both are scratch
   memory that must outlive the use of d.  Cost is O(pc_cnt). */

static inline fd_dasm_t *
fd_dasm_init( fd_dasm_t *  d,
              void const * actions,
              int *        pclabels,
              ulong        pc_cnt,
              int *        buf,
              ulong        buf_cnt ) {
  d->actions  = actions;
  d->pclabels = pclabels;
  d->pc_cnt   = pc_cnt;
  d->buf      = buf;
  d->buf_cnt  = (int)buf_cnt;
  d->pos      = 1;
  d->ofs      = 0;
  d->err      = FD_DASM_SUCCESS;
  d->err_arg  = 0;
  fd_memset( d->lglabels, 0, sizeof(d->lglabels) );
  fd_memset( pclabels,    0, pc_cnt*sizeof(int)  );
  return d;
}

/* fd_dasm_pclabel_ofs returns the code offset of pc label idx, or -1
   if that label is not defined.  fd_dasm_global_ofs does the same for
   global label idx (the `->name` labels, numbered by the enum that
   `.globals` emits).  Valid after a successful fd_dasm_link. */

static inline int
fd_dasm_pclabel_ofs( fd_dasm_t const * d,
                     ulong             idx ) {
  if( FD_UNLIKELY( idx>=d->pc_cnt ) ) return -1;
  int pos = d->pclabels[ idx ];
  return pos<0 ? d->buf[ -pos ] : -1;
}

static inline int
fd_dasm_global_ofs( fd_dasm_t const * d,
                    ulong             idx ) {
  if( FD_UNLIKELY( idx>=FD_DASM_LG_MAX-10UL ) ) return -1;
  int pos = d->lglabels[ 10UL+idx ];
  return pos<0 ? d->buf[ -pos ] : -1;
}

FD_FN_CONST static inline char const *
fd_dasm_strerror( int err ) {
  switch( err ) {
  case FD_DASM_SUCCESS:   return "success";
  case FD_DASM_ERR_FULL:  return "buffer full";
  case FD_DASM_ERR_IMM:   return "immediate out of range";
  case FD_DASM_ERR_REG:   return "register out of range";
  case FD_DASM_ERR_LABEL: return "bad label";
  case FD_DASM_ERR_UNDEF: return "undefined label";
  case FD_DASM_ERR_REL:   return "branch out of range";
  case FD_DASM_ERR_PHASE: return "phase error";
  default:                return "unknown";
  }
}

/* Helpers for the passes */

static inline int
fd_dasm_fail( fd_dasm_t * d,
              int         err,
              int         arg ) {
  d->err     = err;
  d->err_arg = arg;
  return err;
}

/* fd_dasm_label_def defines the label with table entry pl at buffer
   position pos, pointing all pending references at it. */

static inline void
fd_dasm_label_def( int * buf,
                   int * pl,
                   int   pos ) {
  int n = *pl;
  while( n>0 ) { int next = buf[ n ]; buf[ n ] = pos; n = next; }
  *pl = -pos;
}

/* fd_dasm_label_ref stores a reference to the label with table entry
   pl at buffer position pos.  fwd forces a new forward reference even
   if the label is defined (local labels are redefined as they go). */

static inline void
fd_dasm_label_ref( int * buf,
                   int * pl,
                   int   pos,
                   int   fwd ) {
  int n = *pl;
  if( n<0 && !fwd ) { buf[ pos ] = -n; return; }
  buf[ pos ] = fd_int_max( n, 0 );
  *pl        = pos;
}

/* fd_dasm_link_check returns FD_DASM_ERR_UNDEF if any label is
   referenced but not defined. */

static inline int
fd_dasm_link_check( fd_dasm_t * d ) {
  for( ulong i=0UL; i<FD_DASM_LG_MAX; i++ ) {
    if( FD_UNLIKELY( d->lglabels[ i ]>0 ) ) return fd_dasm_fail( d, FD_DASM_ERR_UNDEF, (int)i );
  }
  for( ulong i=0UL; i<d->pc_cnt; i++ ) {
    if( FD_UNLIKELY( d->pclabels[ i ]>0 ) ) return fd_dasm_fail( d, FD_DASM_ERR_UNDEF, (int)i );
  }
  return FD_DASM_SUCCESS;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_h */
