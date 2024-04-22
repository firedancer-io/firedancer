#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h

/* The clock sysvar provides an approximate measure of network time. */

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/clock.rs#L10 */
#define DEFAULT_TICKS_PER_SECOND ( 160UL )
#define FD_SYSVAR_CLOCK_DEFAULT_HASHES_PER_TICK  (12500UL)

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (102400UL)
static uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN))) __attribute__((used));


#define CIDX_T ulong
#define VAL_T  long
struct ele {
  CIDX_T parent_cidx;
  CIDX_T left_cidx;
  CIDX_T right_cidx;
  CIDX_T prio_cidx;
  VAL_T timestamp;
  unsigned long stake;
};

typedef struct ele ele_t;

#define POOL_NAME  pool
#define POOL_T     ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  parent_cidx
#include "../../../util/tmpl/fd_pool.c"

FD_FN_CONST static inline int valcmp (VAL_T a, VAL_T b) {
  int val = (a < b) ? -1 : 1;
  return (a == b) ? 0 : val;
}

#define TREAP_NAME       treap
#define TREAP_T          ele_t
#define TREAP_QUERY_T    VAL_T
#define TREAP_CMP(q,e)   valcmp(q, e->timestamp)
#define TREAP_LT(e0,e1)  (((VAL_T)((e0)->timestamp)) < ((VAL_T)((e1)->timestamp)))
#define TREAP_IDX_T      CIDX_T
#define TREAP_PARENT     parent_cidx
#define TREAP_LEFT       left_cidx
#define TREAP_RIGHT      right_cidx
#define TREAP_PRIO       prio_cidx
#define TREAP_IMPL_STYLE 0
#include "../../../util/tmpl/fd_treap.c"

FD_PROTOTYPES_BEGIN

/* The clock sysvar provides an approximate measure of network time. */

/* Initialize the clock sysvar account. */

void
fd_sysvar_clock_init( fd_exec_slot_ctx_t * slot_ctx );

/* Update the clock sysvar account.  This should be called at the start
   of every slot, before execution commences. */

int
fd_sysvar_clock_update( fd_exec_slot_ctx_t * slot_ctx );

/* Reads the current value of the clock sysvar */

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_sol_sysvar_clock_t * result,
                      fd_exec_slot_ctx_t *    slot_ctx );

/* fd_slot_cnt_2day returns the number of slots in two days.
   Used in rent collection. */

static inline ulong
fd_slot_cnt_2day( ulong ticks_per_slot ) {
  ulong seconds = (2UL * 24UL * 60UL * 60UL);
  ulong ticks   = seconds * DEFAULT_TICKS_PER_SECOND;
  return ticks / ticks_per_slot;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_clock_h */
