#include "../util/fd_util_base.h"

/* Aligned Jump Table */

#ifndef ALIGNED_JMP_TAB_ID
#error "Define ALIGNED_JMP_TAB_ID"
#endif

#ifndef ALIGNED_JMP_TAB_ALIGNMENT
#error "Define ALIGNED_JMP_TAB_ALIGNMENT"
#endif

#define __AJT_ID ALIGNED_JMP_TAB_ID

#define __AJT_LABEL(prefix, id) prefix##_##id
#define AJT_BASE_LABEL(id)    __AJT_LABEL(base, id)
#define AJT_BREAK_LABEL(id)   __AJT_LABEL(break, id)
#define AJT_RET_LABEL(id)     __AJT_LABEL(ret, id)
#define AJT_CASE_LABEL(val, id)     __AJT_LABEL(case_##val, id)

#define AJT_BREAK_LOC AJT_BREAK_LABEL(__AJT_ID)
#define AJT_RET_LOC AJT_RET_LABEL(__AJT_ID)
#define AJT_CASE_LOC(val) AJT_CASE_LABEL(val, __AJT_ID)
#define AJT_BASE_LOC AJT_BASE_LABEL(__AJT_ID)

#define __AJT_GOTO(idx, base_lbl, alignment) goto *(&&base_lbl + (idx * alignment))
#define AJT_GOTO(idx) __AJT_GOTO( \
    idx, \
    AJT_BASE_LABEL(__AJT_ID), \
    ALIGNED_JMP_TAB_ALIGNMENT \
)

#define __AJT_START_IMPL(base_lbl, ret_lbl, alignment) \
goto ret_lbl; \
base_lbl:
#define __AJT_START(base_lbl, ret_lbl, alignment) __AJT_START_IMPL(base_lbl, ret_lbl, alignment)
#define AJT_START __AJT_START( \
    AJT_BASE_LABEL(__AJT_ID), \
    AJT_RET_LABEL(__AJT_ID), \
    ALIGNED_JMP_TAB_ALIGNMENT \
)

#define __AJT_CASE_END_IMPL { \
  ic++; \
  pc++; \
  instr = ctx->instrs[pc]; \
  goto *(&&AJT_BASE_LOC + locs[instr.opcode.raw]); \
}
#define __AJT_CASE_END __AJT_CASE_END_IMPL
#define AJT_CASE_END __AJT_CASE_END

#define __AJT_CASE_IMPL(case_lbl, break_lbl, alignment) \
case_lbl: \
  dst_reg = instr.dst_reg; \
  src_reg = instr.src_reg; \
  imm = instr.imm;
#define __AJT_CASE(case_lbl, break_lbl, alignment) __AJT_CASE_IMPL(case_lbl, break_lbl, alignment)
#define AJT_CASE(val) __AJT_CASE( \
    AJT_CASE_LABEL(val, __AJT_ID), \
    AJT_BREAK_LABEL(__AJT_ID), \
    ALIGNED_JMP_TAB_ALIGNMENT \
)


#define __AJT_END_IMPL(ret_lbl, break_lbl, alignment) \
ret_lbl:
#define __AJT_END(ret_lbl, break_lbl, alignment) __AJT_END_IMPL(ret_lbl, break_lbl, alignment)
#define AJT_END __AJT_END( \
    AJT_RET_LABEL(__AJT_ID), \
    AJT_BREAK_LABEL(__AJT_ID), \
    ALIGNED_JMP_TAB_ALIGNMENT \
)

