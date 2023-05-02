#include "../util/fd_util_base.h"

/* Jump table template 
 * 
 * In order to 
 */

#ifndef JMP_TAB_ID
#error "Define JMP_TAB_ID"
#endif

#ifndef JMP_TAB_PRE_CASE_CODE
#error "Define JMP_TAB_PRE_CASE_CODE"
#endif

#ifndef JMP_TAB_POST_CASE_CODE
#error "Define JMP_TAB_POST_CASE_CODE"
#endif

#define __JT_ID JMP_TAB_ID

#define __JT_LABEL(prefix, id) prefix##_##id
#define JT_BASE_LABEL(id)    __JT_LABEL(base, id)
#define JT_BREAK_LABEL(id)   __JT_LABEL(break, id)
#define JT_RET_LABEL(id)     __JT_LABEL(ret, id)
#define JT_CASE_LABEL(val, id)     __JT_LABEL(case_##val, id)

#define JT_BREAK_LOC JT_BREAK_LABEL(__JT_ID)
#define JT_RET_LOC JT_RET_LABEL(__JT_ID)
#define JT_CASE_LOC(val) JT_CASE_LABEL(val, __JT_ID)
#define JT_BASE_LOC JT_BASE_LABEL(__JT_ID)

#define __JT_GOTO(idx, base_lbl, alignment) goto *(&&base_lbl + (idx * alignment))
#define JT_GOTO(idx) __JT_GOTO( \
    idx, \
    JT_BASE_LABEL(__JT_ID), \
)

#define __JT_START_IMPL(base_lbl, ret_lbl, alignment) \
goto ret_lbl;
#define __JT_START(base_lbl, ret_lbl, alignment) __JT_START_IMPL(base_lbl, ret_lbl, alignment)
#define JT_START __JT_START( \
    JT_BASE_LABEL(__JT_ID), \
    JT_RET_LABEL(__JT_ID), \
)

#define __JT_CASE_END_IMPL(post_case_code) \
post_case_code
#define __JT_CASE_END(post_case_code) __JT_CASE_END_IMPL(post_case_code)
#define JT_CASE_END __JT_CASE_END( \
  JMP_TAB_POST_CASE_CODE \
)

#define __JT_CASE_IMPL(case_lbl, pre_case_code) \
case_lbl: \
  pre_case_code
#define __JT_CASE(case_lbl, pre_case_code) __JT_CASE_IMPL(case_lbl, pre_case_code)
#define JT_CASE(val) __JT_CASE( \
    JT_CASE_LABEL(val, __JT_ID), \
    JMP_TAB_PRE_CASE_CODE \
)


#define __JT_END_IMPL(ret_lbl, break_lbl, alignment) \
ret_lbl:
#define __JT_END(ret_lbl, break_lbl, alignment) __JT_END_IMPL(ret_lbl, break_lbl, alignment)
#define JT_END __JT_END( \
    JT_RET_LABEL(__JT_ID), \
    JT_BREAK_LABEL(__JT_ID), \
)

