#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_tmpl_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_tmpl_h

/* Container instantiations for the fd_vote_codec.h types.  Kept out of
   fd_vote_codec.h (included by ~90 TUs through fd_bank.h) because only
   the vote program, codec and a few tiles use them. */

#include "fd_vote_codec.h"

/**********************************************************************/
/* Deque templates -- instruction sub-types                           */
/**********************************************************************/

#define DEQUE_NAME deq_ulong
#define DEQUE_T ulong
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

#define DEQUE_NAME deq_fd_vote_lockout_t
#define DEQUE_T fd_vote_lockout_t
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

/**********************************************************************/
/* Deque templates -- vote account state                              */
/**********************************************************************/

#define DEQUE_NAME deq_fd_vote_epoch_credits_t
#define DEQUE_T fd_vote_epoch_credits_t
#define DEQUE_MAX MAX_EPOCH_CREDITS_HISTORY_CAPACITY
#include "../../../../util/tmpl/fd_deque.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

#define DEQUE_NAME deq_fd_landed_vote_t
#define DEQUE_T fd_landed_vote_t
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

/**********************************************************************/
/* Treap / pool for authorized voters                                 */
/**********************************************************************/

#define POOL_NAME fd_vote_authorized_voters_pool
#define POOL_T fd_vote_authorized_voter_t
#define POOL_IDX_T uchar
#define POOL_NEXT parent
#include "../../../../util/tmpl/fd_pool.c"
#define TREAP_NAME fd_vote_authorized_voters_treap
#define TREAP_T fd_vote_authorized_voter_t
#define TREAP_IDX_T uchar
#define TREAP_QUERY_T ulong
#define TREAP_CMP(q,e) ( (q == (e)->epoch) ? 0 : ( (q < (e)->epoch) ? -1 : 1 ) )
#define TREAP_LT(e0,e1) ((e0)->epoch<(e1)->epoch)
#include "../../../../util/tmpl/fd_treap.c"

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_tmpl_h */
