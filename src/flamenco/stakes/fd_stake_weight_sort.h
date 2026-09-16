#ifndef HEADER_fd_flamenco_stakes_fd_stake_weight_sort_h
#define HEADER_fd_flamenco_stakes_fd_stake_weight_sort_h

/* Sort instantiations for fd_stake_weight.h types.  Separate header so
   the ~110 TUs that only need the structs skip two fd_sort.c
   expansions. */

#include "fd_stake_weight.h"

#define SORT_NAME fd_stake_weight_key_sort
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_vote_weights_by_stake_vote
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).vote_key.uc, (b).vote_key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#endif /* HEADER_fd_flamenco_stakes_fd_stake_weight_sort_h */
