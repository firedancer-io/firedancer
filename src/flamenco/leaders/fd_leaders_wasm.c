#include "fd_leaders.h"

/* The codebase has several FD_LOG_* calls but I/O support in wasm is
   unecessary and required extra effort on the frontend, so we stub out
   these functions instead. */

long fd_log_wallclock() { return 0; }
char const * fd_log_private_0( char const * fmt, ... ) { return 0; }
void fd_log_private_1(int level, long now, char const * file, int line, char const * func, char const * msg) {}
void fd_log_private_2(int level, long now, char const * file, int line, char const * func, char const * msg) {}

#define SORT_NAME        fd_stakes_sort
#define SORT_KEY_T       fd_stake_weight_t
#define SORT_BEFORE(a,b) (a.stake>b.stake) ? 1 : (a.stake<b.stake) ? 0 : memcmp( &a.key, &b.key, 32UL )>0
#include "../../util/tmpl/fd_sort.c"

static fd_epoch_leaders_t * lsched;
static uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) lsched_mem[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_PUB_CNT, MAX_SLOTS_CNT) ];
static fd_pubkey_t pubkeys[ MAX_PUB_CNT ];
static ulong stakes[ MAX_PUB_CNT ];

/* fd_epoch_leaders_wasm is as thin wrapper around the
   fd_epoch_leaders API. This lets us compile the leader schcedule logic
   to wasm without having to know the memory layout of structures
   in the firedancer codebase. */
void
fd_epoch_leaders_wasm_init( ulong         epoch,
                            ulong         slot0,
                            ulong         slot_cnt,
                            ulong         pub_cnt,
                            ulong         excluded_stake ) {

    fd_stake_weight_t pubkeys_stakes[ pub_cnt ];
    for( ulong i=0UL; i<pub_cnt; i++ ) pubkeys_stakes[ i ] = (fd_stake_weight_t){.key=pubkeys[i], .stake=stakes[ i ]};

    /* Assume wasm doesn't pre-sort */
    fd_stakes_sort_inplace( pubkeys_stakes, pub_cnt );

    fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched_mem ) );
    lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( lsched_mem, epoch, slot0, slot_cnt, pub_cnt, pubkeys_stakes, excluded_stake ) );

    return;
}

fd_pubkey_t *
fd_epoch_leaders_wasm_get_pubkeys() {
   return (fd_pubkey_t *)pubkeys;
}

ulong *
fd_epoch_leaders_wasm_get_stakes() {
   return (ulong *)stakes;
}

uint
fd_epoch_leaders_wasm_get_sched_cnt() {
   return lsched->sched_cnt;
}

uint *
fd_epoch_leaders_wasm_get_sched() {
   return lsched->sched;
}
