#ifndef HEADER_fd_src_discof_backtest_fd_backtest_shredcap_h
#define HEADER_fd_src_discof_backtest_fd_backtest_shredcap_h

#include "../../util/fd_util_base.h"

struct fd_backtest_shredcap_private;
typedef struct fd_backtest_shredcap_private fd_backtest_shredcap_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_backtest_shredcap_align( void );

FD_FN_CONST ulong
fd_backtest_shredcap_footprint( void );

fd_backtest_shredcap_t *
fd_backtest_shredcap_new( void *       shmem,
                          char const * path );

void *
fd_backtest_shredcap_delete( fd_backtest_shredcap_t * db );

void
fd_backtest_shredcap_init( fd_backtest_shredcap_t * db,
                           ulong                    root_slot );

int
fd_backtest_shredcap_next_root_slot( fd_backtest_shredcap_t * db,
                                     ulong *                  root_slot,
                                     ulong *                  shred_cnt );

void const *
fd_backtest_shredcap_shred( fd_backtest_shredcap_t * db,
                            ulong                    slot,
                            ulong                    shred_idx );

uchar const *
fd_backtest_shredcap_bank_hash( fd_backtest_shredcap_t * db,
                                ulong                    slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backtest_fd_backtest_shredcap_h */
