#ifndef HEADER_fd_src_discof_backtest_fd_backtest_rocksdb_h
#define HEADER_fd_src_discof_backtest_fd_backtest_rocksdb_h

#include "../../util/fd_util_base.h"

struct fd_backtest_rocksdb_private;
typedef struct fd_backtest_rocksdb_private fd_backtest_rocksdb_t;

#define FD_BACKTEST_ROCKSDB_MAGIC (0xF17EDA2CE58AC810) /* FIREDANCE BACKT V0 */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_backtest_rocksdb_align( void );

FD_FN_CONST ulong
fd_backtest_rocksdb_footprint( void );

void *
fd_backtest_rocksdb_new( void *       shmem,
                         char const * path );

fd_backtest_rocksdb_t *
fd_backtest_rocksdb_join( void * shdb );

void
fd_backtest_rocksdb_init( fd_backtest_rocksdb_t * db,
                          ulong                   root_slot );

int
fd_backtest_rocksdb_next_root_slot( fd_backtest_rocksdb_t * db,
                                    ulong *                 root_slot,
                                    ulong *                 shred_cnt );

void const *
fd_backtest_rocksdb_shred( fd_backtest_rocksdb_t * db,
                           ulong                   slot,
                           ulong                   shred_idx );

uchar const *
fd_backtest_rocksdb_bank_hash( fd_backtest_rocksdb_t * db,
                               ulong                   slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backtest_fd_backtest_rocksdb_h */
