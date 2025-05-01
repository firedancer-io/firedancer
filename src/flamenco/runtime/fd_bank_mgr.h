#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk.h"

/* TODO: make this struct opaque. */
struct fd_bank_mgr {
  fd_funk_t *           funk;
  fd_funk_txn_t *       funk_txn;
  fd_funk_rec_prepare_t prepare;
};
typedef struct fd_bank_mgr fd_bank_mgr_t;

ulong
fd_bank_mgr_align( void );

ulong
fd_bank_mgr_footprint( void );

void *
fd_bank_mgr_new( void * mem );

fd_bank_mgr_t *
fd_bank_mgr_join( void * mem, fd_funk_t * funk, fd_funk_txn_t * funk_txn );

/* TODO: Turn all of these into an iter macro (see sysvar cache). */
fd_block_hash_queue_global_t *
fd_bank_mgr_block_hash_queue_query( fd_bank_mgr_t * bank_mgr );

fd_block_hash_queue_global_t *
fd_bank_mgr_block_hash_queue_modify( fd_bank_mgr_t * bank_mgr );

int
fd_bank_mgr_block_hash_queue_save( fd_bank_mgr_t * bank_mgr );
