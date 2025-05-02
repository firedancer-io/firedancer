#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../funk/fd_funk.h"

/* The bank manager is a wrapper on top of funk that manages on-chain
   state not represented by accounts. In practice, this on-chain state
   is a direct parallel to the Bank data structure in the Agave client.

   Each "member" of the bank manager is represented by a funk record.
   The rationale behind this is to make the bank fork-aware by
   leveraging the fact that funk already is. Also, by separating out
   each member of the bank into its own funk record means that we will
   not need to copy the entire bank while forking. A record will only
   be copied if it is modified in a slot. Each bank manager record must
   not contain gaddrs or local pointers -- all data must be accessed
   directly or with an offset.

   The standard usage pattern of the bank manager is to first refresh a
   local join for each slot via a call to fd_bank_mgr_join().
   If this join is not refreshed with the latest funk txn, then the
   caller will receive stale data. There are two ways to access the
   data after a join has been established:
   1. non-mutable: call _query(). The data returned by this call should
      not be modified and will return a direct pointer to the data in
      the funk record map.
   2. mutable: call _modfiy() followed by a _save(). _modify() will
      return a pointer to the data structure of the previous incarnation
      of record. This record can be freely modified, but it must be
      followed by a call to _save() or the changes will be discarded.
      For a single join of the bank manager, _modify() and _save()
      should not be interleaved.

   TODO: Consider supporting multiple funk rec prepares per join.
   TODO: Replace the below ID, FOOTPRINT, ALIGN with macros and ideally
   a function that generates the worst case footprint and align given
   some parameters. */

#define FD_BANK_MGR_BLOCK_HASH_QUEUE_ID        (0)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_FOOTPRINT (50000UL)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN     (1024UL)

#define FD_BANK_MGR_SLOT_ID        (1)
#define FD_BANK_MGR_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_FEE_RATE_GOVERNOR_ID        (2)
#define FD_BANK_MGR_FEE_RATE_GOVERNOR_FOOTPRINT (40UL)
#define FD_BANK_MGR_FEE_RATE_GOVERNOR_ALIGN     (8UL)

#define FD_BANK_MGR_CAPITALIZATION_ID        (3)
#define FD_BANK_MGR_CAPITALIZATION_FOOTPRINT (8UL)
#define FD_BANK_MGR_CAPITALIZATION_ALIGN     (8UL)

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

#define BANK_MGR_FUNCTIONS(type, name, uppername)        \
type*                                                    \
fd_bank_mgr_##name##_query(fd_bank_mgr_t* bank_mgr);     \
                                                         \
type*                                                    \
fd_bank_mgr_##name##_modify(fd_bank_mgr_t* bank_mgr);    \
                                                         \
int                                                      \
fd_bank_mgr_##name##_save(fd_bank_mgr_t* bank_mgr);

#define FD_BANK_MGR_ITER(X)                                             \
  X(fd_block_hash_queue_global_t, block_hash_queue,  BLOCK_HASH_QUEUE)  \
  X(ulong,                        slot,              SLOT)              \
  X(fd_fee_rate_governor_t,       fee_rate_governor, FEE_RATE_GOVERNOR) \
  X(ulong,                        capitalization,    CAPITALIZATION)

FD_BANK_MGR_ITER(BANK_MGR_FUNCTIONS)
