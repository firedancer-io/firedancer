#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_public_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_public_h

#include "../fd_flamenco_base.h"
#include "fd_runtime.h"
#include "../features/fd_features.h"

/* definition of the public/readable workspace */
#define FD_RUNTIME_PUBLIC_MAGIC (0xF17EDA2C9A7B1C21UL)

#define EXEC_NEW_SLOT_SIG  (0xABC123UL)
#define EXEC_NEW_EPOCH_SIG (0xDEF456UL)
#define EXEC_NEW_TXN_SIG   (0x777777UL)
#define EXEC_HASH_ACCS_SIG (0x888888UL)

#define FD_EXEC_STATE_NOT_BOOTED (0xFFFFFFFFUL)
#define FD_EXEC_STATE_BOOTED     (1<<1UL      )
#define FD_EXEC_STATE_EPOCH_DONE (1<<2UL      )
#define FD_EXEC_STATE_SLOT_DONE  (1<<3UL      )
#define FD_EXEC_STATE_TXN_DONE   (1<<4UL      )
#define FD_EXEC_STATE_IDLE       (1<<5UL      )

static uint FD_FN_UNUSED
fd_exec_fseq_get_state( ulong fseq ) {
  return (uint)(fseq & 0xFFFFFFFFU);
}

static ulong FD_FN_UNUSED
fd_exec_fseq_set_slot_done( void ) {
  return (ulong)FD_EXEC_STATE_SLOT_DONE;
}

static ulong FD_FN_UNUSED
fd_exec_fseq_set_booted( uint offset ) {
  ulong state = ((ulong)offset << 32UL);
  state      |= FD_EXEC_STATE_BOOTED;
  return state;
}

static uint FD_FN_UNUSED
fd_exec_fseq_get_booted_offset( ulong fseq ) {
  return (uint)(fseq >> 32UL);
}

static ulong FD_FN_UNUSED
fd_exec_fseq_set_epoch_done( void ) {
  return FD_EXEC_STATE_EPOCH_DONE;
}

static ulong FD_FN_UNUSED
fd_exec_fseq_set_txn_done( void ) {
  return FD_EXEC_STATE_TXN_DONE;
}

static ulong FD_FN_UNUSED
fd_exec_fseq_set_idle( void ) {
  return FD_EXEC_STATE_IDLE;
}

struct fd_runtime_public_epoch_msg {
  fd_features_t       features;
  ulong               total_epoch_stake;
  fd_epoch_schedule_t epoch_schedule;
  fd_rent_t           rent;
  double              slots_per_year;
  ulong               stakes_encoded_gaddr;
  ulong               stakes_encoded_sz;
  ulong               bank_hash_cmp_gaddr;
};
typedef struct fd_runtime_public_epoch_msg fd_runtime_public_epoch_msg_t;

struct fd_runtime_public_slot_msg {
  ulong                  slot;
  ulong                  prev_lamports_per_signature;
  fd_fee_rate_governor_t fee_rate_governor;
  ulong                  sysvar_cache_gaddr;
  ulong                  block_hash_queue_encoded_gaddr;
  ulong                  block_hash_queue_encoded_sz;
};
typedef struct fd_runtime_public_slot_msg fd_runtime_public_slot_msg_t;

struct fd_runtime_public_txn_msg {
  fd_txn_p_t txn;
};
typedef struct fd_runtime_public_txn_msg fd_runtime_public_txn_msg_t;

struct fd_runtime_public_hash_bank_msg {
  ulong task_infos_gaddr;
  ulong start_idx;
  ulong end_idx;
};
typedef struct fd_runtime_public_hash_bank_msg fd_runtime_public_hash_bank_msg_t;

struct fd_runtime_public {
  /* FIXME:  This is a non-fork-aware copy of the currently active
     features.  Once the epoch_ctx and the slot_ctx get moved into
     this workspace AND we make the epoch_ctx properly fork aware at
     the epoch boundary, we can remove this copy of the features map
     and just use the epoch_ctx (or slot_ctx) copy directly. */

  /* TODO: Maybe it is better to split out the runtime_spad_gaddr into
     a different shared struct? I think it is okay because it is part of
     the runtime. */
  ulong         magic;
  fd_features_t features;
  ulong         runtime_spad_gaddr;
};
typedef struct fd_runtime_public fd_runtime_public_t;

FD_FN_CONST static inline ulong
fd_runtime_public_align( void ) {
  return alignof(fd_runtime_public_t);
}

ulong
fd_runtime_public_footprint( void );

void *
fd_runtime_public_new( void * shmem );

fd_runtime_public_t *
fd_runtime_public_join( void * shmem );

/* Returns a local join of the runtime spad */
fd_spad_t *
fd_runtime_public_join_and_get_runtime_spad( fd_runtime_public_t const * runtime_public );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_public_h */
