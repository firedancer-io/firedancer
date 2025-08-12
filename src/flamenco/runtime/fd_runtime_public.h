#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_public_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_public_h

#include "../features/fd_features.h"
#include "../types/fd_types.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../disco/fd_disco_base.h"

/* FIXME: Everything in this file should be migrated to fd_exec.h */

/* definition of the public/readable workspace */
#define FD_RUNTIME_PUBLIC_MAGIC (0xF17EDA2C9A7B1C21UL)

#define EXEC_NEW_TXN_SIG               (0x777777UL)

#define FD_WRITER_BOOT_SIG             (0xAABB0011UL)
#define FD_WRITER_SLOT_SIG             (0xBBBB1122UL)
#define FD_WRITER_TXN_SIG              (0xBBCC2233UL)
#define FD_WRITER_ACCOUNT_UPDATE_SIG   (0xBBDD3344UL)

#define FD_EXEC_STATE_NOT_BOOTED       (0xFFFFFFFFUL)
#define FD_EXEC_STATE_BOOTED           (1<<1UL      )

#define FD_WRITER_STATE_NOT_BOOTED     (0UL         )
#define FD_WRITER_STATE_READY          (1UL         )
#define FD_WRITER_STATE_TXN_DONE       (1UL<<1      )

#define FD_EXEC_ID_SENTINEL            (UINT_MAX    )


/* parallel execution apis ********************************************/

/* These are callbacks used to support different execution schemes.
   Namely, this is for tpool and to executing using the exec tiles. */

/* If you need more than the current amount of arguments/ways to exec,
   you need to update all uses of fd_exec_para_fn. */

#define FD_EXEC_PARA_TPOOL (0UL)
#define FD_EXEC_PARA_TILES (1UL)

typedef void (*fd_exec_para_cb_fn_t)( void * para_arg_1,
                                      void * para_arg_2,
                                      void * arg_1,
                                      void * arg_2,
                                      void * arg_3,
                                      void * arg_4 );

struct fd_exec_para_cb_ctx {
  uint                 num_args;
  fd_exec_para_cb_fn_t func;
  /* para_arg_{n} is used to pass arguments that are for the purpose of
    multithreaded execution. fn_arg_{n} are used to pass arguments used
    by the core business logic of the function. */
  void *            para_arg_1;
  void *            para_arg_2;
  void *            fn_arg_1;
  void *            fn_arg_2;
  void *            fn_arg_3;
  void *            fn_arg_4;
};
typedef struct fd_exec_para_cb_ctx fd_exec_para_cb_ctx_t;

static void FD_FN_UNUSED
fd_exec_para_call_func( fd_exec_para_cb_ctx_t * ctx ) {
  ctx->func( ctx->para_arg_1,
            ctx->para_arg_2,
            ctx->fn_arg_1,
            ctx->fn_arg_2,
            ctx->fn_arg_3,
            ctx->fn_arg_4 );
}

static int FD_FN_UNUSED
fd_exec_para_cb_is_single_threaded( fd_exec_para_cb_ctx_t * ctx ) {
  return ctx->para_arg_1==NULL && ctx->para_arg_2==NULL;
}

/**********************************************************************/

/* exec fseq management apis ******************************************/

static uint FD_FN_UNUSED
fd_exec_fseq_get_state( ulong fseq ) {
  return (uint)(fseq & 0xFFFFFFFFU);
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

static uint FD_FN_UNUSED
fd_exec_fseq_get_slot( ulong fseq ) {
  return (uint)(fseq >> 32UL);
}

static uint FD_FN_UNUSED
fd_exec_fseq_get_bpf_id( ulong fseq ) {
  return (uint)(fseq >> 32UL);
}

static uint FD_FN_UNUSED
fd_exec_fseq_get_pairs_len( ulong fseq ) {
  return (uint)(fseq >> 32UL);
}

static inline int
fd_exec_fseq_is_not_joined( ulong fseq ) {
  return fseq==ULONG_MAX;
}

/* Writer tile fseq management APIs ***********************************/

/*
   +----------------------------------+----------+----------------------+
   |         Transaction ID           | Exec Tile|         State        |
   |            (32 bits)             |   ID     |       (24 bits)      |
   |                                  | (8 bits) |                      |
   +----------------------------------+----------+----------------------+
 */

static inline uint
fd_writer_fseq_get_state( ulong fseq ) {
  return (uint)(fseq & 0x00FFFFFFU);
}

static inline ulong
fd_writer_fseq_set_txn_done( uint txn_id, uchar exec_tile_id ) {
  ulong state = (((ulong)txn_id) << 32);
  state      |= (((ulong)exec_tile_id) << 24);
  state      |= FD_WRITER_STATE_TXN_DONE;
  return state;
}

static inline uint
fd_writer_fseq_get_txn_id( ulong fseq ) {
  return (uint)(fseq >> 32);
}

static inline uchar
fd_writer_fseq_get_exec_tile_id( ulong fseq ) {
  return (uchar)((fseq >> 24) & 0xFFUL);
}

static inline int
fd_writer_fseq_is_not_joined( ulong fseq ) {
  return fseq==ULONG_MAX;
}

struct fd_runtime_public_txn_msg {
  ulong      slot;
  fd_txn_p_t txn;
};
typedef struct fd_runtime_public_txn_msg fd_runtime_public_txn_msg_t;

struct fd_runtime_public_hash_bank_msg {
  ulong task_infos_gaddr;
  ulong lthash_gaddr;
  ulong start_idx;
  ulong end_idx;
  ulong slot;
};
typedef struct fd_runtime_public_hash_bank_msg fd_runtime_public_hash_bank_msg_t;

struct fd_runtime_public_exec_writer_boot_msg {
  uint txn_ctx_offset;
};
typedef struct fd_runtime_public_exec_writer_boot_msg fd_runtime_public_exec_writer_boot_msg_t;
FD_STATIC_ASSERT( sizeof(fd_runtime_public_exec_writer_boot_msg_t)<=FD_EXEC_WRITER_MTU, exec_writer_msg_mtu );

struct fd_runtime_public_exec_writer_txn_msg {
  uint  txn_id;
  uchar exec_tile_id;
};
typedef struct fd_runtime_public_exec_writer_txn_msg fd_runtime_public_exec_writer_txn_msg_t;
FD_STATIC_ASSERT( sizeof(fd_runtime_public_exec_writer_txn_msg_t)<=FD_EXEC_WRITER_MTU, exec_writer_msg_mtu );

struct fd_runtime_public_replay_writer_slot_msg {
  ulong slot_ctx_gaddr;
};
typedef struct fd_runtime_public_replay_writer_slot_msg fd_runtime_public_replay_writer_slot_msg_t;
FD_STATIC_ASSERT( sizeof(fd_runtime_public_replay_writer_slot_msg_t)<=FD_REPLAY_WRITER_MTU, replay_writer_msg_mtu );

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */
#define FD_ACC_SZ_MAX       (10UL<<20) /* 10MiB */

/* Message sent from writer tile to replay tile,
   notifying the solcap writer that an account update has occurred. */
struct fd_runtime_public_account_update_msg {
  fd_pubkey_t              pubkey;
  fd_solana_account_meta_t info;
  ulong                    data_sz;
  fd_hash_t                hash;
  /* Account data follows immediately after this struct */
};
typedef struct fd_runtime_public_account_update_msg fd_runtime_public_account_update_msg_t;
#define FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_FOOTPRINT (FD_ACC_SZ_MAX + sizeof(fd_runtime_public_account_update_msg_t))
FD_STATIC_ASSERT( sizeof(fd_runtime_public_account_update_msg_t) == 128, account_update_msg_mtu );

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

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_runtime_public_align( void );

ulong
fd_runtime_public_footprint( ulong spad_mem_max );

void *
fd_runtime_public_new( void * shmem,
                       ulong  spad_mem_max );

fd_runtime_public_t *
fd_runtime_public_join( void * shmem );

/* Returns a local join of the runtime spad */
fd_spad_t *
fd_runtime_public_spad( fd_runtime_public_t const * runtime_public );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_public_h */
