#include "fd_acc_mgr.h"
#include "context/fd_exec_slot_ctx.h"

#define FD_BANK_MGR_SUCCESS (0)
#define FD_BANK_MGR_FAILURE (-1)
#define FD_BANK_MGR_XID_1   (0xF11777777DDDDUL)
#define BLOCK_HASH_QUEUE_ID (0UL)


/* TODO: Make this struct private. */
struct fd_bank_mgr_prepare {
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_query_t   query[1];
  uchar *               data;
  ulong                 entry_id;
};
typedef struct fd_bank_mgr_prepare fd_bank_mgr_prepare_t;

static uchar * FD_FN_UNUSED
fd_bank_mgr_get_data( fd_bank_mgr_prepare_t * prepare ) {
  return prepare->data;
}

int
fd_bank_mgr_prepare_entry( fd_funk_t *             funk,
                           fd_funk_txn_t *         funk_txn,
                           ulong                   entry_id,
                           ulong                   sz,
                           fd_bank_mgr_prepare_t * prepare );

int
fd_bank_mgr_publish_entry( fd_bank_mgr_prepare_t * prepare );

int
fd_bank_mgr_create_entry( fd_funk_t *     funk,
                          fd_funk_txn_t * funk_txn,
                          ulong           entry_id,
                          uchar *         entry_data,
                          ulong           entry_data_sz );

int
fd_bank_mgr_entry_query_const( fd_funk_t *     funk,
                               fd_funk_txn_t * funk_txn,
                               ulong           entry_id,
                               uchar * *       out_entry_data,
                               ulong *         out_entry_data_sz );
