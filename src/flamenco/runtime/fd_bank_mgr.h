#include "fd_acc_mgr.h"
#include "context/fd_exec_slot_ctx.h"

#define FD_BANK_MGR_XID_1   (0xF11777777DDDDUL)
#define BLOCK_HASH_QUEUE_ID (0UL)

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
                               uchar const * * out_entry_data,
                               ulong *         out_entry_data_sz );
