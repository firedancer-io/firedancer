#ifndef HEADER_fd_src_flamenco_txn_fd_txn_generate_h
#define HEADER_fd_src_flamenco_txn_fd_txn_generate_h

/* Provides utility methods to create txn templates for
   pre-staging, as well as a mechanism to build out an
   entire transaction with instructions. */

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../flamenco/types/fd_types.h"

/* Struct used to define a list of accounts supplied in a txn.
   Also provides information on number of signers/writeable accounts. */
struct fd_txn_accounts {
  /* signature cnt <= 128 */
  uchar  signature_cnt;
  /* readonly signed/unsigned <= 128 */
  uchar  readonly_signed_cnt;
  uchar  readonly_unsigned_cnt;
  ushort acct_cnt;
  fd_pubkey_t * signers_w;
  fd_pubkey_t * signers_r;
  fd_pubkey_t * non_signers_w;
  fd_pubkey_t * non_signers_r;
};

typedef struct fd_txn_accounts fd_txn_accounts_t;

FD_PROTOTYPES_BEGIN

/* Method used to create a template for a txn (useful for pre-staging and re-use)
   Num signatures is restricted to < 128. Returns the offset to the start of the
   insructions. */
ulong
fd_txn_base_generate( uchar out_txn_meta[ static FD_TXN_MAX_SZ ],
                      uchar out_txn_payload[ static FD_TXN_MTU ],
                      ulong num_signatures,
                      fd_txn_accounts_t * accounts,
                      uchar * opt_recent_blockhash );

/* Method used for adding an instruction to a txn being generated.
   The accounts param is a list of indices to the accounts in the txn.
   The instruction buffer contains the data for the instruction to
   be added. Returns the offset to the start of the instruction added
   in the transaction buffer. */
ulong
fd_txn_add_instr( uchar * txn_meta_ptr,
                  uchar out_txn_payload[ static FD_TXN_MTU ],
                  uchar program_id,
                  uchar const * accounts,
                  ulong accounts_sz,
                  uchar const * instr_buf,
                  ulong instr_buf_sz );

/* Helper method to reset the list of instrs in the metadata and
   remove all instrs from the txn payload. */
void
fd_txn_reset_instrs( uchar * txn_meta_ptr,
                     uchar out_txn_payload[ static FD_TXN_MTU ] );
FD_PROTOTYPES_END

#endif
