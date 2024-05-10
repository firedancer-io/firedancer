/**
 * Provides utility methods to create txn templates for
 * pre-staging, as well as a mechanism to build out an 
 * entire transaction with instructions.
*/

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../flamenco/types/fd_types.h"

#define SIGNATURE_SZ 64
#define ACCOUNT_SZ   32
#define BLOCKHASH_SZ 32

/**
 * Struct used to define a list of accounts supplied in a txn.
 * Also provides information on number of signers/writeable accounts.
*/
struct fd_txn_accounts {
  ulong signature_cnt;
  ulong readonly_signed_cnt;
  ulong readonly_unsigned_cnt;
  ulong acct_cnt;
  fd_pubkey_t * signers_w;
  fd_pubkey_t * signers_r;
  fd_pubkey_t * non_signers_w;
  fd_pubkey_t * non_signers_r;
};

typedef struct fd_txn_accounts fd_txn_accounts_t;

// Message header type
struct __attribute__((packed)) fd_txn_message_hdr {
  uchar num_signatures;
  uchar num_readonly_signatures;
  uchar num_readonly_unsigned;
};

typedef struct fd_txn_message_hdr fd_txn_message_hdr_t;

/**
 * Instruction builder function signature. Accepts an output buffer and optional argument.
 * Returns the size of the instruction.
 * An example of such a function used for testing:
 * 
 ushort build_vote_state_update_instr( uchar * out_buf, uchar * FD_PARAM_UNUSED opt_args, ulong FD_PARAM_UNUSED opt_args_len ) {
    fd_vote_instruction_t vote_instr;
    vote_instr.discriminant = fd_vote_instruction_enum_update_vote_state;
    fd_vote_state_update_t update;
    memset(&update, 0, sizeof(fd_vote_state_update_t));
    getrandom( update.hash.key, 32UL, 0 );
    ulong ts = (ulong)fd_log_wallclock();
    update.timestamp = &ts;
    vote_instr.inner.update_vote_state = update;
    fd_bincode_encode_ctx_t encode = {.data = out_buf, .dataend = (out_buf + FD_TXN_MTU)};
    fd_vote_instruction_encode( &vote_instr, &encode );
    (void) opt_args;
    (void) opt_args_len;
    return (ushort)fd_vote_instruction_size( &vote_instr );
}
**/
typedef ushort (*fd_build_instr_fun)( uchar * buf_out, uchar * opt_arg, ulong arg_sz );

FD_PROTOTYPES_BEGIN

/**
 * Method used to create a template for a txn (useful for pre-staging and re-use)
*/
ulong fd_txn_base_generate( uchar out_txn_meta[ static FD_TXN_MAX_SZ ],
                            uchar out_txn_payload[ static FD_TXN_MTU ],
                            ulong num_signatures,
                            fd_txn_accounts_t * accounts,
                            uchar * opt_recent_blockhash );

/**
 * Method used for adding an instruction to a txn being generated.
*/
ulong fd_txn_add_instr( uchar * txn_meta_ptr,
                        uchar out_txn_payload[ static FD_TXN_MTU ],
                        uchar program_id,
                        uchar * accounts,
                        ulong accounts_len,
                        fd_build_instr_fun instr_fun,
                        uchar * opt_build_args,
                        ulong opt_args_len );
FD_PROTOTYPES_END
