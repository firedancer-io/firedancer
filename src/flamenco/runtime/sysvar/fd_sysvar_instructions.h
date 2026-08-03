#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h

#include "../../fd_flamenco_base.h"
#include "../../accdb/fd_accdb.h"
#include "../../../ballet/txn/fd_txn.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_instructions_offsets_overflow returns 1 if serializing the
   instructions sysvar for the given txn would cause the offset to
   overflow. This is only possible for V1 transactions. This mirrors
   Agave's semantics.

   https://github.com/anza-xyz/solana-sdk/blob/instructions-sysvar@v4.0.0/instructions-sysvar/src/lib.rs#L97-L156 */
FD_FN_PURE static inline int
fd_sysvar_instructions_offsets_overflow( fd_txn_t const * txn ) {
  ulong off = sizeof(ushort) + (ulong)sizeof(ushort)*txn->instr_cnt;
  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    if( FD_UNLIKELY( off>(ulong)USHORT_MAX ) ) return 1;
    off += sizeof(ushort)
         + (ulong)txn->instr[i].acct_cnt*( sizeof(uchar)+sizeof(fd_pubkey_t) )
         + sizeof(fd_pubkey_t) + sizeof(ushort) + txn->instr[i].data_sz;
  }
  return 0;
}

int
fd_sysvar_instructions_serialize_account( fd_txn_in_t const * txn_in,
                                          fd_txn_out_t *      txn_out,
                                          ulong               txn_idx );

void
fd_sysvar_instructions_update_current_instr_idx( fd_acc_t * acc,
                                                 ushort     current_instr_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_instructions_h */
