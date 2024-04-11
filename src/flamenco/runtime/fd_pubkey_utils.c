#include "fd_pubkey_utils.h"

int
fd_pubkey_create_with_seed( fd_exec_instr_ctx_t const * ctx,
                            uchar const                 base [ static 32 ],
                            char const *                seed,
                            ulong                       seed_sz,
                            uchar const                 owner[ static 32 ],
                            uchar                       out  [ static 32 ] ) {

  static char const pda_marker[] = {"ProgramDerivedAddress"};

  if( seed_sz > 32UL ) {
    ctx->txn_ctx->custom_err = 0;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if( 0==memcmp( owner+11, pda_marker, 21UL ) ) {
    ctx->txn_ctx->custom_err = 2;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  fd_sha256_append( &sha, base,  32UL    );
  fd_sha256_append( &sha, seed,  seed_sz );
  fd_sha256_append( &sha, owner, 32UL    );

  fd_sha256_fini( &sha, out );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
