#include "fd_pubkey_utils.h"
#include "../vm/fd_vm_syscalls.h"
#include "../../ballet/ed25519/fd_curve25519.h"

int
fd_pubkey_create_with_seed( fd_exec_instr_ctx_t const * ctx,
                            uchar const                 base [ static 32 ],
                            char const *                seed,
                            ulong                       seed_sz,
                            uchar const                 owner[ static 32 ],
                            uchar                       out  [ static 32 ] ) {

  static char const pda_marker[] = {"ProgramDerivedAddress"};

  if( seed_sz>MAX_SEED_LEN ) {
    ctx->txn_ctx->custom_err = 0U;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if( 0==memcmp( owner+11UL, pda_marker, 21UL ) ) {
    ctx->txn_ctx->custom_err = 2U;
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

/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/sdk/program/src/pubkey.rs#L578-L625 */
int
fd_pubkey_derive_pda( fd_pubkey_t const * program_id, 
                      ulong               seeds_cnt, 
                      uchar **            seeds, 
                      uchar *             bump_seed, 
                      fd_pubkey_t *       out ) {

  if( seeds_cnt>MAX_SEEDS ) {
    return FD_PUBKEY_ERR_MAX_SEED_LEN_EXCEEDED;
  }
  /* TODO: This does not contain size checks for the seed as checked in
     https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/sdk/program/src/pubkey.rs#L586-L588 */
                      
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  for ( ulong i=0UL; i<seeds_cnt; i++ ) {
    uchar * seed = *(seeds + i);
    if( FD_UNLIKELY( !seed ) ) {
      break;
    }
    fd_sha256_append( &sha, seed, 32UL );
  }
    
  if( bump_seed ) {
    fd_sha256_append( &sha, bump_seed, 1UL );
  }
  fd_sha256_append( &sha, program_id,              sizeof(fd_pubkey_t) );
  fd_sha256_append( &sha, "ProgramDerivedAddress", 21UL                );

  fd_sha256_fini( &sha, out );

  /* A PDA is valid if it is not a valid ed25519 curve point.
     In most cases the user will have derived the PDA off-chain, 
     or the PDA is a known signer. */
  if( FD_UNLIKELY( fd_ed25519_point_validate( out->key ) ) ) {
    return FD_PUBKEY_ERR_INVALID_SEEDS;
  }

  return FD_PUBKEY_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/sdk/program/src/pubkey.rs#L482-L534 */
int
fd_pubkey_try_find_program_address( fd_pubkey_t const * program_id, 
                                    ulong               seeds_cnt, 
                                    uchar **            seeds, 
                                    fd_pubkey_t *       out,
                                    uchar *             out_bump_seed ) {
  uchar bump_seed[ 1UL ];
  for ( ulong i=0UL; i<256UL; ++i ) {
    bump_seed[ 0UL ] = (uchar)(255UL - i);

    fd_pubkey_t derived[ 1UL ];
    int err = fd_pubkey_derive_pda( program_id, seeds_cnt, seeds, bump_seed, derived );
    if( err==FD_PUBKEY_SUCCESS ) {
      /* Stop looking if we have found a valid PDA */
      fd_memcpy( out, derived, sizeof(fd_pubkey_t) );
      fd_memcpy( out_bump_seed, bump_seed, 1UL );
      break;
    } else if( err!=FD_PUBKEY_ERR_INVALID_SEEDS ) { 
      return err;
    }
  }

  if( out ) {
    return FD_PUBKEY_SUCCESS;
  }
  return FD_PUBKEY_ERR_NO_PDA_FOUND;
}
