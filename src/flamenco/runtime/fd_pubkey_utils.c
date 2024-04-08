#include "fd_pubkey_utils.h"

#include "fd_executor.h"
#include "fd_runtime.h"


const size_t MAX_SEED_LEN = 32;
const char PDA_MARKER[] = {"ProgramDerivedAddress"};

int
fd_pubkey_create_with_seed( uchar const  base [ static 32 ],
                            char const * seed,
                            ulong        seed_sz,
                            uchar const  owner[ static 32 ],
                            uchar        out  [ static 32 ] ) {
//  if seed.len() > MAX_SEED_LEN {
//      return Err(PubkeyError::MaxSeedLengthExceeded);
//    }

  if (seed_sz > MAX_SEED_LEN)
    return FD_EXECUTOR_SYSTEM_ERR_MAX_SEED_LENGTH_EXCEEDED;

  if( memcmp( &owner[32UL - sizeof(PDA_MARKER)-1], PDA_MARKER, sizeof(PDA_MARKER)-1 ) == 0)
    return FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER;
//  let owner = owner.as_ref();
//  if owner.len() >= PDA_MARKER.len() {
//      let slice = &owner[owner.len() - PDA_MARKER.len()..];
//      if slice == PDA_MARKER {
//          return Err(PubkeyError::IllegalOwner);
//        }
//    }

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  fd_sha256_append( &sha, base,  32UL    );
  fd_sha256_append( &sha, seed,  seed_sz );
  fd_sha256_append( &sha, owner, 32UL    );

  fd_sha256_fini( &sha, out );

//  Ok(Pubkey::new(
//      hashv(&[base.as_ref(), seed.as_ref(), owner]).as_ref(),
//      ))

  return FD_RUNTIME_EXECUTE_SUCCESS;
}
