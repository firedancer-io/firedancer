#include "fd_transpile_bind.h"
#include "fd_transpile.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/blake3/fd_blake3.h"

uint
fd_transpile_bind_lookup( fd_pubkey_t const * prog_id,
                          uchar const *       bin,
                          ulong               bin_sz ) {
  for( ulong i=0UL; fd_transpiled_ext[ i ]; i++ ) {
    fd_transpile_export_t const * export = fd_transpiled_ext[ i ];
    if( !fd_pubkey_eq( (fd_pubkey_t const *)export->meta.prog_id, prog_id ) ) continue;
    FD_BASE58_ENCODE_32_BYTES( prog_id->uc, prog_id_b58 );
    if( FD_UNLIKELY( export->abi_version!=FD_TRANSPILE_ABI_VERSION ||
                     export->struct_size!=sizeof(fd_transpile_export_t) ) ) {
      FD_LOG_WARNING(( "transpiled program %s ignored (abi %lu, expected %lu)", prog_id_b58, export->abi_version, FD_TRANSPILE_ABI_VERSION ));
      continue;
    }
    uchar hash[ 32 ];
    fd_blake3_hash( bin, bin_sz, hash );
    if( FD_UNLIKELY( memcmp( hash, export->meta.elf_hash, 32UL ) ) ) {
      FD_LOG_NOTICE(( "transpiled program %s ignored (ELF differs)", prog_id_b58 ));
      continue;
    }
    FD_LOG_NOTICE(( "transpiled program %s bound", prog_id_b58 ));
    return (uint)( i+1UL );
  }
  return 0U;
}

void
fd_transpile_bind_unbind( fd_progcache_rec_t * rec,
                          char const *         reason ) {
  FD_VOLATILE( rec->transpiled_idx ) = 0U;
  FD_BASE58_ENCODE_32_BYTES( rec->pair.prog.uc, prog_id_b58 );
  FD_LOG_NOTICE(( "transpiled program %s unbound (%s)", prog_id_b58, reason ));
}
