#include "fd_transpile_bind.h"
#include "fd_transpile.h"
#include "fd_jit_arena.h"
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

fd_transpile_bind_t *
fd_transpile_bind_jit_init( fd_transpile_bind_t *      bind,
                            void *                     arena_mem,
                            void *                     heat_mem,
                            ulong                      row_idx,
                            fd_progcache_rec_t const * rec0,
                            ulong                      rec_max ) {
  fd_jit_arena_t * arena = fd_jit_arena_join( arena_mem );
  fd_jit_heat_t *  heat  = fd_jit_heat_join ( heat_mem  );
  if( FD_UNLIKELY( !arena || !heat || row_idx>=heat->row_cnt || heat->rec_max!=rec_max ) ) return NULL;
  bind->arena   = arena;
  bind->heat    = fd_jit_heat_row( heat, row_idx );
  bind->rec0    = rec0;
  bind->rec_max = rec_max;
  return bind;
}

fd_vm_transpiled_exec_func_t
fd_transpile_bind_exec( fd_transpile_bind_t const * bind,
                        fd_progcache_rec_t const *  rec ) {
  uint idx = FD_VOLATILE_CONST( rec->transpiled_idx );
  if( !idx || ( idx & FD_TRANSPILE_BIND_HOLD ) ) return NULL;
  if( idx & FD_TRANSPILE_BIND_JIT ) {
    if( FD_UNLIKELY( !bind || !bind->arena ) ) return NULL;
    ulong slot = idx & ~FD_TRANSPILE_BIND_JIT;
    if( FD_UNLIKELY( slot>=FD_VOLATILE_CONST( bind->arena->slot_cnt ) ) ) return NULL;
    return fd_jit_arena_exec( bind->arena, slot );
  }
  return fd_transpiled_ext[ idx-1U ]->exec;
}

void
fd_transpile_bind_unbind( fd_progcache_rec_t * rec,
                          char const *         reason ) {
  FD_VOLATILE( rec->transpiled_idx ) = FD_TRANSPILE_BIND_HOLD;
  FD_BASE58_ENCODE_32_BYTES( rec->pair.prog.uc, prog_id_b58 );
  FD_LOG_NOTICE(( "transpiled program %s unbound (%s)", prog_id_b58, reason ));
}
