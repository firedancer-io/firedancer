#include "fd_jit_arena.h"
#include "fd_transpile.h"
#include "fd_transpile_target.h"
#include "../fd_vm_private.h"
#include "../syscall/fd_vm_syscall.h"
#include "../../../ballet/base58/fd_base58.h"

#if FD_HAS_HOSTED
#include <errno.h>
#include <sys/mman.h>
#endif

void *
fd_jit_arena_new( void * mem,
                  ulong  code_max ) {
  if( FD_UNLIKELY( !mem || !fd_ulong_is_aligned( (ulong)mem, FD_JIT_ARENA_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad mem" ));
    return NULL;
  }
  fd_jit_arena_t * arena = mem;
  memset( arena, 0, sizeof(fd_jit_arena_t) );
  arena->code_off = fd_ulong_align_up( sizeof(fd_jit_arena_t), FD_JIT_ARENA_ALIGN );
  arena->code_max = fd_ulong_align_up( code_max, FD_JIT_ARENA_ALIGN );
  arena->free_cnt = 1UL;
  arena->free[ 0 ] = (fd_jit_extent_t){ .off = 0UL, .sz = arena->code_max };
  fd_transpile_trap_fill( (uchar *)mem + arena->code_off, arena->code_max );
  FD_COMPILER_MFENCE();
  arena->magic = FD_JIT_ARENA_MAGIC;
  return mem;
}

fd_jit_arena_t *
fd_jit_arena_join( void * mem ) {
  fd_jit_arena_t * arena = mem;
  if( FD_UNLIKELY( !arena || arena->magic!=FD_JIT_ARENA_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return arena;
}

#if FD_HAS_HOSTED

void
fd_jit_arena_protect_exec( void * mem ) {
  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( mem, 1UL, info ) ) ) FD_LOG_ERR(( "jit arena is not in a joined workspace" ));
  int prot = PROT_READ|PROT_EXEC|( info->mode==FD_SHMEM_JOIN_MODE_READ_WRITE ? PROT_WRITE : 0 );
  if( FD_UNLIKELY( mprotect( info->shmem, info->page_sz*info->page_cnt, prot ) ) )
    FD_LOG_ERR(( "mprotect(jit arena,%s) failed (%i-%s)", prot&PROT_WRITE ? "rwx" : "r-x", errno, fd_io_strerror( errno ) ));
}

#endif /* FD_HAS_HOSTED */

/* Veneers (fd_transpile_veneer_vm) load a pointer from the fd_vm_t and
   tail jump through a function pointer in it.  For syscalls that is
   vm->syscalls and the slot's func pointer; for runtime helpers it is
   vm->transpiled.rt (an fd_transpile_rt_t) and the helper. */

#define VENEER_SZ FD_TRANSPILE_VENEER_SZ

#define EXT_MAX (FD_VM_TRANSPILE_SYM_MAX+FD_SBPF_SYSCALLS_SLOT_CNT)

long
fd_jit_arena_find( fd_jit_arena_t const * arena,
                   uchar const *          prog_id,
                   uchar const *          image_hash,
                   ulong                  feature_slot ) {
  for( ulong i=0UL; i<arena->slot_cnt; i++ ) {
    fd_jit_slot_t const * s = &arena->slot[ i ];
    if( s->prog_sz && s->feature_slot==feature_slot &&
        !memcmp( s->prog_id, prog_id, 32UL ) && !memcmp( s->image_hash, image_hash, 32UL ) ) return (long)i;
  }
  return -1L;
}

void
fd_jit_arena_free( fd_jit_arena_t * arena,
                   ulong            slot_idx ) {
  FD_TEST( slot_idx<arena->slot_cnt );
  fd_jit_slot_t * slot = &arena->slot[ slot_idx ];
  ulong off = slot->prog_off - arena->code_off;
  ulong sz  = slot->prog_sz;
  FD_TEST( sz );

  uchar * base = (uchar *)arena + slot->prog_off;
  fd_transpile_trap_fill( base, sz );
  fd_transpile_icache_flush( base, sz );

  fd_jit_extent_t * f = arena->free;
  ulong             n = arena->free_cnt;
  ulong             i = 0UL;
  while( i<n && f[ i ].off<off ) i++;
  int join_prev = i>0UL && f[ i-1UL ].off+f[ i-1UL ].sz==off;
  int join_next = i<n   && off+sz==f[ i ].off;
  if( join_prev && join_next ) {
    f[ i-1UL ].sz += sz + f[ i ].sz;
    memmove( f+i, f+i+1UL, (n-i-1UL)*sizeof(fd_jit_extent_t) );
    arena->free_cnt = n-1UL;
  } else if( join_prev ) {
    f[ i-1UL ].sz += sz;
  } else if( join_next ) {
    f[ i ].off = off;
    f[ i ].sz += sz;
  } else {
    memmove( f+i+1UL, f+i, (n-i)*sizeof(fd_jit_extent_t) );
    f[ i ] = (fd_jit_extent_t){ .off = off, .sz = sz };
    arena->free_cnt = n+1UL;
  }

  slot->prog_sz = 0UL;
  arena->code_used -= sz;
  arena->prog_cnt--;
}

long
fd_jit_arena_place( fd_jit_arena_t *     arena,
                    fd_jit_res_t const * res,
                    uchar const *        frag,
                    ulong                frag_sz,
                    int *                opt_dedup ) {
  FD_BASE58_ENCODE_32_BYTES( res->meta.prog_id, prog_b58 );
  if( opt_dedup ) *opt_dedup = 0;

  if( FD_UNLIKELY( res->code_sz>FD_JIT_RES_CODE_MAX || res->rodata_sz>FD_JIT_RES_RODATA_MAX ||
                   res->reloc_cnt>FD_JIT_RES_RELOC_MAX || res->rodata_reloc_cnt>FD_JIT_RES_RODATA_RELOC_MAX ||
                   res->entrypoint_off>=res->code_sz ) ) {
    FD_LOG_WARNING(( "jit %s: malformed response (code %lu rodata %lu reloc %lu/%lu entry %lu)",
                     prog_b58, res->code_sz, res->rodata_sz, res->reloc_cnt, res->rodata_reloc_cnt, res->entrypoint_off ));
    return FD_JIT_ARENA_ERR_INVAL;
  }
  ulong code_off, rodata_off, reloc_off, rodata_reloc_off;
  ulong need = fd_jit_res_layout( res, &code_off, &rodata_off, &reloc_off, &rodata_reloc_off );
  if( FD_UNLIKELY( need>frag_sz ) ) {
    FD_LOG_WARNING(( "jit %s: short response (%lu<%lu)", prog_b58, frag_sz, need ));
    return FD_JIT_ARENA_ERR_INVAL;
  }
  uchar const *         code         = frag + code_off;
  uchar const *         rodata       = frag + rodata_off;
  fd_elf64_rela const * reloc        = (fd_elf64_rela const *)( frag + reloc_off );
  fd_elf64_rela const * rodata_reloc = (fd_elf64_rela const *)( frag + rodata_reloc_off );

  /* Same ELF, same feature set => same code.  Reuse. */

  long hit = fd_jit_arena_find( arena, res->meta.prog_id, res->meta.elf_hash, res->feature_slot );
  if( hit>=0L ) {
    if( opt_dedup ) *opt_dedup = 1;
    return hit;
  }
  ulong idx = 0UL;
  while( idx<arena->slot_cnt && arena->slot[ idx ].prog_sz ) idx++;
  if( FD_UNLIKELY( idx>=FD_JIT_ARENA_SLOT_MAX ) ) return FD_JIT_ARENA_ERR_FULL;

  /* Validate relocations against the syscall table the program was
     compiled with, and collect the external symbols it needs. */

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  if( FD_UNLIKELY( fd_vm_syscall_register_slot( syscalls, res->feature_slot, &res->features, 0 )!=FD_VM_SUCCESS ) ) {
    FD_LOG_WARNING(( "jit %s: syscall registration failed", prog_b58 ));
    return FD_JIT_ARENA_ERR_INVAL;
  }

  uint  ext_idx[ EXT_MAX ];
  uint  ext_sym[ EXT_MAX ];
  ulong ext_cnt = 0UL;
  memset( ext_idx, 0xff, sizeof(ext_idx) );
  for( ulong i=0UL; i<res->reloc_cnt; i++ ) {
    uint sym = FD_ELF64_R_SYM ( reloc[i].r_info );
    uint typ = FD_ELF64_R_TYPE( reloc[i].r_info );
    int  kind = fd_transpile_reloc_kind( typ );
    if( FD_UNLIKELY( reloc[i].r_offset+FD_TRANSPILE_RELOC_SZ>res->code_sz ) ) {
      FD_LOG_WARNING(( "jit %s: reloc %lu out of bounds", prog_b58, i ));
      return FD_JIT_ARENA_ERR_INVAL;
    }
    if( kind==FD_TRANSPILE_RELOC_ADDR ) {
      if( FD_UNLIKELY( sym!=FD_VM_TRANSPILE_SYM_TEXT && sym!=FD_VM_TRANSPILE_SYM_RODATA ) ) {
        FD_LOG_WARNING(( "jit %s: bad address reloc sym %u", prog_b58, sym ));
        return FD_JIT_ARENA_ERR_INVAL;
      }
      continue;
    }
    if( FD_UNLIKELY( kind!=FD_TRANSPILE_RELOC_CALL || sym>=EXT_MAX ) ) {
      FD_LOG_WARNING(( "jit %s: bad reloc type %u sym %u", prog_b58, typ, sym ));
      return FD_JIT_ARENA_ERR_INVAL;
    }
    int known = ( sym==FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ) | ( sym==FD_VM_TRANSPILE_SYM_FRAME_INIT ) |
                ( sym>=FD_VM_TRANSPILE_SYM_MAX && !!syscalls[ sym-FD_VM_TRANSPILE_SYM_MAX ].func );
    if( FD_UNLIKELY( !known ) ) {
      FD_LOG_WARNING(( "jit %s: call to unknown sym %u", prog_b58, sym ));
      return FD_JIT_ARENA_ERR_INVAL;
    }
    if( ext_idx[ sym ]!=UINT_MAX ) continue;
    ext_idx[ sym ]     = (uint)ext_cnt;
    ext_sym[ ext_cnt ] = sym;
    ext_cnt++;
  }
  for( ulong i=0UL; i<res->rodata_reloc_cnt; i++ ) {
    fd_elf64_rela const * r = &rodata_reloc[ i ];
    if( FD_UNLIKELY( FD_ELF64_R_TYPE( r->r_info )!=FD_TRANSPILE_R_PCREL32 ||
                     FD_ELF64_R_SYM ( r->r_info )!=FD_VM_TRANSPILE_SYM_TEXT ||
                     r->r_offset+FD_TRANSPILE_RELOC_SZ>res->rodata_sz ) ) {
      FD_LOG_WARNING(( "jit %s: bad rodata reloc %lu", prog_b58, i ));
      return FD_JIT_ARENA_ERR_INVAL;
    }
  }

  /* Extent layout */

  ulong veneer_off = fd_ulong_align_up( res->code_sz, 16UL );
  ulong tables_off = fd_ulong_align_up( veneer_off + ext_cnt*VENEER_SZ, 64UL );
  ulong prog_sz    = fd_ulong_align_up( tables_off + res->rodata_sz, 64UL );
  ulong free_idx = 0UL;
  while( free_idx<arena->free_cnt && arena->free[ free_idx ].sz<prog_sz ) free_idx++;
  if( FD_UNLIKELY( free_idx>=arena->free_cnt ) ) return FD_JIT_ARENA_ERR_FULL;
  uchar * base   = (uchar *)arena + arena->code_off + arena->free[ free_idx ].off;
  uchar * text   = base;
  uchar * tables = base + tables_off;

  memcpy( text,   code,   res->code_sz   );
  memcpy( tables, rodata, res->rodata_sz );

  for( ulong i=0UL; i<ext_cnt; i++ ) {
    uint sym = ext_sym[ i ];
    uchar * v = text + veneer_off + i*VENEER_SZ;
    if( sym>=FD_VM_TRANSPILE_SYM_MAX ) {
      ulong slot = sym-FD_VM_TRANSPILE_SYM_MAX;
      fd_transpile_veneer_vm( v, (uint)offsetof( fd_vm_t, syscalls ), (uint)( slot*sizeof(fd_sbpf_syscalls_t) + offsetof( fd_sbpf_syscalls_t, func ) ) );
    } else {
      ulong rt_off = sym==FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ? offsetof( fd_transpile_rt_t, mmu_translate )
                                                              : offsetof( fd_transpile_rt_t, frame_init );
      fd_transpile_veneer_vm( v, (uint)offsetof( fd_vm_t, transpiled.rt ), (uint)rt_off );
    }
  }

  for( ulong i=0UL; i<res->reloc_cnt; i++ ) {
    uint  sym = FD_ELF64_R_SYM ( reloc[i].r_info );
    uint  typ = FD_ELF64_R_TYPE( reloc[i].r_info );
    ulong s;
    if(      fd_transpile_reloc_kind( typ )==FD_TRANSPILE_RELOC_CALL ) s = (ulong)( text + veneer_off + ext_idx[ sym ]*VENEER_SZ );
    else if( sym==FD_VM_TRANSPILE_SYM_RODATA                         ) s = (ulong)tables;
    else                                                               s = (ulong)text;
    if( FD_UNLIKELY( fd_transpile_reloc_apply( text + reloc[i].r_offset, typ, s, reloc[i].r_addend ) ) ) goto reach;
  }
  for( ulong i=0UL; i<res->rodata_reloc_cnt; i++ ) {
    if( FD_UNLIKELY( fd_transpile_reloc_apply( tables + rodata_reloc[i].r_offset, FD_TRANSPILE_R_PCREL32, (ulong)text, rodata_reloc[i].r_addend ) ) ) goto reach;
  }
  fd_transpile_icache_flush( text, tables_off );

  fd_jit_extent_t * ext = &arena->free[ free_idx ];
  ext->off += prog_sz;
  ext->sz  -= prog_sz;
  if( !ext->sz ) {
    memmove( ext, ext+1, (arena->free_cnt-free_idx-1UL)*sizeof(fd_jit_extent_t) );
    arena->free_cnt--;
  }

  fd_jit_slot_t * slot = &arena->slot[ idx ];
  slot->entry_off    = (ulong)( text - (uchar *)arena ) + res->entrypoint_off;
  slot->prog_off     = (ulong)( base - (uchar *)arena );
  slot->prog_sz      = prog_sz;
  slot->feature_slot = res->feature_slot;
  memcpy( slot->prog_id,  res->meta.prog_id,  32UL );
  memcpy( slot->image_hash, res->meta.elf_hash, 32UL );
  arena->code_used += prog_sz;
  arena->prog_cnt++;
  FD_COMPILER_MFENCE();
  if( idx==arena->slot_cnt ) FD_VOLATILE( arena->slot_cnt ) = idx+1UL;
  return (long)idx;

reach:
  FD_LOG_WARNING(( "jit %s: relocation out of reach", prog_b58 ));
  fd_transpile_trap_fill( base, prog_sz );
  return FD_JIT_ARENA_ERR_INVAL;
}
