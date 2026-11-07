#include "fd_jit_arena.h"
#include "fd_transpile.h"
#include "../fd_vm_private.h"
#include "../syscall/fd_vm_syscall.h"
#include "../../../ballet/base58/fd_base58.h"

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
  memset( (uchar *)mem + arena->code_off, 0xcc, arena->code_max ); /* int3 */
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

/* Veneers: 16 bytes each, entered by `call rel32` from transpiled code
   with r12 = fd_vm_t * (and rdi = vm as first argument).

     mov rax, [r12+disp32]      49 8b 84 24 <disp32>
     jmp qword [rax+disp32]     ff a0 <disp32>
     int3 x2                    cc cc

   For syscalls rax = vm->syscalls and the second disp picks the slot's
   func pointer; for runtime helpers rax = vm->transpiled.rt (an
   fd_transpile_rt_t) and the second disp picks the helper. */

#define VENEER_SZ (16UL)

static void
veneer_emit( uchar * p,
             uint    disp_a,
             uint    disp_b ) {
  p[0] = 0x49; p[1] = 0x8b; p[2] = 0x84; p[3] = 0x24;
  FD_STORE( uint, p+4, disp_a );
  p[8] = 0xff; p[9] = 0xa0;
  FD_STORE( uint, p+10, disp_b );
  p[14] = 0xcc; p[15] = 0xcc;
}

static int
rel32_patch( uchar * site,
             ulong   s,
             long    a ) {
  long v = (long)s + a - (long)site;
  if( FD_UNLIKELY( v<(long)INT_MIN || v>(long)INT_MAX ) ) return -1;
  FD_STORE( int, site, (int)v );
  return 0;
}

#define EXT_MAX (FD_VM_TRANSPILE_SYM_MAX+FD_SBPF_SYSCALLS_SLOT_CNT)

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
    return -1L;
  }
  ulong code_off, rodata_off, reloc_off, rodata_reloc_off;
  ulong need = fd_jit_res_layout( res, &code_off, &rodata_off, &reloc_off, &rodata_reloc_off );
  if( FD_UNLIKELY( need>frag_sz ) ) {
    FD_LOG_WARNING(( "jit %s: short response (%lu<%lu)", prog_b58, frag_sz, need ));
    return -1L;
  }
  uchar const *         code         = frag + code_off;
  uchar const *         rodata       = frag + rodata_off;
  fd_elf64_rela const * reloc        = (fd_elf64_rela const *)( frag + reloc_off );
  fd_elf64_rela const * rodata_reloc = (fd_elf64_rela const *)( frag + rodata_reloc_off );

  /* Same ELF, same feature set => same code.  Reuse. */

  for( ulong i=0UL; i<arena->slot_cnt; i++ ) {
    fd_jit_slot_t const * s = &arena->slot[ i ];
    if( !memcmp( s->prog_id, res->meta.prog_id, 32UL ) && !memcmp( s->image_hash, res->meta.elf_hash, 32UL ) &&
        s->feature_slot==res->feature_slot ) {
      if( opt_dedup ) *opt_dedup = 1;
      return (long)i;
    }
  }
  if( FD_UNLIKELY( arena->slot_cnt>=FD_JIT_ARENA_SLOT_MAX ) ) {
    FD_LOG_WARNING(( "jit %s: arena slot table full", prog_b58 ));
    return -1L;
  }

  /* Validate relocations against the syscall table the program was
     compiled with, and collect the external symbols it needs. */

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  if( FD_UNLIKELY( fd_vm_syscall_register_slot( syscalls, res->feature_slot, &res->features, 0 )!=FD_VM_SUCCESS ) ) {
    FD_LOG_WARNING(( "jit %s: syscall registration failed", prog_b58 ));
    return -1L;
  }

  uint  ext_idx[ EXT_MAX ];
  uint  ext_sym[ EXT_MAX ];
  ulong ext_cnt = 0UL;
  memset( ext_idx, 0xff, sizeof(ext_idx) );
  for( ulong i=0UL; i<res->reloc_cnt; i++ ) {
    uint sym = FD_ELF64_R_SYM ( reloc[i].r_info );
    uint typ = FD_ELF64_R_TYPE( reloc[i].r_info );
    if( FD_UNLIKELY( reloc[i].r_offset+4UL>res->code_sz ) ) {
      FD_LOG_WARNING(( "jit %s: reloc %lu out of bounds", prog_b58, i ));
      return -1L;
    }
    if( typ==FD_ELF_R_X86_64_PC32 ) {
      if( FD_UNLIKELY( sym!=FD_VM_TRANSPILE_SYM_TEXT && sym!=FD_VM_TRANSPILE_SYM_RODATA ) ) {
        FD_LOG_WARNING(( "jit %s: bad PC32 sym %u", prog_b58, sym ));
        return -1L;
      }
      continue;
    }
    if( FD_UNLIKELY( typ!=FD_ELF_R_X86_64_PLT32 || sym>=EXT_MAX ) ) {
      FD_LOG_WARNING(( "jit %s: bad reloc type %u sym %u", prog_b58, typ, sym ));
      return -1L;
    }
    int known = ( sym==FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ) | ( sym==FD_VM_TRANSPILE_SYM_FRAME_INIT ) |
                ( sym>=FD_VM_TRANSPILE_SYM_MAX && !!syscalls[ sym-FD_VM_TRANSPILE_SYM_MAX ].func );
    if( FD_UNLIKELY( !known ) ) {
      FD_LOG_WARNING(( "jit %s: call to unknown sym %u", prog_b58, sym ));
      return -1L;
    }
    if( ext_idx[ sym ]!=UINT_MAX ) continue;
    ext_idx[ sym ]     = (uint)ext_cnt;
    ext_sym[ ext_cnt ] = sym;
    ext_cnt++;
  }
  for( ulong i=0UL; i<res->rodata_reloc_cnt; i++ ) {
    fd_elf64_rela const * r = &rodata_reloc[ i ];
    if( FD_UNLIKELY( FD_ELF64_R_TYPE( r->r_info )!=FD_ELF_R_X86_64_PC32 ||
                     FD_ELF64_R_SYM ( r->r_info )!=FD_VM_TRANSPILE_SYM_TEXT ||
                     r->r_offset+4UL>res->rodata_sz ) ) {
      FD_LOG_WARNING(( "jit %s: bad rodata reloc %lu", prog_b58, i ));
      return -1L;
    }
  }

  /* Extent layout */

  ulong veneer_off = fd_ulong_align_up( res->code_sz, 16UL );
  ulong tables_off = fd_ulong_align_up( veneer_off + ext_cnt*VENEER_SZ, 64UL );
  ulong prog_sz    = fd_ulong_align_up( tables_off + res->rodata_sz, 64UL );
  if( FD_UNLIKELY( arena->code_used+prog_sz>arena->code_max ) ) {
    FD_LOG_WARNING(( "jit %s: arena full (%lu+%lu>%lu)", prog_b58, arena->code_used, prog_sz, arena->code_max ));
    return -1L;
  }
  uchar * base   = (uchar *)arena + arena->code_off + arena->code_used;
  uchar * text   = base;
  uchar * tables = base + tables_off;

  memcpy( text,   code,   res->code_sz   );
  memcpy( tables, rodata, res->rodata_sz );

  for( ulong i=0UL; i<ext_cnt; i++ ) {
    uint sym = ext_sym[ i ];
    uchar * v = text + veneer_off + i*VENEER_SZ;
    if( sym>=FD_VM_TRANSPILE_SYM_MAX ) {
      ulong slot = sym-FD_VM_TRANSPILE_SYM_MAX;
      veneer_emit( v, (uint)offsetof( fd_vm_t, syscalls ), (uint)( slot*sizeof(fd_sbpf_syscalls_t) + offsetof( fd_sbpf_syscalls_t, func ) ) );
    } else {
      ulong rt_off = sym==FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ? offsetof( fd_transpile_rt_t, mmu_translate )
                                                              : offsetof( fd_transpile_rt_t, frame_init );
      veneer_emit( v, (uint)offsetof( fd_vm_t, transpiled.rt ), (uint)rt_off );
    }
  }

  for( ulong i=0UL; i<res->reloc_cnt; i++ ) {
    uint  sym = FD_ELF64_R_SYM ( reloc[i].r_info );
    uint  typ = FD_ELF64_R_TYPE( reloc[i].r_info );
    ulong s;
    if(      typ==FD_ELF_R_X86_64_PLT32            ) s = (ulong)( text + veneer_off + ext_idx[ sym ]*VENEER_SZ );
    else if( sym==FD_VM_TRANSPILE_SYM_RODATA       ) s = (ulong)tables;
    else                                             s = (ulong)text;
    if( FD_UNLIKELY( rel32_patch( text + reloc[i].r_offset, s, reloc[i].r_addend ) ) ) goto reach;
  }
  for( ulong i=0UL; i<res->rodata_reloc_cnt; i++ ) {
    if( FD_UNLIKELY( rel32_patch( tables + rodata_reloc[i].r_offset, (ulong)text, rodata_reloc[i].r_addend ) ) ) goto reach;
  }

  ulong idx = arena->slot_cnt;
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
  FD_VOLATILE( arena->slot_cnt ) = idx+1UL;
  return (long)idx;

reach:
  FD_LOG_WARNING(( "jit %s: rel32 out of reach", prog_b58 ));
  memset( base, 0xcc, prog_sz );
  return -1L;
}
