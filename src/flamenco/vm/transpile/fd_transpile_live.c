#define _GNU_SOURCE
#include "fd_transpile_live.h"
#include "fd_transpile_runtime.h"
#include "../fd_vm_base.h"
#include "../../../util/rng/fd_rng.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Transpiled code only uses rel32 addressing.  Calls to C functions
   (PLT32 relocs) go through veneers appended to .text, which jump via
   a GOT in .rodata.  This way, the .text and .rodata mappings only need
   to be within +/-2 GiB of each other, not of the host binary.

   .rodata layout:
     fd_transpiled_live_t
     tables     uchar[ t->rodata_sz ] (transpiler rodata, see fd_transpile.h)
     got        ulong[ ext_cnt ]      (absolute addresses of C functions)

   .text layout:
     code       uchar[ code_sz ]      (entrypoint at offset 0)
     veneer     uchar[ ext_cnt ][ 8 ] (jmp qword [rip+got_off]; int3; int3)

   The distance between .text and .rodata is randomized within
   FD_TRANSPILED_LIVE_GAP_MAX. */

#define FD_TRANSPILED_LIVE_MAP_SZ_MAX  (256UL<<20)
#define FD_TRANSPILED_LIVE_GAP_MAX     (1UL<<30)
#define FD_TRANSPILED_LIVE_PLACE_TRIES (64UL)

#define FD_TRANSPILED_LIVE_EXT_MAX (FD_VM_TRANSPILE_SYM_MAX+FD_SBPF_SYSCALLS_SLOT_CNT)
#define FD_TRANSPILED_LIVE_VENEER_SZ (8UL)

static int
rel32_patch( uchar * site,
             ulong   s,
             long    a ) {
  long v = (long)s + a - (long)site;
  if( FD_UNLIKELY( v<(long)INT_MIN || v>(long)INT_MAX ) ) return -1;
  FD_STORE( int, site, (int)v );
  return 0;
}

/* text_map_place maps sz bytes of RW anonymous memory at a random
   page-aligned distance of at most FD_TRANSPILED_LIVE_GAP_MAX from
   the region [ref,ref+ref_sz), without overlapping it. */

static uchar *
text_map_place( ulong ref,
                ulong ref_sz,
                ulong sz ) {
  ulong gap_pages = FD_TRANSPILED_LIVE_GAP_MAX / FD_SHMEM_NORMAL_PAGE_SZ;
  for( ulong try=0UL; try<FD_TRANSPILED_LIVE_PLACE_TRIES; try++ ) {
    ulong r;
    if( FD_UNLIKELY( !fd_rng_secure( &r, sizeof(ulong) ) ) ) return NULL;
    ulong pages = 1UL + ( (r>>1) % gap_pages );
    ulong delta = pages * FD_SHMEM_NORMAL_PAGE_SZ;
    ulong cand;
    if( r&1UL ) {
      cand = ref + ref_sz - FD_SHMEM_NORMAL_PAGE_SZ + delta; /* above */
      if( cand<ref+ref_sz ) continue;
    } else {
      if( delta+sz-FD_SHMEM_NORMAL_PAGE_SZ>ref ) continue;  /* below */
      cand = ref - sz + FD_SHMEM_NORMAL_PAGE_SZ - delta;
    }
    if( cand<(1UL<<20) || cand+sz>(1UL<<47) ) continue;

    void * p = mmap( (void *)cand, sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0 );
    if( p==MAP_FAILED ) {
      if( errno==EEXIST ) continue;
      FD_LOG_WARNING(( "mmap(%#lx,%lu) failed (%i-%s)", cand, sz, errno, fd_io_strerror( errno ) ));
      return NULL;
    }
    if( FD_UNLIKELY( (ulong)p!=cand ) ) { /* kernel without MAP_FIXED_NOREPLACE */
      munmap( p, sz );
      continue;
    }
    return p;
  }
  FD_LOG_WARNING(( "failed to place .text mapping after %lu tries", FD_TRANSPILED_LIVE_PLACE_TRIES ));
  return NULL;
}

fd_transpiled_live_t *
fd_transpiled_live_create( fd_sbpf_program_t const * prog,
                           fd_sbpf_syscalls_t const * syscalls ) {

  if( FD_UNLIKELY( !prog || !syscalls ) ) {
    FD_LOG_WARNING(( "NULL prog or syscalls" ));
    return NULL;
  }
  ulong text_cnt = prog->info.text_cnt;
  if( FD_UNLIKELY( !text_cnt || prog->entry_pc>=text_cnt ) ) {
    FD_LOG_WARNING(( "invalid program text_cnt %lu or entry_pc %lu", text_cnt, prog->entry_pc ));
    return NULL;
  }

  fd_transpiled_live_t * live          = NULL;
  fd_transpiler_t *      t             = NULL;
  uchar *                text          = NULL;
  uchar *                rodata        = NULL;
  ulong                  text_map_sz   = 0UL;
  ulong                  rodata_map_sz = 0UL;

  /* Transpile */

  t = aligned_alloc( 64UL, sizeof(fd_transpiler_t) );
  if( FD_UNLIKELY( !t ) ) {
    FD_LOG_WARNING(( "malloc failed" ));
    goto fail;
  }

  if( FD_UNLIKELY( fd_vm_transpile_prog( t, prog, syscalls ) ) ) {
    FD_LOG_WARNING(( "fd_vm_transpile_prog failed" ));
    goto fail;
  }
  fd_elf64_rela const * reloc     = t->reloc;
  ulong                 reloc_cnt = t->reloc_cnt;
  ulong                 code_sz   = t->code_sz;

  /* Resolve external symbols */

  uint  ext_idx[ FD_TRANSPILED_LIVE_EXT_MAX ];
  ulong ext_addr[ FD_TRANSPILED_LIVE_EXT_MAX ];
  ulong ext_cnt = 0UL;
  memset( ext_idx, 0xff, sizeof(ext_idx) );
  for( ulong i=0UL; i<reloc_cnt; i++ ) {
    if( FD_ELF64_R_TYPE( reloc[i].r_info )!=FD_ELF_R_X86_64_PLT32 ) continue;
    uint sym = FD_ELF64_R_SYM( reloc[i].r_info );
    if( FD_UNLIKELY( sym>=FD_TRANSPILED_LIVE_EXT_MAX ) ) {
      FD_LOG_WARNING(( "unsupported call target symbol %u", sym ));
      goto fail;
    }
    if( ext_idx[ sym ]!=UINT_MAX ) continue;
    ulong addr = 0UL;
    switch( sym ) {
    case FD_VM_TRANSPILE_SYM_MMU_TRANSLATE: addr = (ulong)fd_vm_transpiled_mmu_translate; break;
    case FD_VM_TRANSPILE_SYM_FRAME_INIT:    addr = (ulong)fd_vm_transpiled_frame_init;    break;
    default:
      if( sym>=FD_VM_TRANSPILE_SYM_MAX ) addr = (ulong)syscalls[ sym-FD_VM_TRANSPILE_SYM_MAX ].func;
      break;
    }
    if( FD_UNLIKELY( !addr ) ) {
      FD_LOG_WARNING(( "unresolved call target symbol %u", sym ));
      goto fail;
    }
    ext_idx [ sym     ] = (uint)ext_cnt;
    ext_addr[ ext_cnt ] = addr;
    ext_cnt++;
  }

  /* Compute layout */

  ulong const veneer_off = fd_ulong_align_up( (ulong)code_sz, 16UL );
  ulong const text_sz    = veneer_off + ext_cnt*FD_TRANSPILED_LIVE_VENEER_SZ;

  ulong const tables_off = fd_ulong_align_up( sizeof(fd_transpiled_live_t), 8UL );
  ulong const got_off    = fd_ulong_align_up( tables_off + t->rodata_sz, 8UL );
  ulong const rodata_sz  = got_off + ext_cnt*sizeof(ulong);

  if( FD_UNLIKELY( text_sz>FD_TRANSPILED_LIVE_MAP_SZ_MAX || rodata_sz>FD_TRANSPILED_LIVE_MAP_SZ_MAX ) ) {
    FD_LOG_WARNING(( "transpiled program too large (text_sz %lu, rodata_sz %lu)", text_sz, rodata_sz ));
    goto fail;
  }
  text_map_sz   = fd_ulong_align_up( text_sz,   FD_SHMEM_NORMAL_PAGE_SZ );
  rodata_map_sz = fd_ulong_align_up( rodata_sz, FD_SHMEM_NORMAL_PAGE_SZ );

  /* Map (both RW for now, neither executable) */

  void * rodata_mem = mmap( NULL, rodata_map_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( rodata_mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(%lu) failed (%i-%s)", rodata_map_sz, errno, fd_io_strerror( errno ) ));
    goto fail;
  }
  rodata = rodata_mem;

  text = text_map_place( (ulong)rodata, rodata_map_sz, text_map_sz );
  if( FD_UNLIKELY( !text ) ) goto fail;

  /* Populate .text */

  memset( text, 0xcc, text_map_sz ); /* int3 */
  memcpy( text, t->code, code_sz );

  for( ulong i=0UL; i<ext_cnt; i++ ) {
    uchar * veneer = text + veneer_off + i*FD_TRANSPILED_LIVE_VENEER_SZ;
    veneer[0] = 0xff; veneer[1] = 0x25; /* jmp qword [rip+disp32] */
    if( FD_UNLIKELY( rel32_patch( veneer+2, (ulong)( rodata + got_off + i*sizeof(ulong) ), -4L ) ) ) goto fail_reach;
  }

  for( ulong i=0UL; i<reloc_cnt; i++ ) {
    ulong ofs = reloc[i].r_offset;
    if( FD_UNLIKELY( ofs+4UL>code_sz ) ) {
      FD_LOG_WARNING(( "relocation %lu offset %lu out of bounds (code_sz %lu)", i, ofs, code_sz ));
      goto fail;
    }
    uint  sym = FD_ELF64_R_SYM ( reloc[i].r_info );
    uint  typ = FD_ELF64_R_TYPE( reloc[i].r_info );
    ulong s;
    if( typ==FD_ELF_R_X86_64_PLT32 ) {
      s = (ulong)( text + veneer_off + ext_idx[ sym ]*FD_TRANSPILED_LIVE_VENEER_SZ );
    } else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_RODATA ) {
      s = (ulong)( rodata + tables_off );
    } else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_TEXT ) {
      s = (ulong)text;
    } else {
      FD_LOG_WARNING(( "unsupported relocation (type %u, sym %u)", typ, sym ));
      goto fail;
    }
    if( FD_UNLIKELY( rel32_patch( text+ofs, s, reloc[i].r_addend ) ) ) goto fail_reach;
  }

  /* Populate .rodata */

  uchar * tables = rodata + tables_off;
  memcpy( tables, t->rodata, t->rodata_sz );
  for( ulong i=0UL; i<t->rodata_reloc_cnt; i++ ) {
    fd_elf64_rela const * r = &t->rodata_reloc[ i ];
    if( FD_UNLIKELY( FD_ELF64_R_TYPE( r->r_info )!=FD_ELF_R_X86_64_PC32 ||
                     FD_ELF64_R_SYM ( r->r_info )!=FD_VM_TRANSPILE_SYM_TEXT ||
                     r->r_offset+4UL>t->rodata_sz ) ) {
      FD_LOG_WARNING(( "unsupported rodata relocation %lu", i ));
      goto fail;
    }
    if( FD_UNLIKELY( rel32_patch( tables+r->r_offset, (ulong)text, r->r_addend ) ) ) goto fail_reach;
  }
  memcpy( rodata + got_off, ext_addr, ext_cnt*sizeof(ulong) );

  live = (fd_transpiled_live_t *)rodata;
  *live = (fd_transpiled_live_t) {
    .text_haddr    = (ulong)text,
    .text_map_sz   = text_map_sz,
    .rodata_haddr  = (ulong)rodata,
    .rodata_map_sz = rodata_map_sz
  };

  /* Seal */

  if( FD_UNLIKELY( mprotect( text, text_map_sz, PROT_READ|PROT_EXEC ) ) ) {
    FD_LOG_WARNING(( "mprotect(.text,r-x) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }
  if( FD_UNLIKELY( mprotect( rodata, rodata_map_sz, PROT_READ ) ) ) {
    FD_LOG_WARNING(( "mprotect(.rodata,r--) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  free( t );
  return live;

fail_reach:
  FD_LOG_WARNING(( "rel32 out of reach (text %p, rodata %p)", (void *)text, (void *)rodata ));
fail:
  if( text   ) munmap( text,   text_map_sz   );
  if( rodata ) munmap( rodata, rodata_map_sz );
  free( t );
  return NULL;
}

void
fd_transpiled_live_destroy( fd_transpiled_live_t * live ) {
  if( FD_UNLIKELY( !live ) ) return;

  fd_transpiled_live_t l = *live;
  if( FD_UNLIKELY( munmap( (void *)l.text_haddr, l.text_map_sz ) ) ) {
    FD_LOG_WARNING(( "munmap(.text) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( munmap( (void *)l.rodata_haddr, l.rodata_map_sz ) ) ) {
    FD_LOG_WARNING(( "munmap(.rodata) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}
