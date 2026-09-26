#define _GNU_SOURCE
#include "fd_vm_jit.h"
#include "../../../ballet/elf/fd_elf.h"
#include "../../../ballet/base58/fd_base58.h"

#if FD_VM_JIT_SUPPORTED

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

/* Code layout in the arena, per program (same as fd_transpile_live.c,
   with .text and .rodata in one contiguous allocation):

     code       uchar[ code_sz ]      (entrypoint at offset 0)
     veneer     uchar[ ext_cnt ][ 8 ] (jmp qword [rip+got_off]; int3; int3)
     bb_bitmap  ulong[ bb_word_cnt ]
     bb_seq     ulong[ bb_word_cnt ]
     bb_jmp     int  [ bb_cnt ]       (BB start in code, relative to bb_jmp)
     got        ulong[ ext_cnt ]      (absolute addresses of C functions)

   DynASM output only uses pc-relative addressing, so code encoded at
   an offset of the writable view runs unchanged at the same offset of
   the executable view.  Relocations are resolved against executable
   view addresses. */

#define FD_VM_JIT_EXT_MAX   (FD_VM_TRANSPILE_SYM_MAX+FD_SBPF_SYSCALLS_SLOT_CNT)
#define FD_VM_JIT_VENEER_SZ (8UL)
#define FD_VM_JIT_MAP_CNT   (2UL*FD_VM_JIT_ENTRY_MAX) /* power of 2 */

struct fd_vm_jit_entry {
  fd_vm_jit_key_t key;
  ulong           gen;    /* 0 if the slot is free, else jit->gen at insert */
  ulong           entry;  /* executable address, 0 if the program failed to compile */
};

typedef struct fd_vm_jit_entry fd_vm_jit_entry_t;

struct __attribute__((aligned(64UL))) fd_vm_jit {
  uchar * rw;        /* writable view of the arena */
  uchar * rx;        /* executable view of the arena */
  ulong   arena_sz;
  ulong   arena_used;
  ulong   gen;       /* bumped on every reset, invalidates all entries */
  ulong   entry_cnt;
  ulong   depth;     /* transpiled frames running (CPI nests them); code can't move while nonzero */

  fd_vm_jit_metrics_t metrics;

  fd_vm_jit_entry_t map[ FD_VM_JIT_MAP_CNT ];

  ulong         bb_splits[ (FD_VM_JIT_TEXT_CNT_MAX+63UL)/64UL ];
  fd_elf64_rela reloc    [ FD_VM_TRANSPILE_RELOC_MAX ];
  uchar         scratch  [] __attribute__((aligned(64UL))); /* fd_vm_transpile_scratch_footprint( FD_VM_JIT_TEXT_CNT_MAX ) */
};

FD_FN_CONST ulong
fd_vm_jit_align( void ) {
  return alignof(fd_vm_jit_t);
}

FD_FN_CONST ulong
fd_vm_jit_footprint( void ) {
  return fd_ulong_align_up( sizeof(fd_vm_jit_t) + fd_vm_transpile_scratch_footprint( FD_VM_JIT_TEXT_CNT_MAX ), alignof(fd_vm_jit_t) );
}

void *
fd_vm_jit_new( void * shmem,
               ulong  arena_sz ) {
  fd_vm_jit_t * jit = (fd_vm_jit_t *)shmem;
  if( FD_UNLIKELY( !jit ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)jit, fd_vm_jit_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !arena_sz || !fd_ulong_is_aligned( arena_sz, FD_SHMEM_NORMAL_PAGE_SZ ) || arena_sz>(1UL<<31) ) ) {
    FD_LOG_WARNING(( "invalid arena_sz %lu", arena_sz ));
    return NULL;
  }

  memset( jit, 0, sizeof(fd_vm_jit_t) );

  int fd = memfd_create( "fd_vm_jit", MFD_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "memfd_create failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }
  if( FD_UNLIKELY( ftruncate( fd, (off_t)arena_sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate(%lu) failed (%i-%s)", arena_sz, errno, fd_io_strerror( errno ) ));
    close( fd );
    return NULL;
  }
  void * rw = mmap( NULL, arena_sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 );
  void * rx = mmap( NULL, arena_sz, PROT_READ|PROT_EXEC,  MAP_SHARED, fd, 0 );
  close( fd );
  if( FD_UNLIKELY( rw==MAP_FAILED || rx==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(%lu) failed (%i-%s)", arena_sz, errno, fd_io_strerror( errno ) ));
    if( rw!=MAP_FAILED ) munmap( rw, arena_sz );
    if( rx!=MAP_FAILED ) munmap( rx, arena_sz );
    return NULL;
  }

  jit->rw       = rw;
  jit->rx       = rx;
  jit->arena_sz = arena_sz;
  jit->gen      = 1UL;
  return jit;
}

fd_vm_jit_t *
fd_vm_jit_join( void * shjit ) {
  return (fd_vm_jit_t *)shjit;
}

fd_vm_jit_metrics_t const *
fd_vm_jit_metrics( fd_vm_jit_t const * jit ) {
  return &jit->metrics;
}

ulong
fd_vm_jit_syscalls_hash( fd_sbpf_syscalls_t const * syscalls ) {
  ulong h = 0x9e3779b97f4a7c15UL;
  for( ulong i=0UL; i<FD_SBPF_SYSCALLS_SLOT_CNT; i++ ) {
    h = fd_ulong_hash( h ^ syscalls[ i ].key );
    if( fd_sbpf_syscalls_key_inval( syscalls[ i ].key ) ) continue; /* empty slot, func is garbage */
    h = fd_ulong_hash( h ^ (ulong)syscalls[ i ].func );
  }
  return h;
}

static ulong
key_hash( fd_vm_jit_key_t const * key ) {
  ulong h = fd_hash( 0UL, key, sizeof(fd_vm_jit_key_t) );
  return h;
}

static int
key_eq( fd_vm_jit_key_t const * a,
        fd_vm_jit_key_t const * b ) {
  return !memcmp( a, b, sizeof(fd_vm_jit_key_t) );
}

/* jit_reset drops every compiled program.  Only valid while no
   transpiled code is running (a CPI callee may be compiled while its
   caller's code is on the stack). */

static int
jit_reset( fd_vm_jit_t * jit ) {
  if( FD_UNLIKELY( jit->depth ) ) return 0;
  FD_LOG_NOTICE(( "jit code cache full (%lu programs, %lu of %lu bytes), resetting", jit->entry_cnt, jit->arena_used, jit->arena_sz ));
  jit->gen++;
  jit->arena_used = 0UL;
  jit->entry_cnt  = 0UL;
  jit->metrics.reset_cnt++;
  return 1;
}

static int
rel32_patch( uchar * site_rw,
             ulong   site_rx,
             ulong   s,
             long    a ) {
  long v = (long)s + a - (long)site_rx;
  if( FD_UNLIKELY( v<(long)INT_MIN || v>(long)INT_MAX ) ) return -1;
  FD_STORE( int, site_rw, (int)v );
  return 0;
}

/* jit_compile transpiles vm's program into the arena.  Returns the
   executable entry address, or 0 if the program can't be compiled
   (the caller interprets it). */

static ulong
jit_compile( fd_vm_jit_t * jit,
             fd_vm_t *     vm,
             int *         full ) {

  ulong text_cnt = vm->text_cnt;
  if( FD_UNLIKELY( !text_cnt || text_cnt>FD_VM_JIT_TEXT_CNT_MAX || vm->entry_pc>=text_cnt ) ) return 0UL;
  /* the transpiler handles sBPF v0, v1 and v3 */
  if( FD_UNLIKELY( vm->sbpf_version!=0UL && vm->sbpf_version!=1UL && vm->sbpf_version!=3UL ) ) return 0UL;

  fd_sbpf_program_t prog[1];
  memset( prog, 0, sizeof(fd_sbpf_program_t) );
  prog->info.text_cnt     = (uint)text_cnt;
  prog->info.sbpf_version = (uint)vm->sbpf_version;
  prog->text              = (ulong *)(ulong)vm->text;
  prog->entry_pc          = vm->entry_pc;
  prog->calldests         = (fd_sbpf_calldests_t *)(ulong)vm->calldests;

  ulong bb_word_cnt = (text_cnt+63UL)>>6;
  fd_vm_transpile_bb_splits( jit->bb_splits, prog );

  fd_vm_transpile_dasm_t d[1];
  ulong reloc_cnt = FD_VM_TRANSPILE_RELOC_MAX;
  if( FD_UNLIKELY( fd_vm_transpile_code( d, jit->scratch, fd_vm_transpile_scratch_footprint( FD_VM_JIT_TEXT_CNT_MAX ),
                                         vm->sbpf_version, (uchar const *)vm->text, text_cnt, vm->entry_pc,
                                         vm->calldests, vm->syscalls, jit->bb_splits, NULL,
                                         jit->reloc, &reloc_cnt ) ) ) return 0UL;
  size_t code_sz = 0;
  if( FD_UNLIKELY( dasm_link( d, &code_sz ) ) ) return 0UL;

  /* Resolve external symbols */

  uint  ext_idx [ FD_VM_JIT_EXT_MAX ];
  ulong ext_addr[ FD_VM_JIT_EXT_MAX ];
  ulong ext_cnt = 0UL;
  memset( ext_idx, 0xff, sizeof(ext_idx) );
  for( ulong i=0UL; i<reloc_cnt; i++ ) {
    if( FD_ELF64_R_TYPE( jit->reloc[i].r_info )!=FD_ELF_R_X86_64_PLT32 ) continue;
    uint sym = FD_ELF64_R_SYM( jit->reloc[i].r_info );
    if( FD_UNLIKELY( sym>=FD_VM_JIT_EXT_MAX ) ) return 0UL;
    if( ext_idx[ sym ]!=UINT_MAX ) continue;
    ulong addr = 0UL;
    switch( sym ) {
    case FD_VM_TRANSPILE_SYM_MMU_TRANSLATE: addr = (ulong)fd_vm_transpiled_mmu_translate; break;
    case FD_VM_TRANSPILE_SYM_FRAME_INIT:    addr = (ulong)fd_vm_transpiled_frame_init;    break;
    default:
      if( sym>=FD_VM_TRANSPILE_SYM_MAX ) addr = (ulong)vm->syscalls[ sym-FD_VM_TRANSPILE_SYM_MAX ].func;
      break;
    }
    if( FD_UNLIKELY( !addr ) ) return 0UL;
    ext_idx [ sym     ] = (uint)ext_cnt;
    ext_addr[ ext_cnt ] = addr;
    ext_cnt++;
  }

  ulong bb_cnt = 0UL;
  for( ulong w=0UL; w<bb_word_cnt; w++ ) bb_cnt += (ulong)fd_ulong_popcnt( jit->bb_splits[ w ] );

  /* Layout */

  ulong const veneer_off = fd_ulong_align_up( (ulong)code_sz, 16UL );
  ulong const bitmap_off = fd_ulong_align_up( veneer_off + ext_cnt*FD_VM_JIT_VENEER_SZ, 64UL );
  ulong const seq_off    = bitmap_off + bb_word_cnt*sizeof(ulong);
  ulong const jmp_off    = seq_off    + bb_word_cnt*sizeof(ulong);
  ulong const got_off    = fd_ulong_align_up( jmp_off + bb_cnt*sizeof(int), 8UL );
  ulong const total_sz   = fd_ulong_align_up( got_off + ext_cnt*sizeof(ulong), 64UL );

  if( FD_UNLIKELY( total_sz>jit->arena_sz ) ) return 0UL;
  if( FD_UNLIKELY( jit->arena_used+total_sz>jit->arena_sz ) ) {
    if( FD_UNLIKELY( !jit_reset( jit ) ) ) { *full = 1; return 0UL; }
  }

  uchar * rw = jit->rw + jit->arena_used;
  ulong   rx = (ulong)jit->rx + jit->arena_used;

  /* Code */

  memset( rw, 0xcc, total_sz ); /* int3 */
  if( FD_UNLIKELY( dasm_encode( d, rw ) ) ) return 0UL;

  for( ulong i=0UL; i<ext_cnt; i++ ) {
    ulong vo = veneer_off + i*FD_VM_JIT_VENEER_SZ;
    rw[ vo ] = 0xff; rw[ vo+1UL ] = 0x25; /* jmp qword [rip+disp32] */
    if( FD_UNLIKELY( rel32_patch( rw+vo+2UL, rx+vo+2UL, rx+got_off+i*sizeof(ulong), -4L ) ) ) return 0UL;
  }

  ulong const lbl_reloc0 = FD_VM_TRANSPILE_DASM_LBL_RELOC0( text_cnt );
  for( ulong i=0UL; i<reloc_cnt; i++ ) {
    int ofs = dasm_getpclabel( d, (uint)( lbl_reloc0+i ) );
    if( FD_UNLIKELY( ofs<0 || (ulong)ofs+4UL>code_sz ) ) return 0UL;
    uint  sym = FD_ELF64_R_SYM ( jit->reloc[i].r_info );
    uint  typ = FD_ELF64_R_TYPE( jit->reloc[i].r_info );
    ulong s;
    if(      typ==FD_ELF_R_X86_64_PLT32                                  ) s = rx + veneer_off + ext_idx[ sym ]*FD_VM_JIT_VENEER_SZ;
    else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_BB_BITMAP ) s = rx + bitmap_off;
    else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_BB_SEQ    ) s = rx + seq_off;
    else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_BB_JMP    ) s = rx + jmp_off;
    else return 0UL;
    if( FD_UNLIKELY( rel32_patch( rw+ofs, rx+(ulong)ofs, s, jit->reloc[i].r_addend ) ) ) return 0UL;
  }

  /* Tables */

  ulong * bitmap = (ulong *)( rw + bitmap_off );
  ulong * seq    = (ulong *)( rw + seq_off    );
  ulong * got    = (ulong *)( rw + got_off    );
  memcpy( bitmap, jit->bb_splits, bb_word_cnt*sizeof(ulong) );
  ulong bb_idx = 0UL;
  for( ulong w=0UL; w<bb_word_cnt; w++ ) {
    seq[ w ] = bb_idx;
    ulong word = jit->bb_splits[ w ];
    while( word ) {
      ulong pc = (w<<6) + (ulong)fd_ulong_find_lsb( word );
      word &= word-1UL;
      int ofs = dasm_getpclabel( d, (uint)pc );
      if( FD_UNLIKELY( ofs<0 ) ) return 0UL;
      /* entries are relative to the table base (see emit_callx_handler) */
      ulong eo = jmp_off + bb_idx*sizeof(int);
      if( FD_UNLIKELY( rel32_patch( rw+eo, rx+eo, rx+(ulong)ofs, (long)( bb_idx*sizeof(int) ) ) ) ) return 0UL;
      bb_idx++;
    }
  }
  memcpy( got, ext_addr, ext_cnt*sizeof(ulong) );

  jit->arena_used += total_sz;
  FD_LOG_DEBUG(( "jit: compiled %lu slots (sbpf v%lu) to [%#lx,%#lx) code_sz %lu", text_cnt, vm->sbpf_version, rx, rx+total_sz, (ulong)code_sz ));
  return rx;
}

int
fd_vm_jit_exec( fd_vm_jit_t *           jit,
                fd_vm_jit_key_t const * key,
                fd_vm_t *               vm ) {

  if( FD_UNLIKELY( vm->trace ) ) return fd_vm_exec( vm );

  /* Look up the program (linear probing, entries of older generations
     are free) */

  ulong mask = FD_VM_JIT_MAP_CNT-1UL;
  ulong slot = key_hash( key ) & mask;
  fd_vm_jit_entry_t * e = NULL;
  for(;;) {
    fd_vm_jit_entry_t * cand = &jit->map[ slot ];
    if( cand->gen!=jit->gen ) break;
    if( key_eq( &cand->key, key ) ) { e = cand; break; }
    slot = (slot+1UL) & mask;
  }

  ulong entry = 0UL;
  if( FD_LIKELY( e ) ) {
    entry = e->entry;
    jit->metrics.hit_cnt++;
  } else if( FD_LIKELY( jit->entry_cnt<FD_VM_JIT_ENTRY_MAX || jit_reset( jit ) ) ) {
    long  t0   = fd_tickcount();
    ulong gen0 = jit->gen;
    int   full = 0;
    entry = jit_compile( jit, vm, &full );
    if( entry ) {
      FD_BASE58_ENCODE_32_BYTES( key->prog.uc, prog_b58 );
      FD_LOG_DEBUG(( "jit: program %s at %#lx", prog_b58, entry ));
    }
    jit->metrics.compile_ticks += (ulong)( fd_tickcount()-t0 );
    if( FD_LIKELY( entry ) ) jit->metrics.compile_cnt++;
    else                     jit->metrics.compile_fail_cnt++;

    if( FD_LIKELY( !full ) ) { /* else no room until the running code returns; interpret this once */
      /* a reset during compilation invalidated the probe position */
      if( FD_UNLIKELY( jit->gen!=gen0 ) ) slot = key_hash( key ) & mask;
      while( jit->map[ slot ].gen==jit->gen ) slot = (slot+1UL) & mask;
      jit->map[ slot ].key   = *key;
      jit->map[ slot ].gen   = jit->gen;
      jit->map[ slot ].entry = entry;
      jit->entry_cnt++;
    }
  }

  if( FD_UNLIKELY( !entry ) ) return fd_vm_exec( vm );

  jit->depth++;
  int err = ((fd_vm_transpiled_exec_func_t)entry)( vm );
  jit->depth--;
  if( FD_UNLIKELY( err==FD_VM_ERR_BAIL ) ) {
    jit->metrics.bail_cnt++;
    err = fd_vm_exec( vm );
  }
  return err;
}

#endif /* FD_VM_JIT_SUPPORTED */
