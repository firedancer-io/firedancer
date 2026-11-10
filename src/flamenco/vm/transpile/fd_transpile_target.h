#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_target_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_target_h

/* fd_transpile_target.h describes the machine code the transpiler
   emits to the code that places it in memory (fd_jit_arena,
   fd_transpile_live, fd_transpile_obj): the ELF machine, the
   relocation types used, how to apply them, and how to write veneers
   for calls out of transpiled code.  The backend is picked by the
   build (FD_HAS_ARM selects arm64, everything else x86-64; see
   Local.mk). */

#include "../../../util/fd_util_base.h"
#include "../../../ballet/elf/fd_elf.h"

#if FD_HAS_ARM
#define FD_TRANSPILE_ARCH_ARM64 1
#else
#define FD_TRANSPILE_ARCH_X86   1
#endif

#if FD_TRANSPILE_ARCH_X86

#define FD_TRANSPILE_EM          FD_ELF_EM_X86_64
#define FD_TRANSPILE_R_ABS64     FD_ELF_R_X86_64_64
#define FD_TRANSPILE_R_PCREL32   FD_ELF_R_X86_64_PC32  /* S+A-P, 32 bit */
#define FD_TRANSPILE_R_CALL      FD_ELF_R_X86_64_PLT32 /* rel32 of call */

#else /* arm64 */

#define FD_TRANSPILE_EM          FD_ELF_EM_AARCH64
#define FD_TRANSPILE_R_ABS64     FD_ELF_R_AARCH64_ABS64
#define FD_TRANSPILE_R_PCREL32   FD_ELF_R_AARCH64_PREL32  /* S+A-P, 32 bit data */
#define FD_TRANSPILE_R_CALL      FD_ELF_R_AARCH64_CALL26  /* imm26 of bl */
#define FD_TRANSPILE_R_ADRP      FD_ELF_R_AARCH64_ADR_PREL_PG_HI21
#define FD_TRANSPILE_R_ADD_LO12  FD_ELF_R_AARCH64_ADD_ABS_LO12_NC

#endif

/* Every relocation the transpiler emits patches a 4 byte field. */

#define FD_TRANSPILE_RELOC_SZ (4UL)

/* fd_transpile_reloc_kind classifies a relocation type. */

#define FD_TRANSPILE_RELOC_CALL (1) /* call to an external function (via a veneer when loaded at run time) */
#define FD_TRANSPILE_RELOC_ADDR (2) /* address of transpiled text or rodata */

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline int
fd_transpile_reloc_kind( uint typ ) {
  if( typ==FD_TRANSPILE_R_CALL    ) return FD_TRANSPILE_RELOC_CALL;
  if( typ==FD_TRANSPILE_R_PCREL32 ) return FD_TRANSPILE_RELOC_ADDR;
#if FD_TRANSPILE_ARCH_ARM64
  if( typ==FD_TRANSPILE_R_ADRP || typ==FD_TRANSPILE_R_ADD_LO12 ) return FD_TRANSPILE_RELOC_ADDR;
#endif
  return -1;
}

/* fd_transpile_reloc_apply patches the field at site for a relocation
   of type typ against symbol value s with addend a.  Returns 0 on
   success, -1 if typ is unknown or the value is out of reach. */

static inline int
fd_transpile_reloc_apply( uchar * site,
                          uint    typ,
                          ulong   s,
                          long    a ) {
  long p = (long)site;
  switch( typ ) {
  case FD_TRANSPILE_R_PCREL32:
#if FD_TRANSPILE_ARCH_X86
  case FD_TRANSPILE_R_CALL:
#endif
  {
    long v = (long)s + a - p;
    if( FD_UNLIKELY( v<(long)INT_MIN || v>(long)INT_MAX ) ) return -1;
    FD_STORE( int, site, (int)v );
    return 0;
  }
#if FD_TRANSPILE_ARCH_ARM64
  case FD_TRANSPILE_R_CALL: {
    long v = (long)s + a - p;
    if( FD_UNLIKELY( (v&3L) || v<-(1L<<27) || v>=(1L<<27) ) ) return -1;
    uint ins = FD_LOAD( uint, site );
    FD_STORE( uint, site, ( ins & 0xfc000000U ) | ( (uint)(v>>2) & 0x03ffffffU ) );
    return 0;
  }
  case FD_TRANSPILE_R_ADRP: {
    long v = ( ((long)s + a)>>12 ) - ( p>>12 );
    if( FD_UNLIKELY( v<-(1L<<20) || v>=(1L<<20) ) ) return -1;
    uint ins = FD_LOAD( uint, site );
    ins &= 0x9f00001fU;
    ins |= ( (uint)v & 3U )<<29;
    ins |= ( ( (uint)v>>2 ) & 0x7ffffU )<<5;
    FD_STORE( uint, site, ins );
    return 0;
  }
  case FD_TRANSPILE_R_ADD_LO12: {
    uint ins = FD_LOAD( uint, site );
    ins &= 0xffc003ffU;
    ins |= ( (uint)( (ulong)s + (ulong)a ) & 0xfffU )<<10;
    FD_STORE( uint, site, ins );
    return 0;
  }
#endif
  default:
    return -1;
  }
}

/* Veneers are FD_TRANSPILE_VENEER_SZ bytes, entered by a transpiled
   call with the first C argument (the fd_vm_t *) already set up.

   fd_transpile_veneer_vm writes a veneer that loads a pointer from the
   fd_vm_t (held in the transpiled ABI's vm register) at disp_a, then
   tail jumps through the function pointer at disp_b from there.
   Nothing in it is absolute, so the code may run at a different
   address in every process.

   fd_transpile_veneer_got writes a veneer that tail jumps through the
   absolute function pointer stored at got.  Returns -1 if got is out
   of reach of the veneer. */

#define FD_TRANSPILE_VENEER_SZ (16UL)

static inline void
fd_transpile_veneer_vm( uchar * p,
                        uint    disp_a,
                        uint    disp_b ) {
#if FD_TRANSPILE_ARCH_X86
  /* mov rax, [r12+disp32]; jmp qword [rax+disp32]; int3; int3 */
  p[0] = 0x49; p[1] = 0x8b; p[2] = 0x84; p[3] = 0x24;
  FD_STORE( uint, p+4, disp_a );
  p[8] = 0xff; p[9] = 0xa0;
  FD_STORE( uint, p+10, disp_b );
  p[14] = 0xcc; p[15] = 0xcc;
#else
  /* ldr x16, [x19, #disp_a]; ldr x16, [x16, #disp_b]; br x16; brk #0 */
  FD_STORE( uint, p+ 0, 0xf9400270U | ( (disp_a>>3)<<10 ) );
  FD_STORE( uint, p+ 4, 0xf9400210U | ( (disp_b>>3)<<10 ) );
  FD_STORE( uint, p+ 8, 0xd61f0200U );
  FD_STORE( uint, p+12, 0xd4200000U );
#endif
}

static inline int
fd_transpile_veneer_got( uchar * p,
                         ulong   got ) {
#if FD_TRANSPILE_ARCH_X86
  /* jmp qword [rip+disp32]; int3 x10 */
  p[0] = 0xff; p[1] = 0x25;
  long v = (long)got - (long)(p+6);
  if( FD_UNLIKELY( v<(long)INT_MIN || v>(long)INT_MAX ) ) return -1;
  FD_STORE( int, p+2, (int)v );
  memset( p+6, 0xcc, 10UL );
  return 0;
#else
  /* adrp x16, got; ldr x16, [x16, #lo12]; br x16; brk #0 */
  FD_STORE( uint, p+ 0, 0x90000010U );
  FD_STORE( uint, p+ 4, 0xf9400210U );
  FD_STORE( uint, p+ 8, 0xd61f0200U );
  FD_STORE( uint, p+12, 0xd4200000U );
  if( FD_UNLIKELY( got&7UL ) ) return -1;
  if( FD_UNLIKELY( fd_transpile_reloc_apply( p, FD_TRANSPILE_R_ADRP, got, 0L ) ) ) return -1;
  uint ins = FD_LOAD( uint, p+4 );
  FD_STORE( uint, p+4, ins | ( (uint)( (got&0xfffUL)>>3 )<<10 ) );
  return 0;
#endif
}

/* fd_transpile_trap_fill fills [p,p+sz) with trapping instructions.
   sz is a multiple of 4. */

static inline void
fd_transpile_trap_fill( uchar * p,
                        ulong   sz ) {
#if FD_TRANSPILE_ARCH_X86
  memset( p, 0xcc, sz ); /* int3 */
#else
  for( ulong i=0UL; i<sz; i+=4UL ) FD_STORE( uint, p+i, 0xd4200000U ); /* brk #0 */
#endif
}

/* fd_transpile_icache_flush makes code written to [p,p+sz) visible to
   instruction fetch.  On arm64 the invalidation is broadcast to all
   cores, but a core that then executes the code for the first time
   still needs fd_transpile_icache_sync. */

static inline void
fd_transpile_icache_flush( uchar * p,
                           ulong   sz ) {
#if FD_TRANSPILE_ARCH_X86
  (void)p; (void)sz;
#else
  __builtin___clear_cache( (char *)p, (char *)(p+sz) );
#endif
}

static inline void
fd_transpile_icache_sync( void ) {
#if FD_TRANSPILE_ARCH_ARM64
  __asm__ __volatile__( "isb" ::: "memory" );
#endif
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_target_h */
