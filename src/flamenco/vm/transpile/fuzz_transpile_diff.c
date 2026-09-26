#define _GNU_SOURCE
#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_transpile_diff runs canonicalized random sBPF programs through
   fd_vm_exec and through transpiled x86 code and compares the resulting
   VM state.  A transpiled run that bails is resumed with fd_vm_exec.

   Input layout:
     [0]     sBPF version
     [1]     heap size
     [2,4)   CU budget
     [4,6)   input region size
     [6]     bit0 input writable, bit1 direct mapping, bit2 vaddr space adjustments
     [7]     initial r2 (text vaddr of instruction slot [7]%text_cnt, feeds CALLX)
     [8,..)  text words, followed by the input region bytes */

#include "fd_transpile.h"
#include "../fd_vm_private.h"
#include "../syscall/fd_vm_syscall.h"
#include "../../runtime/fd_runtime.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../../ballet/murmur3/fd_murmur3.h"
#include "../../../util/sanitize/fd_fuzz.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define TEXT_MAX  (1024UL)
#define INPUT_MAX (4096UL)
#define EXT_MAX   (FD_VM_TRANSPILE_SYM_MAX+FD_SBPF_SYSCALLS_SLOT_CNT)

/* One RWX arena: code, veneers (jmp [rip+got]), GOT, rodata */

#define CODE_OFF   (0UL)
#define VENEER_OFF (FD_TRANSPILER_CODE_MAX)
#define GOT_OFF    (VENEER_OFF + 8UL*EXT_MAX)
#define RODATA_OFF (( GOT_OFF + 8UL*EXT_MAX + 63UL ) & ~63UL)
#define ARENA_SZ   (RODATA_OFF + FD_TRANSPILER_RODATA_MAX)

static struct { char const * name; fd_sbpf_syscall_func_t func; } const sys_tab[] = {
  { "sol_log_64_",  fd_vm_syscall_sol_log_64  },
  { "sol_memcpy_",  fd_vm_syscall_sol_memcpy  },
  { "sol_memmove_", fd_vm_syscall_sol_memmove },
  { "sol_memset_",  fd_vm_syscall_sol_memset  },
  { "sol_memcmp_",  fd_vm_syscall_sol_memcmp  },
};
#define SYS_CNT (sizeof(sys_tab)/sizeof(sys_tab[0]))
static uint sys_hash[ SYS_CNT ];

static uchar *               arena;
static fd_transpiler_t *     transpiler;
static fd_sbpf_syscalls_t *  syscalls;
static fd_sbpf_calldests_t * calldests;
static fd_vm_t *             vm_a;
static fd_vm_t *             vm_b;
static fd_sha256_t           sha[1];
static ulong                 text[ TEXT_MAX ];
static uchar                 input_a[ INPUT_MAX ] __attribute__((aligned(16)));
static uchar                 input_b[ INPUT_MAX ] __attribute__((aligned(16)));
static fd_vm_input_region_t  region_a[1];
static fd_vm_input_region_t  region_b[1];

static fd_runtime_t *      runtime;
static fd_txn_out_t *      txn_out;
static fd_exec_instr_ctx_t instr_ctx[1];
static fd_log_collector_t  logc[1];

/* valid opcodes per sBPF version, discovered via fd_vm_validate */
static uchar ops    [ FD_SBPF_VERSION_COUNT ][ 256 ];
static ulong ops_cnt[ FD_SBPF_VERSION_COUNT ];

static ulong stat_iter, stat_valid, stat_bail;

static void
stats( void ) {
  FD_LOG_NOTICE(( "iter %lu valid %lu bail %lu", stat_iter, stat_valid, stat_bail ));
}

static int
probe_op( ulong version,
          ulong op ) {
  static ulong t[3];
  fd_vm_t * vm = vm_a;
  vm->sbpf_version = version;
  vm->rodata       = (uchar const *)t;
  vm->text         = t;
  uint const imms[2] = { 16U, 1U };
  for( ulong i=0UL; i<2UL; i++ ) {
    t[0] = fd_vm_instr( op, 0, 0, 0, imms[i] );
    t[1] = fd_vm_instr( 0x95UL, 0, 0, 0, 0U );
    t[2] = t[1];
    vm->text_cnt = 2UL; vm->text_sz = vm->rodata_sz = 16UL;
    if( !fd_vm_validate( vm ) ) return 1;
    t[1] = 0UL;
    vm->text_cnt = 3UL; vm->text_sz = vm->rodata_sz = 24UL;
    if( !fd_vm_validate( vm ) ) return 1;
  }
  return 0;
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  if( getenv( "FUZZ_TRANSPILE_STATS" ) ) atexit( stats );

  transpiler = aligned_alloc( 64UL, sizeof(fd_transpiler_t) );
  vm_a       = fd_vm_join( fd_vm_new( aligned_alloc( fd_vm_align(), fd_vm_footprint() ) ) );
  vm_b       = fd_vm_join( fd_vm_new( aligned_alloc( fd_vm_align(), fd_vm_footprint() ) ) );
  syscalls   = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) ) );
  calldests  = fd_sbpf_calldests_join( fd_sbpf_calldests_new( aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( TEXT_MAX ) ), TEXT_MAX ) );
  runtime    = calloc( 1UL, sizeof(fd_runtime_t) );
  txn_out    = calloc( 1UL, sizeof(fd_txn_out_t) );
  FD_TEST( transpiler && vm_a && vm_b && syscalls && calldests && runtime && txn_out );
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );

  runtime->log.log_collector = logc;
  instr_ctx->runtime = runtime;
  instr_ctx->txn_out = txn_out;

  for( ulong i=0UL; i<SYS_CNT; i++ ) {
    FD_TEST( !fd_vm_syscall_register( syscalls, sys_tab[i].name, sys_tab[i].func ) );
    sys_hash[i] = fd_murmur3_32( sys_tab[i].name, strlen( sys_tab[i].name ), 0U );
  }

  arena = mmap( NULL, ARENA_SZ, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( arena!=MAP_FAILED );
  ulong * got = (ulong *)( arena+GOT_OFF );
  got[ FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ] = (ulong)fd_vm_transpiled_mmu_translate;
  got[ FD_VM_TRANSPILE_SYM_FRAME_INIT    ] = (ulong)fd_vm_transpiled_frame_init;
  for( ulong i=0UL; i<FD_SBPF_SYSCALLS_SLOT_CNT; i++ ) got[ FD_VM_TRANSPILE_SYM_MAX+i ] = (ulong)syscalls[i].func;
  for( ulong i=0UL; i<EXT_MAX; i++ ) {
    uchar * v = arena+VENEER_OFF+8UL*i;
    v[0] = 0xff; v[1] = 0x25; v[6] = 0xcc; v[7] = 0xcc;
    FD_STORE( int, v+2, (int)( (long)(uchar *)&got[i] - (long)(v+6) ) );
  }

  ulong const versions[3] = { FD_SBPF_V0, FD_SBPF_V1, FD_SBPF_V3 };
  for( ulong v=0UL; v<3UL; v++ ) {
    ulong ver = versions[v];
    for( ulong op=1UL; op<256UL; op++ ) {
      if( probe_op( ver, op ) ) ops[ ver ][ ops_cnt[ ver ]++ ] = (uchar)op;
    }
  }
  return 0;
}

static int
is_jump( ulong version,
         ulong op ) {
  ulong cls = op & 7UL;
  if( cls==5UL ) return op!=0x85UL && op!=0x8dUL && op!=0x95UL;
  return cls==6UL && version==FD_SBPF_V3;
}

/* canonicalize rewrites raw words into a program that passes the
   verifier: valid opcodes, in-range registers, jump targets and
   immediates, and call targets that are syscalls or local functions. */

static void
canonicalize( ulong         version,
              uchar const * raw,
              ulong         text_cnt ) {
  fd_sbpf_calldests_null( calldests );
  fd_sbpf_calldests_insert( calldests, 0UL );

  for( ulong pc=0UL; pc<text_cnt; pc++ ) {
    ulong w   = FD_LOAD( ulong, raw+8UL*pc );
    ulong op  = ops[ version ][ (w & 255UL) % ops_cnt[ version ] ];
    ulong dst = ((w>> 8) & 15UL) % 11UL;
    ulong src = ((w>>12) & 15UL) % 11UL;
    short off = (short)(w>>16);
    uint  imm = (uint)(w>>32);

    if( dst==10UL && (op&7UL)!=2UL && (op&7UL)!=3UL ) {
      if( version==FD_SBPF_V1 && op==0x07UL ) imm &= ~63U;
      else                                    dst = 0UL;
    }
    if( op==0x18UL ) { /* LDDW */
      if( pc+2UL>=text_cnt ) op = 0x95UL;
      else                   text[ pc+1UL ] = FD_LOAD( ulong, raw+8UL*(pc+1UL) ) & 0xffffffff00000000UL;
    }
    if( is_jump( version, op ) ) off = (short)( (ulong)(ushort)off % text_cnt - pc - 1UL );
    switch( op ) {
    case 0x85: /* CALL_IMM */
      if( (imm&3U)==0U ) {
        src = 0UL;
        imm = sys_hash[ (imm>>2) % SYS_CNT ];
      } else {
        ulong target = (imm>>2) % text_cnt;
        if( FD_VM_SBPF_STATIC_SYSCALLS( version ) ) {
          src = 1UL;
          imm = (uint)( target - pc - 1UL );
        } else {
          src = 0UL;
          imm = fd_pchash( (uint)target );
          fd_sbpf_calldests_insert( calldests, target );
        }
      }
      break;
    case 0x8d: /* CALLX */
      if( FD_VM_SBPF_CALLX_USES_DST_REG( version ) ) dst %= 10UL;
      else                                            imm %= 10U;
      break;
    case 0xd4: case 0xdc: imm = 16U<<(imm%3U); break; /* LE, BE */
    case 0x64: case 0x74: case 0xc4: imm %= 32U;  break; /* 32-bit shifts */
    case 0x67: case 0x77: case 0xc7: imm %= 64U;  break; /* 64-bit shifts */
    case 0x34: case 0x37: case 0x94: case 0x97: imm |= !imm; break; /* div/mod imm */
    default: break;
    }
    text[ pc ] = fd_vm_instr( op, dst, src, off, imm );
    if( op==0x18UL ) pc++;
  }
  /* jumps and calls may not land on the second word of an LDDW */
  for( ulong pc=0UL; pc<text_cnt; pc++ ) {
    ulong op  = fd_vm_instr_opcode( text[ pc ] );
    ulong src = fd_vm_instr_src   ( text[ pc ] );
    uint  imm = fd_vm_instr_imm   ( text[ pc ] );
    if( op==0x18UL ) { pc++; continue; }
    if( is_jump( version, op ) ) {
      ulong target = pc + 1UL + fd_vm_instr_offset( text[ pc ] );
      if( fd_vm_instr_opcode( text[ target ] )==0x00UL ) {
        text[ pc ] = ( text[ pc ] & ~0xffff0000UL ) | ( (ulong)(ushort)(short)( target-1UL-pc-1UL ) << 16 );
      }
    } else if( op==0x85UL && src==1UL ) {
      ulong target = pc + 1UL + (ulong)(long)(int)imm;
      if( fd_vm_instr_opcode( text[ target ] )==0x00UL ) text[ pc ] = fd_vm_instr( op, 0, 1, 0, (uint)( target-1UL-pc-1UL ) );
    } else if( op==0x85UL && !FD_VM_SBPF_STATIC_SYSCALLS( version ) && !fd_sbpf_syscalls_query_const( syscalls, imm, NULL ) ) {
      ulong target = fd_pchash_inverse( imm );
      if( fd_vm_instr_opcode( text[ target ] )==0x00UL ) {
        text[ pc ] = fd_vm_instr( op, 0, 0, 0, fd_pchash( (uint)( target-1UL ) ) );
        fd_sbpf_calldests_insert( calldests, target-1UL );
      }
    }
  }
}

static fd_vm_transpiled_exec_func_t
link( void ) {
  fd_transpiler_t * t = transpiler;
  uchar * code   = arena+CODE_OFF;
  uchar * rodata = arena+RODATA_OFF;
  memcpy( code,   t->code,   t->code_sz   );
  memcpy( rodata, t->rodata, t->rodata_sz );
  for( ulong i=0UL; i<t->reloc_cnt; i++ ) {
    fd_elf64_rela const * r = &t->reloc[i];
    uint sym = FD_ELF64_R_SYM ( r->r_info );
    uint typ = FD_ELF64_R_TYPE( r->r_info );
    uchar * s;
    if(      typ==FD_ELF_R_X86_64_PLT32 && sym<EXT_MAX          ) s = arena+VENEER_OFF+8UL*sym;
    else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_RODATA ) s = rodata;
    else if( typ==FD_ELF_R_X86_64_PC32 && sym==FD_VM_TRANSPILE_SYM_TEXT   ) s = code;
    else FD_LOG_ERR(( "unsupported reloc type %u sym %u", typ, sym ));
    uchar * site = code + r->r_offset;
    FD_STORE( int, site, (int)( (long)s + r->r_addend - (long)site ) );
  }
  for( ulong i=0UL; i<t->rodata_reloc_cnt; i++ ) {
    fd_elf64_rela const * r = &t->rodata_reloc[i];
    uchar * site = rodata + r->r_offset;
    FD_STORE( int, site, (int)( (long)code + r->r_addend - (long)site ) );
  }
  fd_vm_transpiled_exec_func_t fn;
  void * entry = code + t->entrypoint_off;
  memcpy( &fn, &entry, sizeof(fn) );
  return fn;
}

struct cfg {
  ulong version;
  ulong heap_max;
  ulong cu;
  ulong text_cnt;
  ulong input_sz;
  int   writable;
  int   direct_mapping;
  int   vasa;
  ulong r2;
};
typedef struct cfg cfg_t;

static void
vm_setup( fd_vm_t *              vm,
          cfg_t const *          c,
          fd_vm_input_region_t * region,
          uchar *                input ) {
  *region = (fd_vm_input_region_t) {
    .haddr                  = (ulong)input,
    .region_sz              = (uint)c->input_sz,
    .address_space_reserved = c->input_sz,
    .is_writable            = (uchar)c->writable
  };
  ulong const * cd = FD_VM_SBPF_STATIC_SYSCALLS( c->version ) ? NULL : calldests;
  FD_TEST( fd_vm_init( vm, instr_ctx, c->heap_max, c->cu,
                       (uchar const *)text, 8UL*c->text_cnt, text, c->text_cnt, 0UL, 8UL*c->text_cnt,
                       0UL, cd, c->version, syscalls, NULL, sha,
                       region, c->input_sz ? 1U : 0U, NULL, 0,
                       c->direct_mapping, 0, c->vasa, 0, c->r2 ) );
}

struct result {
  int   err;
  int   exec_err;
  int   exec_err_kind;
  ulong log_sz;
  uchar log[ FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA ];
};
typedef struct result result_t;

static void
run( fd_vm_t *                    vm,
     fd_vm_transpiled_exec_func_t fn,
     result_t *                   res ) {
  fd_log_collector_init( logc, 1 );
  txn_out->err.exec_err      = 0;
  txn_out->err.exec_err_kind = 0;
  int err = fn ? fn( vm ) : fd_vm_exec( vm );
  if( fn && err==FD_VM_ERR_EBPF_BAIL ) {
    stat_bail++;
    err = fd_vm_exec( vm );
  }
  res->err           = err;
  res->exec_err      = txn_out->err.exec_err;
  res->exec_err_kind = txn_out->err.exec_err_kind;
  res->log_sz        = logc->buf_sz;
  memcpy( res->log, logc->buf, res->log_sz );
}

static ulong bad;

#define CHK( name, a, b ) do {                                                              \
    ulong _a = (ulong)(a); ulong _b = (ulong)(b);                                           \
    if( _a!=_b ) { bad++; FD_LOG_WARNING(( "%s: interp %#lx jit %#lx", (name), _a, _b )); } \
  } while(0)

/* Lazily zeroed regions: bytes past the shorter clean size must be zero
   on the longer side, since the program could not have observed them. */

static void
cmp_mem( char const *  name,
         uchar const * a, ulong a_sz,
         uchar const * b, ulong b_sz ) {
  ulong lo = fd_ulong_min( a_sz, b_sz );
  ulong hi = fd_ulong_max( a_sz, b_sz );
  for( ulong i=0UL; i<lo; i++ ) {
    if( a[i]!=b[i] ) { bad++; FD_LOG_WARNING(( "%s[%#lx]: interp %02x jit %02x", name, i, a[i], b[i] )); return; }
  }
  uchar const * big = a_sz>b_sz ? a : b;
  for( ulong i=lo; i<hi; i++ ) {
    if( big[i] ) { bad++; FD_LOG_WARNING(( "%s[%#lx]: %02x beyond other side's clean size %#lx", name, i, big[i], lo )); return; }
  }
}

static void
compare( result_t const * ra,
         result_t const * rb,
         int              bailed,
         cfg_t const *    c ) {
  fd_vm_t const * a = vm_a;
  fd_vm_t const * b = vm_b;
  bad = 0UL;

  if( ra->err==FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS ) {
    if( rb->err!=FD_VM_ERR_EBPF_SYSCALL_ERROR ) CHK( "err", ra->err, rb->err );
    CHK( "cu", a->cu, b->cu );
    goto done;
  }
  CHK( "err", ra->err, rb->err );
  CHK( "cu",  a->cu,   b->cu   );
  CHK( "exec_err",      ra->exec_err,      rb->exec_err      );
  CHK( "exec_err_kind", ra->exec_err_kind, rb->exec_err_kind );
  CHK( "log_sz", ra->log_sz, rb->log_sz );
  if( ra->log_sz==rb->log_sz ) cmp_mem( "log", ra->log, ra->log_sz, rb->log, rb->log_sz );
  ulong reg_cnt = ra->err!=FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT ? FD_VM_REG_CNT : 10UL;
  for( ulong i=0UL; i<reg_cnt; i++ ) {
    char name[8]; fd_cstr_printf( name, sizeof(name), NULL, "r%lu", i );
    CHK( name, a->reg[i], b->reg[i] );
  }
  CHK( "ic",        a->ic,        b->ic        );
  CHK( "heap_sz",   a->heap_sz,   b->heap_sz   );
  if( bailed ) CHK( "pc", a->pc, b->pc );
  /* frame state after a callx fault is not part of the contract */
  if( ra->err!=FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT ) {
    CHK( "frame_cnt", a->frame_cnt, b->frame_cnt );
    ulong frames = fd_ulong_min( fd_ulong_min( a->frame_cnt, b->frame_cnt ), FD_VM_STACK_FRAME_MAX );
    cmp_mem( "shadow", (uchar const *)a->shadow, frames*sizeof(fd_vm_shadow_t), (uchar const *)b->shadow, frames*sizeof(fd_vm_shadow_t) );
  }
  cmp_mem( "stack",  a->stack, a->stack_clean, b->stack, b->stack_clean );
  cmp_mem( "heap",   a->heap,  a->heap_clean,  b->heap,  b->heap_clean  );
  cmp_mem( "input",  input_a, c->input_sz, input_b, c->input_sz );
done:
  if( FD_UNLIKELY( bad ) ) {
    for( ulong i=0UL; i<c->text_cnt; i++ ) FD_LOG_WARNING(( "text[%lu] = %016lx", i, text[i] ));
    FD_LOG_ERR(( "%lu mismatches (v%lu text_cnt %lu cu %lu heap %lu input %lu%s dm %d vasa %d bail %d)",
                 bad, c->version, c->text_cnt, c->cu, c->heap_max, c->input_sz, c->writable ? " rw" : " ro",
                 c->direct_mapping, c->vasa, bailed ));
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  stat_iter++;
  if( FD_UNLIKELY( size<8UL ) ) return -1;
  ulong const versions[3] = { FD_SBPF_V0, FD_SBPF_V1, FD_SBPF_V3 };
  cfg_t c = {
    .version        = versions[ data[0]%3 ],
    .heap_max       = (ulong)( data[1]%9 ) * 32768UL,
    .cu             = 1UL + fd_ushort_load_2( data+2 ),
    .input_sz       = fd_ushort_load_2( data+4 ) % (INPUT_MAX+1UL),
    .writable       = !!( data[6] & 1 ),
    .direct_mapping = !!( data[6] & 2 ),
    .vasa           = !!( data[6] & 4 ),
  };
  ulong body = size-8UL;
  c.input_sz = fd_ulong_min( c.input_sz, body );
  c.text_cnt = fd_ulong_min( ( body-c.input_sz )/8UL, TEXT_MAX );
  if( FD_UNLIKELY( !c.text_cnt ) ) return -1;
  c.r2 = FD_VM_MEM_MAP_PROGRAM_REGION_START + 8UL*( data[7] % c.text_cnt );
  uchar const * raw = data+8UL;
  memcpy( input_a, raw+8UL*c.text_cnt, c.input_sz );
  memcpy( input_b, input_a, c.input_sz );

  canonicalize( c.version, raw, c.text_cnt );

  vm_setup( vm_a, &c, region_a, input_a );
  vm_setup( vm_b, &c, region_b, input_b );
  if( FD_UNLIKELY( fd_vm_validate( vm_a ) ) ) return -1;
  stat_valid++;

  ulong const * cd = FD_VM_SBPF_STATIC_SYSCALLS( c.version ) ? NULL : calldests;
  if( FD_UNLIKELY( fd_vm_transpile_code( transpiler, c.version, (uchar const *)text, c.text_cnt, 0UL, cd, syscalls, (uchar const *)text, 8UL*c.text_cnt, 0UL ) ) ) {
    FD_LOG_ERR(( "fd_vm_transpile_code failed on a verified program" ));
  }
  fd_vm_transpiled_exec_func_t fn = link();

  static result_t ra[1];
  static result_t rb[1];
  ulong bail0 = stat_bail;
  run( vm_a, NULL, ra );
  run( vm_b, fn,   rb );
  compare( ra, rb, stat_bail!=bail0, &c );
  return 0;
}
