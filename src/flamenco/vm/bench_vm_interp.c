#include "fd_vm.h"
#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "test_vm_util.h"
#include "../runtime/fd_bank.h"
#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

/* Hardware performance counters (Linux only) */

#if defined(__linux__)
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern long syscall( long, ... );

struct fd_perf_ctr {
  int fd_insn;
  int fd_cycles;
  int fd_branches;
  int fd_br_miss;
};

static int
fd_perf_event_open_( struct perf_event_attr * attr,
                     int group_fd ) {
  return (int)syscall( (long)SYS_perf_event_open, attr,
                       (long)0 /*pid=self*/, (long)-1 /*cpu=any*/,
                       (long)group_fd, (long)0 /*flags*/ );
}

static struct fd_perf_ctr
fd_perf_ctr_open( void ) {
  struct fd_perf_ctr ctr = { .fd_insn=-1, .fd_cycles=-1, .fd_branches=-1, .fd_br_miss=-1 };

  struct perf_event_attr pe;
  memset( &pe, 0, sizeof(pe) );
  pe.size           = sizeof(pe);
  pe.type           = PERF_TYPE_HARDWARE;
  pe.disabled       = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv     = 1;

  pe.config = PERF_COUNT_HW_INSTRUCTIONS;
  ctr.fd_insn = fd_perf_event_open_( &pe, -1 );

  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  ctr.fd_cycles = fd_perf_event_open_( &pe, ctr.fd_insn );

  pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
  ctr.fd_branches = fd_perf_event_open_( &pe, ctr.fd_insn );

  pe.config = PERF_COUNT_HW_BRANCH_MISSES;
  ctr.fd_br_miss = fd_perf_event_open_( &pe, ctr.fd_insn );

  return ctr;
}

static void
fd_perf_ctr_reset_and_enable( struct fd_perf_ctr * ctr ) {
  ioctl( ctr->fd_insn, PERF_EVENT_IOC_RESET,  PERF_IOC_FLAG_GROUP );
  ioctl( ctr->fd_insn, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP );
}

static void
fd_perf_ctr_disable( struct fd_perf_ctr * ctr ) {
  ioctl( ctr->fd_insn, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP );
}

static long long
fd_perf_ctr_read_one_( int fd ) {
  long long val = 0;
  if( FD_UNLIKELY( read( fd, &val, sizeof(val) ) != (long)sizeof(val) ) ) val = -1;
  return val;
}

static void
fd_perf_ctr_read( struct fd_perf_ctr * ctr,
                  long long * insn,
                  long long * cycles,
                  long long * branches,
                  long long * br_miss ) {
  *insn     = fd_perf_ctr_read_one_( ctr->fd_insn );
  *cycles   = fd_perf_ctr_read_one_( ctr->fd_cycles );
  *branches = fd_perf_ctr_read_one_( ctr->fd_branches );
  *br_miss  = fd_perf_ctr_read_one_( ctr->fd_br_miss );
}

static void
fd_perf_ctr_close( struct fd_perf_ctr * ctr ) {
  if( ctr->fd_br_miss >=0 ) close( ctr->fd_br_miss );
  if( ctr->fd_branches>=0 ) close( ctr->fd_branches );
  if( ctr->fd_cycles  >=0 ) close( ctr->fd_cycles );
  if( ctr->fd_insn    >=0 ) close( ctr->fd_insn );
}

static int have_perf_g;
static struct fd_perf_ctr pctr_g;

static void
perf_init( void ) {
  pctr_g = fd_perf_ctr_open();
  have_perf_g = ( pctr_g.fd_insn >= 0 );
  if( !have_perf_g ) FD_LOG_NOTICE(( "perf counters unavailable, wall-clock only" ));
}

static void
perf_fini( void ) {
  fd_perf_ctr_close( &pctr_g );
}

#else /* !__linux__ */

static int have_perf_g = 0;
static void perf_init( void ) { FD_LOG_NOTICE(( "perf counters unavailable (not linux)" )); }
static void perf_fini( void ) {}

#endif

static void
perf_report( char const * label, long dt, ulong iters ) {
  FD_LOG_NOTICE(( "%-24s %11li ns (%.1f ns/iter, %lu iters)",
    label, dt, (double)dt / (double)iters, iters ));

#if defined(__linux__)
  if( have_perf_g ) {
    long long p_insn=0, p_cycles=0, p_branches=0, p_br_miss=0;
    fd_perf_ctr_read( &pctr_g, &p_insn, &p_cycles, &p_branches, &p_br_miss );
    double per = (double)iters;
    FD_LOG_NOTICE(( "  %-22s %.1f insn  %.1f cyc  IPC=%.3f  %.1f br  %.1f br_miss (%.2f%%)",
                    "",
                    (double)p_insn     / per,
                    (double)p_cycles   / per,
                    (p_cycles>0) ? (double)p_insn/(double)p_cycles : 0.0,
                    (double)p_branches / per,
                    (double)p_br_miss  / per,
                    (p_branches>0) ? 100.0*(double)p_br_miss/(double)p_branches : 0.0 ));
  }
#endif
}

/* Micro-benchmarks: synthetic SBPF programs */

static void
generate_random_alu_instrs( fd_rng_t * rng,
                            ulong *    text,
                            ulong      text_cnt ) {
  static uchar const opcodes[] = {
    FD_SBPF_OP_ADD_IMM,   FD_SBPF_OP_ADD_REG,
    FD_SBPF_OP_SUB_IMM,   FD_SBPF_OP_SUB_REG,
    FD_SBPF_OP_MUL_IMM,   FD_SBPF_OP_MUL_REG,
    FD_SBPF_OP_DIV_IMM,
    FD_SBPF_OP_OR_IMM,    FD_SBPF_OP_OR_REG,
    FD_SBPF_OP_AND_IMM,   FD_SBPF_OP_AND_REG,
    FD_SBPF_OP_LSH_IMM,   FD_SBPF_OP_LSH_REG,
    FD_SBPF_OP_RSH_IMM,   FD_SBPF_OP_RSH_REG,
    FD_SBPF_OP_NEG,
    FD_SBPF_OP_MOD_IMM,
    FD_SBPF_OP_XOR_IMM,   FD_SBPF_OP_XOR_REG,
    FD_SBPF_OP_MOV_IMM,   FD_SBPF_OP_MOV_REG,
    FD_SBPF_OP_ARSH_IMM,  FD_SBPF_OP_ARSH_REG,
  };
  ulong const opcodes_cnt = sizeof(opcodes)/sizeof(opcodes[0]);

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, opcodes_cnt)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll(rng, 1024*1024);
    switch( instr.opcode.raw ) {
    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

static void
generate_random_alu64_instrs( fd_rng_t * rng,
                              ulong *    text,
                              ulong      text_cnt ) {
  static uchar const opcodes[] = {
    FD_SBPF_OP_ADD64_IMM,   FD_SBPF_OP_ADD64_REG,
    FD_SBPF_OP_SUB64_IMM,   FD_SBPF_OP_SUB64_REG,
    FD_SBPF_OP_MUL64_IMM,   FD_SBPF_OP_MUL64_REG,
    FD_SBPF_OP_DIV64_IMM,
    FD_SBPF_OP_OR64_IMM,    FD_SBPF_OP_OR64_REG,
    FD_SBPF_OP_AND64_IMM,   FD_SBPF_OP_AND64_REG,
    FD_SBPF_OP_LSH64_IMM,   FD_SBPF_OP_LSH64_REG,
    FD_SBPF_OP_RSH64_IMM,   FD_SBPF_OP_RSH64_REG,
    FD_SBPF_OP_NEG64,
    FD_SBPF_OP_MOD64_IMM,
    FD_SBPF_OP_XOR64_IMM,   FD_SBPF_OP_XOR64_REG,
    FD_SBPF_OP_MOV64_IMM,   FD_SBPF_OP_MOV64_REG,
    FD_SBPF_OP_ARSH64_IMM,  FD_SBPF_OP_ARSH64_REG,
  };
  ulong const opcodes_cnt = sizeof(opcodes)/sizeof(opcodes[0]);

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, opcodes_cnt)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll( rng, 1024*1024 );
    switch( instr.opcode.raw ) {
    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x67:  /* FD_SBPF_OP_LSH_IMM */
    case 0x77:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc7:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

static void
bench_micro_exec( char const *          label,
                  ulong const *         text,
                  ulong                 text_cnt,
                  fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, text_cnt,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
      0UL, NULL, TEST_VM_DEFAULT_SBPF_VERSION, NULL, NULL, sha,
      NULL, 0UL, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( vm_ok );

  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  for( ulong r=1; r<11; r++ ) vm->reg[r] = r;
  fd_vm_mem_cfg( vm );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  long dt = -fd_log_wallclock();
#if defined(__linux__)
  if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif

  int err = fd_vm_exec( vm );

#if defined(__linux__)
  if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
  dt += fd_log_wallclock();

  if( FD_UNLIKELY( err!=FD_VM_SUCCESS ) ) {
    FD_LOG_WARNING(( "%-24s FAILED err=%d (%s) ic=%lu cu=%lu",
                     label, err, fd_vm_strerror( err ), vm->ic, vm->cu ));
    fd_vm_delete( fd_vm_leave( vm ) );
    fd_sha256_delete( fd_sha256_leave( sha ) );
    return;
  }

  perf_report( label, dt, text_cnt );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

/* P-token transfer macro-benchmark */

#define PTOKEN_INPUT_SZ    0x7AB0UL
#define PTOKEN_REALLOC_PAD 10240UL

static void
ptoken_build_input( uchar * buf,
                    ulong   transfer_amount,
                    ulong   source_balance,
                    uchar   seed ) {
  memset( buf, 0, PTOKEN_INPUT_SZ );

  *(ulong *)(buf + 0x0000) = 3UL;

  /* Account 1 (source token account) */
  buf[0x0008] = 0xFF;
  buf[0x0009] = 0;
  buf[0x000A] = 1;
  buf[0x000B] = 0;
  memset( buf + 0x0010, seed, 32 );
  memset( buf + 0x0030, 0x06, 32 );
  *(ulong *)(buf + 0x0050) = 1000000UL;
  *(ulong *)(buf + 0x0058) = 165UL;

  uchar * acct1_data = buf + 0x0060;
  memset( acct1_data + 0x00, 0xAA, 32 );
  memset( acct1_data + 0x20, (int)(seed+1), 32 );
  *(ulong *)(acct1_data + 0x40) = source_balance;
  *(uint  *)(acct1_data + 0x48) = 0;
  acct1_data[0x6C] = 1;
  *(uint *)(acct1_data + 0x6D) = 0;

  /* Account 2 (destination token account) */
  buf[0x2910] = 0xFF;
  buf[0x2911] = 0;
  buf[0x2912] = 1;
  buf[0x2913] = 0;
  memset( buf + 0x2918, (int)(seed+2), 32 );
  memset( buf + 0x2938, 0x06, 32 );
  *(ulong *)(buf + 0x2958) = 1000000UL;
  *(ulong *)(buf + 0x2960) = 165UL;

  uchar * acct2_data = buf + 0x2968;
  memset( acct2_data + 0x00, 0xAA, 32 );
  memset( acct2_data + 0x20, (int)(seed+3), 32 );
  *(ulong *)(acct2_data + 0x40) = 500UL;
  *(uint  *)(acct2_data + 0x48) = 0;
  acct2_data[0x6C] = 1;
  *(uint *)(acct2_data + 0x6D) = 0;

  /* Account 3 (authority/owner) */
  buf[0x5218] = 0xFF;
  buf[0x5219] = 1;
  buf[0x521A] = 0;
  buf[0x521B] = 0;
  memset( buf + 0x5220, (int)(seed+1), 32 );
  memset( buf + 0x5240, 0x01, 32 );
  *(ulong *)(buf + 0x5260) = 1000000UL;
  *(ulong *)(buf + 0x5268) = 0UL;

  /* Instruction data: discriminator(3) + amount(u64) */
  *(ulong *)(buf + 0x7A78) = 9UL;
  buf[0x7A80] = 3;
  *(ulong *)(buf + 0x7A81) = transfer_amount;

  /* program_id */
  memset( buf + 0x7A90, 0x06, 32 );
}

static void
bench_ptoken_transfer( fd_runtime_t * runtime,
                       char const *   elf_path ) {

  /* Load p-token ELF */

  FILE * f = fopen( elf_path, "r" );
  if( FD_UNLIKELY( !f ) ) {
    FD_LOG_WARNING(( "ptoken: cannot open %s, skipping", elf_path ));
    return;
  }
  struct stat st;
  FD_TEST( 0==fstat( fileno( f ), &st ) );
  ulong  bin_sz  = (ulong)st.st_size;
  void * bin_buf = malloc( bin_sz + 8UL );
  FD_TEST( bin_buf );
  FD_TEST( fread( bin_buf, bin_sz, 1UL, f )==1UL );
  fclose( f );

  /* Scan for ELF magic (handle optional prefix) */
  ulong elf_off = 0;
  for( ulong i = 0; i + 4 <= bin_sz; i++ ) {
    if( ((uchar *)bin_buf)[i]==0x7f && ((uchar *)bin_buf)[i+1]=='E'
     && ((uchar *)bin_buf)[i+2]=='L' && ((uchar *)bin_buf)[i+3]=='F' ) {
      elf_off = i;
      break;
    }
  }
  void * elf_buf = (uchar *)bin_buf + elf_off;
  ulong  elf_sz  = bin_sz - elf_off;

  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 0;
  config.sbpf_min_version  = FD_SBPF_V0;
  config.sbpf_max_version  = FD_SBPF_V2;
  if( FD_UNLIKELY( fd_sbpf_elf_peek( &elf_info, elf_buf, elf_sz, &config )<0 ) ) {
    FD_LOG_WARNING(( "ptoken: elf_peek failed, skipping" ));
    free( bin_buf );
    return;
  }

  void * rodata = malloc( elf_info.bin_sz );
  FD_TEST( rodata );

  ulong prog_align = fd_sbpf_program_align();
  ulong prog_foot  = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( prog_align, prog_foot ), &elf_info, rodata );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * prog_syscalls = fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( prog_syscalls );
  fd_vm_syscall_register_all( prog_syscalls, 0 );

  void * scratch = malloc( elf_sz );
  int load_err = fd_sbpf_program_load( prog, elf_buf, elf_sz, prog_syscalls, &config, scratch, elf_sz );
  free( scratch );
  if( FD_UNLIKELY( load_err ) ) {
    FD_LOG_WARNING(( "ptoken: program_load failed (%d), skipping", load_err ));
    free( rodata ); free( bin_buf );
    free( fd_sbpf_program_delete( prog ) );
    free( fd_sbpf_syscalls_delete( prog_syscalls ) );
    return;
  }

  /* Build 8 distinct input buffers */

  ulong const N_INPUTS = 8UL;
  uchar * inputs[ 8 ];
  for( ulong i = 0; i < N_INPUTS; i++ ) {
    inputs[i] = (uchar *)malloc( PTOKEN_INPUT_SZ );
    FD_TEST( inputs[i] );
    ptoken_build_input( inputs[i],
                        100UL + i * 13UL,
                        10000UL + i * 1000UL,
                        (uchar)(0x10 + i * 0x11) );
  }

  /* Verify each input produces a successful transfer */

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  for( ulong i = 0; i < N_INPUTS; i++ ) {
    fd_vm_input_region_t input_region = {
      .vaddr_offset           = 0UL,
      .haddr                  = (ulong)inputs[i],
      .region_sz              = (uint)PTOKEN_INPUT_SZ,
      .address_space_reserved = PTOKEN_INPUT_SZ,
      .is_writable            = 1U
    };

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
        prog->rodata, prog->rodata_sz,
        prog->text, prog->info.text_cnt,
        (ulong)prog->text - (ulong)prog->rodata, prog->info.text_sz,
        prog->entry_pc, prog->calldests,
        FD_SBPF_V0, prog_syscalls, NULL, sha,
        &input_region, 1UL, NULL, 0,
        0, 0, 0, 0, 0UL );
    FD_TEST( vm_ok );

    vm->pc        = vm->entry_pc;
    vm->ic        = 0UL;
    vm->cu        = vm->entry_cu;
    vm->frame_cnt = 0UL;
    vm->heap_sz   = 0UL;
    fd_vm_mem_cfg( vm );

    int err = fd_vm_exec( vm );
    if( FD_UNLIKELY( err!=FD_VM_SUCCESS || vm->reg[0]!=0UL ) ) {
      FD_LOG_WARNING(( "ptoken: input %lu failed: err=%d (%s) r0=%lu ic=%lu",
                       i, err, fd_vm_strerror( err ), vm->reg[0], vm->ic ));
      fd_vm_delete( fd_vm_leave( vm ) );
      goto cleanup;
    }
    FD_LOG_NOTICE(( "ptoken: input %lu OK  ic=%lu cu_left=%lu",
                    i, vm->ic, vm->cu ));
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  /* Benchmark loop */

  ulong const ITERS = 100000UL;

  long dt = -fd_log_wallclock();
#if defined(__linux__)
  if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif

  for( ulong iter = 0; iter < ITERS; iter++ ) {
    ulong idx = iter & (N_INPUTS - 1);

    uchar * inp = inputs[idx];
    ulong amt = 100UL + idx * 13UL;
    *(ulong *)(inp + 0x0060 + 0x40) = 10000UL + idx * 1000UL;
    *(ulong *)(inp + 0x2968 + 0x40) = 500UL;
    *(ulong *)(inp + 0x7A81)        = amt;

    fd_vm_input_region_t input_region = {
      .vaddr_offset           = 0UL,
      .haddr                  = (ulong)inp,
      .region_sz              = (uint)PTOKEN_INPUT_SZ,
      .address_space_reserved = PTOKEN_INPUT_SZ,
      .is_writable            = 1U
    };

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
        prog->rodata, prog->rodata_sz,
        prog->text, prog->info.text_cnt,
        (ulong)prog->text - (ulong)prog->rodata, prog->info.text_sz,
        prog->entry_pc, prog->calldests,
        FD_SBPF_V0, prog_syscalls, NULL, sha,
        &input_region, 1UL, NULL, 0,
        0, 0, 0, 0, 0UL );
    FD_TEST( vm_ok );

    vm->pc        = vm->entry_pc;
    vm->ic        = 0UL;
    vm->cu        = vm->entry_cu;
    vm->frame_cnt = 0UL;
    vm->heap_sz   = 0UL;
    fd_vm_mem_cfg( vm );

    int err = fd_vm_exec( vm );
    if( FD_UNLIKELY( err!=FD_VM_SUCCESS ) ) {
      FD_LOG_ERR(( "ptoken: iteration %lu failed err=%d", iter, err ));
    }

    fd_vm_delete( fd_vm_leave( vm ) );
  }

#if defined(__linux__)
  if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
  dt += fd_log_wallclock();

  perf_report( "ptoken_xfer", dt, ITERS );

cleanup:
  for( ulong i = 0; i < N_INPUTS; i++ ) free( inputs[i] );
  free( rodata );
  free( bin_buf );
  free( fd_sbpf_program_delete( prog ) );
  free( fd_sbpf_syscalls_delete( prog_syscalls ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",       NULL, NULL            );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic"      );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 5UL             );
  ulong        near_cpu   = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",   NULL, fd_log_cpu_id() );
  ulong        wksp_tag   = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",   NULL, 1234UL          );
  char const * ptoken_elf = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ptoken-elf", NULL, NULL            );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  perf_init();

  /* Micro-benchmarks: ALU (128M instructions) */

  ulong   text_cnt = 128UL*1024UL*1024UL;
  ulong * text     = (ulong *)malloc( sizeof(ulong)*text_cnt );
  FD_TEST( text );

  generate_random_alu_instrs( rng, text, text_cnt );
  bench_micro_exec( "alu", text, text_cnt, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  bench_micro_exec( "alu64", text, text_cnt, instr_ctx );

  /* Micro-benchmarks: ALU short (1024 instructions) */

  text_cnt = 1024UL;
  generate_random_alu_instrs( rng, text, text_cnt );
  bench_micro_exec( "alu_short", text, text_cnt, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  bench_micro_exec( "alu64_short", text, text_cnt, instr_ctx );

  free( text );

  /* Macro-benchmark: p-token transfer */

  if( ptoken_elf ) {
    bench_ptoken_transfer( runtime, ptoken_elf );
  } else {
    FD_LOG_NOTICE(( "skipping ptoken bench (pass --ptoken-elf <path>)" ));
  }

  perf_fini();

  FD_LOG_NOTICE(( "bench done" ));
  fd_halt();
  return 0;
}
