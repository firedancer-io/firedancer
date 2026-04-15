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
  char const * ptoken_elf = fd_env_strip_cmdline_cstr ( &argc, &argv, "--ptoken-elf", NULL,
                                                       "src/ballet/sbpf/fixtures/ptoken_program.so" );

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

  /* Memory load benchmark: 1M sequential loads from input region */

  {
    ulong input_sz = 32768UL;
    uchar * input_buf = (uchar *)malloc( input_sz );
    FD_TEST( input_buf );
    memset( input_buf, 0x42, input_sz );

    fd_vm_input_region_t input_region;
    memset( &input_region, 0, sizeof(input_region) );
    input_region.vaddr_offset           = 0UL;
    input_region.haddr                  = (ulong)input_buf;
    input_region.region_sz              = (uint)input_sz;
    input_region.address_space_reserved = input_sz;
    input_region.is_writable            = 0;

    ulong load_cnt = 1024UL * 1024UL;
    ulong ld_text_cnt = 2UL + load_cnt + 1UL;
    ulong * ld_text = (ulong *)malloc( sizeof(ulong) * ld_text_cnt );
    FD_TEST( ld_text );

    ld_text[0] = fd_vm_instr( 0x18, 1, 0, 0, 0 );
    ld_text[1] = fd_vm_instr( 0,    0, 0, 0, 4 );

    for( ulong i = 0; i < load_cnt; i++ ) {
      short off = (short)((i * 8UL) % (input_sz - 8UL));
      ld_text[2 + i] = fd_vm_instr( 0x79, 0, 1, off, 0 );
    }
    ld_text[ld_text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_sha256_t _sha2[1];
    fd_sha256_t * sha2 = fd_sha256_join( fd_sha256_new( _sha2 ) );

    fd_vm_t _vm2[1];
    fd_vm_t * vm2 = fd_vm_join( fd_vm_new( _vm2 ) );
    FD_TEST( vm2 );

    fd_sbpf_syscalls_t * ld_syscalls = fd_sbpf_syscalls_new(
        aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    FD_TEST( ld_syscalls );
    fd_vm_syscall_register_all( ld_syscalls, 0 );

    int vm_ok = !!fd_vm_init(
        vm2, instr_ctx, FD_VM_HEAP_DEFAULT, ld_text_cnt + 10UL,
        (uchar *)ld_text, 8UL*ld_text_cnt, ld_text, ld_text_cnt, 0UL, 8UL*ld_text_cnt,
        0UL, NULL, FD_SBPF_V0, ld_syscalls, NULL, sha2,
        &input_region, 1UL, NULL, 0,
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
        0, 0UL );
    FD_TEST( vm_ok );

    vm2->pc        = vm2->entry_pc;
    vm2->ic        = 0UL;
    vm2->cu        = vm2->entry_cu;
    vm2->frame_cnt = 0UL;
    vm2->heap_sz   = 0UL;
    fd_vm_mem_cfg( vm2 );
    FD_TEST( fd_vm_validate( vm2 )==FD_VM_SUCCESS );

    long dt2 = -fd_log_wallclock();
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif
    int err2 = fd_vm_exec( vm2 );
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
    dt2 += fd_log_wallclock();
    FD_TEST( err2==FD_VM_SUCCESS );
    perf_report( "mem_ld", dt2, load_cnt );

    free( ld_text );
    free( input_buf );
    free( fd_sbpf_syscalls_delete( ld_syscalls ) );
    fd_vm_delete( fd_vm_leave( vm2 ) );
    fd_sha256_delete( fd_sha256_leave( sha2 ) );
  }

  /* Branch benchmark: tight loop of JNE (taken) + ADD (1M branches) */

  {
    fd_sha256_t _sha3[1];
    fd_sha256_t * sha3 = fd_sha256_join( fd_sha256_new( _sha3 ) );

    fd_sbpf_syscalls_t * br_syscalls = fd_sbpf_syscalls_new(
        aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    FD_TEST( br_syscalls );
    fd_vm_syscall_register_all( br_syscalls, 0 );

    ulong loop_iters = 1UL << 20;
    ulong br_text_cnt = 3UL;
    ulong br_text[3];
    br_text[0] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1 );
    br_text[1] = fd_vm_instr( FD_SBPF_OP_JNE_IMM, 0, 0, (short)(-2), (uint)loop_iters );
    br_text[2] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm3[1];
    fd_vm_t * vm3 = fd_vm_join( fd_vm_new( _vm3 ) );
    FD_TEST( vm3 );

    int vm_ok = !!fd_vm_init(
        vm3, instr_ctx, FD_VM_HEAP_DEFAULT, 4UL * loop_iters,
        (uchar *)br_text, 8UL*br_text_cnt, br_text, br_text_cnt, 0UL, 8UL*br_text_cnt,
        0UL, NULL, FD_SBPF_V0, br_syscalls, NULL, sha3,
        NULL, 0UL, NULL, 0,
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
        0, 0UL );
    FD_TEST( vm_ok );

    vm3->pc        = vm3->entry_pc;
    vm3->ic        = 0UL;
    vm3->cu        = vm3->entry_cu;
    vm3->frame_cnt = 0UL;
    vm3->heap_sz   = 0UL;
    fd_vm_mem_cfg( vm3 );
    FD_TEST( fd_vm_validate( vm3 )==FD_VM_SUCCESS );

    long dt3 = -fd_log_wallclock();
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif
    int err3 = fd_vm_exec( vm3 );
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
    dt3 += fd_log_wallclock();
    FD_TEST( err3==FD_VM_SUCCESS );
    perf_report( "branch", dt3, loop_iters );

    free( fd_sbpf_syscalls_delete( br_syscalls ) );
    fd_vm_delete( fd_vm_leave( vm3 ) );
    fd_sha256_delete( fd_sha256_leave( sha3 ) );
  }

  /* Lazy zeroing benchmarks */

  {
    /* vm_new cost (lazy: only zeros config+tail, not stack/heap) */
    ulong const NEW_ITERS = 1UL << 14;
    uchar * shmem = (uchar *)aligned_alloc( FD_VM_ALIGN, FD_VM_FOOTPRINT );
    FD_TEST( shmem );

    long dt4 = -fd_log_wallclock();
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif
    for( ulong i = 0; i < NEW_ITERS; i++ ) {
      fd_vm_new( shmem );
      fd_vm_delete( shmem );
      __asm__ volatile( "" ::: "memory" );
    }
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
    dt4 += fd_log_wallclock();
    perf_report( "vm_new", dt4, NEW_ITERS );
    free( shmem );
  }

  {
    /* Program touching 16 stack pages via stores (measures per-page lazy zeroing overhead) */
    fd_sha256_t _sha5[1];
    fd_sha256_t * sha5 = fd_sha256_join( fd_sha256_new( _sha5 ) );

    fd_sbpf_syscalls_t * lz_syscalls = fd_sbpf_syscalls_new(
        aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    FD_TEST( lz_syscalls );
    fd_vm_syscall_register_all( lz_syscalls, 0 );

    ulong pages_to_touch = 16;
    ulong lz_text_cnt = 2UL + pages_to_touch * 2UL + 1UL;
    ulong * lz_text = (ulong *)malloc( sizeof(ulong) * lz_text_cnt );
    FD_TEST( lz_text );

    ulong stack_base = FD_VM_MEM_MAP_STACK_REGION_START;
    lz_text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 2, 0, 0, (uint)(stack_base) );
    lz_text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(stack_base >> 32) );

    for( ulong p = 0; p < pages_to_touch; p++ ) {
      short off = (short)(p * FD_VM_LAZY_PAGE_SZ);
      lz_text[2 + p*2]     = fd_vm_instr( FD_SBPF_OP_STB, 2, 0, off, 0x42 );
      lz_text[2 + p*2 + 1] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1 );
    }
    lz_text[lz_text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    ulong const LZ_ITERS = 1UL << 14;
    fd_vm_t _vm5[1];
    fd_vm_t * vm5 = fd_vm_join( fd_vm_new( _vm5 ) );
    FD_TEST( vm5 );

    long dt5 = -fd_log_wallclock();
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_reset_and_enable( &pctr_g );
#endif
    for( ulong i = 0; i < LZ_ITERS; i++ ) {
      int vm_ok = !!fd_vm_init(
          vm5, instr_ctx, FD_VM_HEAP_DEFAULT, 10UL * lz_text_cnt,
          (uchar *)lz_text, 8UL*lz_text_cnt, lz_text, lz_text_cnt, 0UL, 8UL*lz_text_cnt,
          0UL, NULL, FD_SBPF_V1, lz_syscalls, NULL, sha5,
          NULL, 0UL, NULL, 0,
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
          0, 0UL );
      FD_TEST( vm_ok );
      int err5 = fd_vm_exec( vm5 );
      FD_TEST( err5==FD_VM_SUCCESS );
      __asm__ volatile( "" ::: "memory" );
    }
#if defined(__linux__)
    if( have_perf_g ) fd_perf_ctr_disable( &pctr_g );
#endif
    dt5 += fd_log_wallclock();
    perf_report( "lazy_16pg_exec", dt5, LZ_ITERS );

    free( lz_text );
    free( fd_sbpf_syscalls_delete( lz_syscalls ) );
    fd_vm_delete( fd_vm_leave( vm5 ) );
    fd_sha256_delete( fd_sha256_leave( sha5 ) );
  }

  /* Macro-benchmark: p-token transfer */

  bench_ptoken_transfer( runtime, ptoken_elf );

  perf_fini();

  FD_LOG_NOTICE(( "bench done" ));
  fd_halt();
  return 0;
}
