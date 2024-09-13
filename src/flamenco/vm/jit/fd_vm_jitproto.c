/*
** This file has been pre-processed with DynASM.
** https://luajit.org/dynasm.html
** DynASM version 1.5.0, DynASM x64 version 1.5.0
** DO NOT EDIT! The original file is in "fd_vm_jitproto.dasc".
*/

#line 1 "fd_vm_jitproto.dasc"
/* fd_vm_jitproto is a first draft of a sBPF JIT compiler for
   Firedancer.  Nothing to see here, it's broken and work-in-progress.

   This version of the JIT compiler supports a linear memory mapping
   only. */

#define _GNU_SOURCE
#include "../../fd_flamenco_base.h"

/* Include dynasm headers.  These fail to compile when some strict
   checks are enabled. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#include "dasm_proto.h"
#include "dasm_x86.h"
#pragma GCC diagnostic pop
//| .arch x64
#if DASM_VERSION != 10500
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 20 "fd_vm_jitproto.dasc"

#include "../../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../runtime/fd_acc_mgr.h"
#include "../../runtime/context/fd_exec_epoch_ctx.h"
#include "../../runtime/context/fd_exec_slot_ctx.h"
#include "../../runtime/context/fd_exec_txn_ctx.h"
#include "../../runtime/sysvar/fd_sysvar_recent_hashes.h"
#include "../fd_vm_private.h"

#include <assert.h>
#include <setjmp.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* FD_DASM_R{...} specify the dynasm register index of x86_64 registers. */

#define FD_DASM_RAX  (0)
#define FD_DASM_RCX  (1)
#define FD_DASM_RDX  (2)
#define FD_DASM_RBX  (3)
#define FD_DASM_RSP  (4)
#define FD_DASM_RBP  (5)
#define FD_DASM_RSI  (6)
#define FD_DASM_RDI  (7)
#define FD_DASM_R8   (8)
#define FD_DASM_R9   (9)
#define FD_DASM_R10 (10)
#define FD_DASM_R11 (11)
#define FD_DASM_R12 (12)
#define FD_DASM_R13 (13)
#define FD_DASM_R14 (14)
#define FD_DASM_R15 (15)

/* FD_VM_JIT_SEGMENT_MAX is the max number of segments. */

#define FD_VM_JIT_SEGMENT_MAX (64)

/* Define thread-local storage slots.

   Depending on compile flags, these are either
   - FS-relative (technically absolute addressed in the FS segment)
     if host is Linux x86_64 with threads
   - rip-relative if host is Linux x86_64 without threads
   Other host environments are unsupported. */

static FD_TL fd_vm_t * fd_jit_vm  = NULL;  /* current VM being executed */
//static FD_TL ulong     ic_correct = 0UL;   /* number of lddw instructions executed */

FD_TL uint  fd_jit_segment_cnt;
FD_TL uint  fd_jit_mem_ro_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL uint  fd_jit_mem_rw_sz[ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_mem_base [ FD_VM_JIT_SEGMENT_MAX ];
FD_TL ulong fd_jit_call_stack_mem[128]; /* UGLY */
FD_TL uint  fd_jit_call_idx;
FD_TL ulong fd_jit_segfault_vaddr = 0x4141414141414141;
FD_TL ulong fd_jit_code_base;
FD_TL dasm_State * fd_jit_dasm;

//| .define translate_in,  rdi
//| .define translate_out, rdx

/* Define mapping between sBPF registers and x86_64 registers.

   This mapping is valid just before a translated sBPF instruction is
   about to be executed.  (At the `=>next_label` token in the code gen
   loop)

   BPF | r0  | r1  | r2  | r3  | r4  | r5  | r6  | r7  | r8  | r9  | r10
   X86 | rsi | r11 | r12 | r13 | r14 | r15 | rbx | rcx | r8  | r9  | r10

   x86_64 GPRs rax, rdi, rdx, rbp do not map to sBPF registers.  Those can
   be used as scratch registers for complex opcodes.

   Note that this mapping cannot be trivially changed.  Certain x86
   instructions (like div) have hardcoded register accesses which the
   JIT code works around.

   dynasm macros bpf_r{...} resolve to 64-bit register names.

   reg_bpf2x86 is indexed by sBPF register numbers and resolves to the
   x86_64 dynasm register index. */

static uchar const reg_bpf2x86[11] = {
  [ 0] =     FD_DASM_RSI,
  //| .define bpf_r0,  rsi
  [ 1] =     FD_DASM_R11,
  //| .define bpf_r1,  r11
  [ 2] =     FD_DASM_R12,
  //| .define bpf_r2,  r12
  [ 3] =     FD_DASM_R13,
  //| .define bpf_r3,  r13
  [ 4] =     FD_DASM_R14,
  //| .define bpf_r4,  r14
  [ 5] =     FD_DASM_R15,
  //| .define bpf_r5,  r15
  [ 6] =     FD_DASM_RBX,
  //| .define bpf_r6,  rbx
  [ 7] =     FD_DASM_RCX,
  //| .define bpf_r7,  rcx
  [ 8] =     FD_DASM_R8,
  //| .define bpf_r8,  r8
  [ 9] =     FD_DASM_R9,
  //| .define bpf_r9,  r9
  [10] =     FD_DASM_R10
  //| .define bpf_r10, r10
};

/* GDB JIT debug interface */

#define GDB_JIT_NOACTION      0
#define GDB_JIT_REGISTER_FN   1
#define GDB_JIT_UNREGISTER_FN 2

struct gdb_jit_code_entry {
  struct gdb_jit_code_entry * next_entry;
  struct gdb_jit_code_entry * prev_entry;
  char const *                symfile_addr;
  ulong                       symfile_size;
};

struct gdb_jit_descriptor {
  uint version;
  uint action_flag;
  struct gdb_jit_code_entry * relevant_entry;
  struct gdb_jit_code_entry * first_entry;
};

/* GDB puts a breakpoint in this function. */
void __attribute__((noinline)) __jit_debug_register_code(void) {}

struct gdb_jit_descriptor __jit_debug_descriptor = { 1, 0, 0, 0 };


/* New proposed ABI */

struct account_meta {
  /* 0x00 */ uint8_t pubkey[0x20];
  /* 0x20 */ uint8_t owner[0x20];
  /* 0x40 */ uint64_t data;
  /* 0x48 */ uint64_t data_len;
  /* 0x50 */ uint64_t lamports;
  /* 0x58 */ uint64_t flags;
  /* 0x60 */ uint8_t unused[0x20];
};

typedef struct account_meta account_meta_t;

//| .globals lbl_
enum {
  lbl_sigfpe,
  lbl_leave,
  lbl_sigsegv,
  lbl_translate_fail,
  lbl_fd_jit_vm_translate_rw,
  lbl_fd_jit_vm_translate_ro,
  lbl_save_regs,
  lbl_restore_regs,
  lbl_emulate_call_imm,
  lbl_emulate_call_imm_ret,
  lbl_emulate_exit,
  lbl_emulate_exit_ret,
  lbl_main,
  lbl_success,
  lbl_overrun,
  lbl__MAX
};
#line 171 "fd_vm_jitproto.dasc"
static FD_TL void * labels[ lbl__MAX ];

static ulong
fd_jit_op_call_imm( uint imm,
                    uint cur_pc,
                    uint dst_pc ) {
  fd_vm_t * vm = fd_jit_vm;
  ulong * reg = vm->reg;
  fd_vm_shadow_t * shadow = vm->shadow;
  fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( vm->syscalls, imm, NULL );
  if( !syscall ) {
    ulong frame_cnt = vm->frame_cnt;
    shadow[ frame_cnt ].r6 = reg[6];
    shadow[ frame_cnt ].r7 = reg[7];
    shadow[ frame_cnt ].r8 = reg[8];
    shadow[ frame_cnt ].r9 = reg[9];
    shadow[ frame_cnt ].pc = cur_pc;
    reg[10] += FD_VM_STACK_FRAME_SZ + FD_VM_STACK_GUARD_SZ;
    vm->frame_cnt = frame_cnt+1;
    ulong x86_dst = (ulong)fd_jit_code_base + (ulong)dasm_getpclabel( &fd_jit_dasm, dst_pc );
    //FD_LOG_NOTICE(( "Calling BPF function %u at %p from %u", dst_pc, (void *)x86_dst, cur_pc ));
    //__asm__("int3");
    return x86_dst;
  } else {
    FD_LOG_NOTICE(( "Executing syscall %08x (%#lx, %#lx, %#lx, %#lx, %#lx)", imm, reg[1], reg[2], reg[3], reg[4], reg[5] ));
    syscall->func( vm, reg[1], reg[2], reg[3], reg[4], reg[5], reg+0 );
    return 0;
  }
}

static ulong
fd_jit_op_exit( void ) {
  fd_vm_t * vm = fd_jit_vm;
  ulong frame_cnt = vm->frame_cnt;
  if( FD_UNLIKELY( !frame_cnt ) ) {
    return 0;
  }
  vm->frame_cnt = --frame_cnt;
  ulong * reg = vm->reg;
  fd_vm_shadow_t * shadow = vm->shadow;
  reg[6]   = shadow[ frame_cnt ].r6;
  reg[7]   = shadow[ frame_cnt ].r7;
  reg[8]   = shadow[ frame_cnt ].r8;
  reg[9]   = shadow[ frame_cnt ].r9;
  uint pc = (uint)shadow[ frame_cnt ].pc + 1;
  reg[10] -= FD_VM_STACK_FRAME_SZ + FD_VM_STACK_GUARD_SZ;
  //FD_LOG_NOTICE(( "Returning to %u", pc ));
  ulong x86_dst = (ulong)fd_jit_code_base + (ulong)dasm_getpclabel( &fd_jit_dasm, pc );
  return x86_dst;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  char const * bin_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--program-file", NULL, NULL );

  /* Read and parse ELF binary */

  FILE * bin_file = fopen( bin_path, "r" );
  if( FD_UNLIKELY( !bin_file ) )
    FD_LOG_ERR(( "fopen(\"%s\") failed (%i-%s)", bin_path, errno, fd_io_strerror( errno ) ));

  struct stat bin_stat;
  if( FD_UNLIKELY( 0!=fstat( fileno( bin_file ), &bin_stat ) ) )
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( bin_stat.st_mode ) ) )
    FD_LOG_ERR(( "File \"%s\" not a regular file", bin_path ));

  ulong  bin_sz  = (ulong)bin_stat.st_size;
  void * bin_buf = malloc( bin_sz+8UL );
  if( FD_UNLIKELY( !bin_buf ) )
    FD_LOG_ERR(( "malloc(%#lx) failed (%i-%s)", bin_sz, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( fread( bin_buf, bin_sz, 1UL, bin_file )!=1UL ) )
    FD_LOG_ERR(( "fread() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( 0==fclose( bin_file ) );

  int is_deploy = 0;
  fd_sbpf_elf_info_t elf_info;
  FD_TEST( fd_sbpf_elf_peek( &elf_info, bin_buf, bin_sz, is_deploy ) );

  void * rodata = malloc( elf_info.rodata_footprint );
  FD_TEST( rodata );

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls, is_deploy );

  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, bin_buf, bin_sz, syscalls, is_deploy ) ) )
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));

  /* Create workspace and scratch allocator */

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 65536, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );
  assert( wksp );

  ulong   smax = 1UL<<30;  /* 1 GiB */
  uchar * smem = malloc( smax );
  ulong fmem[ 64 ];
  fd_scratch_attach( smem, fmem, smax, 64UL );
  fd_scratch_push();

  /* Create runtime context */

  ulong txn_max = 2UL;
  ulong rec_max = 1024UL;
  fd_funk_t * funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1UL ), 1UL, (ulong)fd_tickcount(), txn_max, rec_max ) );
  assert( funk );
  fd_funk_start_write( funk );

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), funk );
  assert( acc_mgr );

  fd_funk_txn_xid_t xid[1] = {{ .ul = {0,1} }};

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  assert( funk_txn );
  fd_scratch_push();

  ulong vote_acct_max = 1;
  uchar * epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  uchar * slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar * txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  fd_exec_epoch_ctx_t * epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );
  fd_exec_slot_ctx_t *  slot_ctx  = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_scratch_virtual() ) );
  fd_exec_txn_ctx_t *   txn_ctx   = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem ) );

  assert( epoch_ctx );
  assert( slot_ctx  );

  epoch_ctx->epoch_bank.rent.lamports_per_uint8_year = 3480;
  epoch_ctx->epoch_bank.rent.exemption_threshold = 2;
  epoch_ctx->epoch_bank.rent.burn_percent = 50;

  fd_features_enable_all( &epoch_ctx->features );

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->acc_mgr   = acc_mgr;
  slot_ctx->valloc    = fd_scratch_virtual();

  fd_slot_bank_new( &slot_ctx->slot_bank );
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  slot_ctx->slot_bank.recent_block_hashes.hashes = recent_block_hashes;
  fd_block_block_hash_entry_t * recent_block_hash = deq_fd_block_block_hash_entry_t_push_tail_nocopy( recent_block_hashes );
  fd_memset( recent_block_hash, 0, sizeof(fd_block_block_hash_entry_t) );

  txn_ctx->epoch_ctx = epoch_ctx;
  txn_ctx->slot_ctx  = slot_ctx;
  txn_ctx->funk_txn  = funk_txn;
  txn_ctx->acc_mgr   = acc_mgr;
  txn_ctx->valloc    = fd_scratch_virtual();

  ulong cu_avail = ULONG_MAX;
  txn_ctx->compute_meter      = cu_avail;
  txn_ctx->compute_unit_limit = cu_avail;

  fd_exec_instr_ctx_t instr_ctx[1] = {{0}};
  instr_ctx->epoch_ctx = epoch_ctx;
  instr_ctx->slot_ctx  = slot_ctx;
  instr_ctx->txn_ctx   = txn_ctx;

  /* Set up VM */

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  /* Set up accounts */

  uchar * account1 = fd_scratch_alloc( 32, 0x1000000 );
  memset( account1, 0, 0x1000000 );
  uchar account2[ 32 ] = {0};
  account_meta_t metas[2] = {
    {
      .pubkey   = {0},
      .owner    = {0},
      .data     = 3UL<<32,
      .data_len = 0x1000000,
      .lamports = 1000000000,
      .flags    = 0
    },
    {
      .pubkey   = {0},
      .owner    = {0},
      .data     = 4UL<<32,
      .data_len = sizeof(account2),
      .lamports = 1000000000,
      .flags    = 0
    }
  };

  /* Region 0: Sentinel */
  fd_jit_mem_ro_sz[0] = 0;
  fd_jit_mem_rw_sz[0] = 0;
  fd_jit_mem_base [0] = 0;

  /* Region 1: Stack */
# define VM_STACK_SZ 0x10000UL
  void * stack_mem = fd_scratch_alloc( 0x10, VM_STACK_SZ );
  fd_jit_mem_ro_sz[1] = VM_STACK_SZ;
  fd_jit_mem_rw_sz[1] = VM_STACK_SZ;
  fd_jit_mem_base [1] = (ulong)stack_mem;

  /* Region 2: Metadata table */
  fd_jit_mem_ro_sz[2] = sizeof(metas);
  fd_jit_mem_rw_sz[2] = sizeof(metas);
  fd_jit_mem_base [2] = (ulong)metas;

  /* Region 3: Account */
  fd_jit_mem_ro_sz[3] = (uint)metas[0].data_len;
  fd_jit_mem_rw_sz[3] = 0;
  fd_jit_mem_base [3] = (ulong)account1;

  /* Region 4: Account */
  fd_jit_mem_ro_sz[4] = sizeof(account2);
  fd_jit_mem_rw_sz[4] = sizeof(account2);
  fd_jit_mem_base [4] = (ulong)account2;

  fd_jit_segment_cnt = 5U;

  fd_vm_input_region_t mem_regions[5];
  for( uint j=0U; j<fd_jit_segment_cnt; j++ ) {
    mem_regions[j] = (fd_vm_input_region_t) {
      .vaddr_offset = ((ulong)j)<<32,
      .haddr        = fd_jit_mem_base [j],
      .region_sz    = fd_jit_mem_ro_sz[j],
      .is_writable  = fd_jit_mem_rw_sz[j] > 0
    };
  }

  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_scratch_alloc( fd_vm_align(), fd_vm_footprint() ) ) );
  FD_TEST( vm );
  // ulong event_max = 1UL<<20;
  // ulong event_data_max = 2048UL;
  //fd_vm_trace_t * trace = fd_vm_trace_new( aligned_alloc( fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max );
  FD_TEST( fd_vm_init(
    vm,
    instr_ctx,
    FD_VM_HEAP_DEFAULT,  /* heap_max */
    txn_ctx->compute_meter, /* entry_cu */
    rodata, /* rodata */
    elf_info.rodata_sz, /* rodata_sz */
    prog->text, /* text */
    prog->text_cnt, /* text_cnt */
    prog->text_off, /* text_off */
    prog->text_sz,  /* text_sz */
    prog->entry_pc, /* entry_pc */
    prog->calldests, /* calldests */
    syscalls,
    NULL,// trace,
    sha,
    mem_regions,
    fd_jit_segment_cnt,
    NULL, /* acc_region_metas */
    0 /* is_deprecated */ ) );

  vm->reg[ 1] = 2UL<<32; /* account table address */
  vm->reg[ 2] = 2; /* account count */
  vm->reg[ 3] = 3UL<<32; /* instruction data address */
  vm->reg[ 4] = 0; /* instruction data size */
  vm->reg[10] = (1UL<<32) + 0x1000;

  for( uint j=0U; j<fd_jit_segment_cnt; j++ ) {
    vm->region_haddr[j] = fd_jit_mem_base[j];
    vm->region_ld_sz[j] = fd_jit_mem_ro_sz[j];
    vm->region_st_sz[j] = fd_jit_mem_rw_sz[j];
  }

  fd_jit_vm = vm;

  printf( "vm at %p\n", (void *)vm );

  /* Set up dynasm */

  dasm_State * d;

  //| .section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 459 "fd_vm_jitproto.dasc"
  dasm_init( &d, DASM_MAXSECTION );
  fd_jit_dasm = d;

  dasm_setupglobal( &d, labels, lbl__MAX );

  dasm_growpc( &d, (uint)prog->text_cnt );
  int next_label = 0;

  //| .actionlist actions
static const unsigned char actions[1500] = {
  254,0,248,10,72,199,192,231,3,0,0,252,233,244,11,255,248,12,72,199,192,231,
  3,0,0,252,233,244,11,255,248,13,72,193,231,32,72,9,215,100,72,137,60,37,237,
  72,131,196,8,252,233,244,12,255,248,14,137,252,250,72,193,252,239,32,100,
  59,60,37,237,15,131,244,13,137,208,33,232,133,192,15,133,244,13,1,213,15,
  130,244,13,100,59,44,189,237,15,131,244,13,100,72,3,20,252,253,237,195,248,
  15,137,252,250,72,193,252,239,32,100,59,60,37,237,15,131,244,13,137,208,33,
  232,133,192,15,133,244,13,1,213,15,130,244,13,255,100,59,44,189,237,15,131,
  244,13,100,72,3,20,252,253,237,195,255,248,16,72,184,237,237,72,137,176,233,
  76,137,152,233,76,137,160,233,76,137,168,233,76,137,176,233,76,137,184,233,
  72,137,152,233,72,137,136,233,76,137,128,233,76,137,136,233,76,137,144,233,
  195,255,248,17,72,184,237,237,72,139,176,233,76,139,152,233,76,139,160,233,
  76,139,168,233,76,139,176,233,76,139,184,233,72,139,152,233,72,139,136,233,
  76,139,128,233,76,139,136,233,76,139,144,233,195,255,248,18,232,244,16,137,
  232,72,137,229,255,72,131,228,252,240,85,85,72,137,214,137,194,72,199,192,
  237,252,255,208,72,137,199,93,93,72,137,252,236,232,244,17,72,133,252,255,
  15,132,244,19,72,131,196,8,252,255,231,248,19,195,255,248,20,232,244,16,72,
  199,192,237,252,255,208,72,137,199,232,244,17,72,133,252,255,15,132,244,21,
  72,131,196,8,252,255,231,248,21,195,255,248,22,255,85,65,87,65,86,65,85,65,
  84,83,255,232,244,17,252,255,231,255,249,255,64,129,192,240,43,239,255,252,
  233,245,255,72,129,192,240,35,239,255,64,1,192,240,131,240,51,255,72,1,192,
  240,131,240,35,255,64,129,232,240,43,239,255,72,129,252,248,240,35,239,255,
  15,132,245,255,72,129,232,240,35,239,255,64,49,192,240,131,240,51,255,72,
  199,192,240,35,237,255,64,41,192,240,131,240,51,255,72,57,192,240,131,240,
  35,15,132,245,255,72,41,192,240,131,240,35,255,64,105,192,240,131,240,51,
  239,255,72,129,252,248,240,35,239,15,135,245,255,72,105,192,240,131,240,35,
  239,255,64,15,175,192,240,132,240,52,255,72,57,192,240,131,240,35,15,135,
  245,255,72,15,175,192,240,132,240,36,255,252,233,244,10,255,64,144,240,42,
  49,210,191,237,252,247,252,247,64,144,240,42,255,72,129,252,248,240,35,239,
  15,131,245,255,72,144,240,34,49,210,72,199,199,237,72,252,247,252,247,72,
  144,240,34,255,64,133,192,240,131,240,51,15,132,244,10,255,64,184,240,42,
  1,0,0,0,255,64,144,240,42,49,210,64,252,247,252,240,240,43,64,144,240,42,
  255,72,57,192,240,131,240,35,15,131,245,255,72,133,192,240,131,240,35,15,
  132,244,10,255,72,144,240,34,49,210,72,252,247,252,240,240,35,72,144,240,
  34,255,64,129,200,240,43,239,255,72,252,247,192,240,35,237,15,133,245,255,
  72,129,200,240,35,239,255,64,9,192,240,131,240,51,255,72,133,192,240,131,
  240,35,15,133,245,255,72,9,192,240,131,240,35,255,64,129,224,240,43,239,255,
  72,129,252,248,240,35,239,15,133,245,255,72,129,224,240,35,239,255,64,33,
  192,240,131,240,51,255,72,57,192,240,131,240,35,15,133,245,255,72,33,192,
  240,131,240,35,255,72,141,184,253,240,3,233,189,3,0,0,0,232,244,15,64,139,
  2,240,139,255,72,141,184,253,240,3,233,189,3,0,0,0,232,244,14,199,2,237,255,
  72,141,184,253,240,3,233,189,3,0,0,0,232,244,14,64,137,2,240,139,255,64,193,
  224,240,43,235,255,72,129,252,248,240,35,239,15,143,245,255,72,193,224,240,
  35,235,255,72,141,184,253,240,3,233,189,1,0,0,0,232,244,15,64,49,192,240,
  131,240,51,102,64,139,2,240,139,255,72,141,184,253,240,3,233,189,1,0,0,0,
  232,244,14,102,199,2,236,255,72,141,184,253,240,3,233,189,1,0,0,0,232,244,
  14,64,137,2,240,139,255,64,136,193,240,131,64,211,224,240,43,255,72,57,192,
  240,131,240,35,15,143,245,255,64,136,193,240,131,72,211,224,240,35,255,72,
  141,184,253,240,3,233,49,252,237,232,244,15,255,64,49,192,240,131,240,51,
  64,138,2,240,131,255,72,141,184,253,240,3,233,49,252,237,232,244,14,198,2,
  235,255,72,141,184,253,240,3,233,49,252,237,232,244,14,64,136,2,240,131,255,
  64,193,232,240,43,235,255,72,129,252,248,240,35,239,15,141,245,255,72,193,
  232,240,35,235,255,72,141,184,253,240,3,233,189,7,0,0,0,232,244,15,72,139,
  2,240,131,255,72,141,184,253,240,3,233,189,7,0,0,0,232,244,14,72,199,192,
  237,72,137,2,255,72,141,184,253,240,3,233,189,7,0,0,0,232,244,14,72,137,2,
  240,131,255,64,136,193,240,131,64,211,232,240,43,255,72,57,192,240,131,240,
  35,15,141,245,255,64,136,193,240,131,72,211,232,240,35,255,64,252,247,216,
  240,43,255,72,199,199,237,72,199,194,237,255,189,237,255,49,252,237,255,232,
  244,18,255,72,252,247,216,240,35,255,64,144,240,42,49,210,191,237,252,247,
  252,247,64,135,208,240,43,255,232,244,20,252,233,244,23,255,64,184,240,42,
  0,0,0,0,255,64,144,240,42,49,210,64,252,247,252,240,240,43,64,135,208,240,
  43,255,72,144,240,34,49,210,72,252,247,252,240,240,35,72,135,208,240,35,255,
  64,129,252,240,240,43,239,255,72,129,252,248,240,35,239,15,130,245,255,72,
  129,252,240,240,35,239,255,72,57,192,240,131,240,35,15,130,245,255,72,49,
  192,240,131,240,35,255,64,184,240,42,237,255,72,129,252,248,240,35,239,15,
  134,245,255,64,137,192,240,131,240,51,255,72,57,192,240,131,240,35,15,134,
  245,255,72,137,192,240,131,240,35,255,64,193,252,248,240,43,235,255,72,129,
  252,248,240,35,239,15,140,245,255,72,193,252,248,240,35,235,255,64,136,193,
  240,131,64,211,252,248,240,43,255,72,57,192,240,131,240,35,15,140,245,255,
  64,136,193,240,131,72,211,252,248,240,35,255,72,129,252,248,240,35,239,15,
  142,245,255,64,15,183,192,240,132,240,52,102,64,193,200,240,43,8,255,64,15,
  200,240,43,255,72,15,200,240,35,255,72,57,192,240,131,240,35,15,142,245,255,
  248,24,72,199,192,231,3,0,0,252,233,244,11,255,248,23,72,137,252,240,248,
  11,91,65,92,65,93,65,94,65,95,93,195,255
};

#line 468 "fd_vm_jitproto.dasc"
  dasm_setup( &d, actions );

  dasm_State ** Dst = &d;

  /* Start emitting code */

  //| .code
  dasm_put(Dst, 0);
#line 475 "fd_vm_jitproto.dasc"

  /* Exception handlers */

  /* TODO */
  //|->sigfpe:
  //| mov rax, 999
  //| jmp ->leave
  dasm_put(Dst, 2);
#line 482 "fd_vm_jitproto.dasc"

  //|->sigsegv:
  //| mov rax, 999
  //| jmp ->leave
  dasm_put(Dst, 16);
#line 486 "fd_vm_jitproto.dasc"

  /* Address translation macros

     The translate_{rw,ro}_{1,2,4,8} macros perform address translation
     and access permission checks for {read-write,read-only} accesses of
     {1,2,4,8} bytes.  The compiler may inline this macro for each
     translated sBPF instruction, so these should be optimized for small
     size.

     Prior to the macro, rdi holds an address in the virtual address
     space (untrusted in [0,2^64)).  If translation and permission
     checks succeed, rdx holds the translated address in the host
     address space.  On failure jumps to sigsegv.  Reasons for failure
     include access to out-of-bounds memory, unaligned address, access
     permission error. */

  ulong fs_base; __asm__( "mov %%fs:0, %0" : "=r"(fs_base) );
  uint  fd_jit_segment_cnt_tpoff    = (uint)( (ulong)&fd_jit_segment_cnt - fs_base );
  uint  fd_jit_mem_ro_sz_tpoff      = (uint)( (ulong)fd_jit_mem_ro_sz    - fs_base );
  uint  fd_jit_mem_rw_sz_tpoff      = (uint)( (ulong)fd_jit_mem_rw_sz    - fs_base );
  uint  fd_jit_mem_base_tpoff       = (uint)( (ulong)fd_jit_mem_base     - fs_base );
  uint  fd_jit_segfault_vaddr_tpoff = (uint)( (ulong)&fd_jit_segfault_vaddr - fs_base );

  //|.macro gen_scalar_translate, sz_table_tpoff
  //| // rdi := virtual address
  //| // ebp := size of the access minus 1
  //|
  //| // edx := segment offset
  //| mov edx, edi
  //|
  //| // edi := segment index
  //| shr rdi, 32
  //|
  //| // segment index in bounds?
  //| fs
  //| cmp edi, [fd_jit_segment_cnt_tpoff]
  //| jae ->translate_fail
  //|
  //| // aligned access?
  //| mov eax, edx
  //| and eax, ebp
  //| test eax, eax
  //| jnz ->translate_fail
  //|
  //| // no multi segment overlap?
  //| add ebp, edx
  //| jc ->translate_fail
  //|
  //| // segment offset in bounds?
  //| fs
  //| cmp ebp, [rdi*4 + sz_table_tpoff]
  //| jae ->translate_fail
  //|
  //| // rdx := host address
  //| fs
  //| add rdx, [rdi*8 + fd_jit_mem_base_tpoff]
  //| ret
  //|.endmacro

  //|->translate_fail:
  //| shl rdi, 32
  //| or rdi, rdx
  //| fs
  //| mov [fd_jit_segfault_vaddr_tpoff], rdi
  //| add rsp, 8
  //| jmp ->sigsegv
  dasm_put(Dst, 30, fd_jit_segfault_vaddr_tpoff);
#line 552 "fd_vm_jitproto.dasc"

  //|->fd_jit_vm_translate_rw:
  //| gen_scalar_translate, fd_jit_mem_rw_sz_tpoff
  //|->fd_jit_vm_translate_ro:
  //| gen_scalar_translate, fd_jit_mem_ro_sz_tpoff
  dasm_put(Dst, 54, fd_jit_segment_cnt_tpoff, fd_jit_mem_rw_sz_tpoff, fd_jit_mem_base_tpoff, fd_jit_segment_cnt_tpoff);
  dasm_put(Dst, 142, fd_jit_mem_ro_sz_tpoff, fd_jit_mem_base_tpoff);
#line 557 "fd_vm_jitproto.dasc"

  //|.macro translate_rw_1
  //| xor ebp, ebp
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_2
  //| mov ebp, 1
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_4
  //| mov ebp, 3
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_rw_8
  //| mov ebp, 7
  //| call ->fd_jit_vm_translate_rw
  //|.endmacro

  //|.macro translate_ro_1
  //| xor ebp, ebp
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_2
  //| mov ebp, 1
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_4
  //| mov ebp, 3
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|.macro translate_ro_8
  //| mov ebp, 7
  //| call ->fd_jit_vm_translate_ro
  //|.endmacro

  //|->save_regs:
  //| mov64 rax, (ulong)vm
  //| mov [rax + offsetof(fd_vm_t, reg[ 0])], bpf_r0
  //| mov [rax + offsetof(fd_vm_t, reg[ 1])], bpf_r1
  //| mov [rax + offsetof(fd_vm_t, reg[ 2])], bpf_r2
  //| mov [rax + offsetof(fd_vm_t, reg[ 3])], bpf_r3
  //| mov [rax + offsetof(fd_vm_t, reg[ 4])], bpf_r4
  //| mov [rax + offsetof(fd_vm_t, reg[ 5])], bpf_r5
  //| mov [rax + offsetof(fd_vm_t, reg[ 6])], bpf_r6
  //| mov [rax + offsetof(fd_vm_t, reg[ 7])], bpf_r7
  //| mov [rax + offsetof(fd_vm_t, reg[ 8])], bpf_r8
  //| mov [rax + offsetof(fd_vm_t, reg[ 9])], bpf_r9
  //| mov [rax + offsetof(fd_vm_t, reg[10])], bpf_r10
  //| ret
  dasm_put(Dst, 160, (unsigned int)((ulong)vm), (unsigned int)(((ulong)vm)>>32), offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 612 "fd_vm_jitproto.dasc"

  //|->restore_regs:
  //| mov64 rax, (ulong)vm
  //| mov bpf_r0,  [rax + offsetof(fd_vm_t, reg[ 0])]
  //| mov bpf_r1,  [rax + offsetof(fd_vm_t, reg[ 1])]
  //| mov bpf_r2,  [rax + offsetof(fd_vm_t, reg[ 2])]
  //| mov bpf_r3,  [rax + offsetof(fd_vm_t, reg[ 3])]
  //| mov bpf_r4,  [rax + offsetof(fd_vm_t, reg[ 4])]
  //| mov bpf_r5,  [rax + offsetof(fd_vm_t, reg[ 5])]
  //| mov bpf_r6,  [rax + offsetof(fd_vm_t, reg[ 6])]
  //| mov bpf_r7,  [rax + offsetof(fd_vm_t, reg[ 7])]
  //| mov bpf_r8,  [rax + offsetof(fd_vm_t, reg[ 8])]
  //| mov bpf_r9,  [rax + offsetof(fd_vm_t, reg[ 9])]
  //| mov bpf_r10, [rax + offsetof(fd_vm_t, reg[10])]
  //| ret
  dasm_put(Dst, 212, (unsigned int)((ulong)vm), (unsigned int)(((ulong)vm)>>32), offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 627 "fd_vm_jitproto.dasc"

  //|->emulate_call_imm:
  //| call ->save_regs
  //| mov eax, ebp // arg 3
  //| mov rbp, rsp
  dasm_put(Dst, 264);
#line 632 "fd_vm_jitproto.dasc"
  /* Align stack pointer by 16 */
  //| and rsp, -16
  //| push rbp
  //| push rbp
  //| // arg 1 already in rdi
  //| mov rsi, rdx // arg 2
  //| mov edx, eax // arg 3
  //| mov rax, &&fd_jit_op_call_imm
  //| call rax
  //| mov rdi, rax // x86 jump address (todo make this static)
  //| pop rbp
  //| pop rbp
  //| mov rsp, rbp
  //| call ->restore_regs
  //| test rdi, rdi
  //| jz ->emulate_call_imm_ret
  //| add rsp, 8
  //| jmp rdi
  //|->emulate_call_imm_ret:
  //| ret
  dasm_put(Dst, 275, (ptrdiff_t)(&fd_jit_op_call_imm));
#line 652 "fd_vm_jitproto.dasc"

  //|->emulate_exit:
  //| call ->save_regs
  //| mov rax, &&fd_jit_op_exit
  //| call rax
  //| mov rdi, rax // return address
  //| call ->restore_regs
  //| test rdi, rdi
  //| jz ->emulate_exit_ret
  //| add rsp, 8
  //| jmp rdi
  //|->emulate_exit_ret:
  //| ret
  dasm_put(Dst, 325, (ptrdiff_t)(&fd_jit_op_exit));
#line 665 "fd_vm_jitproto.dasc"

  /* Start translating user code */

  //|->main:
  dasm_put(Dst, 362);
#line 669 "fd_vm_jitproto.dasc"

  /* Back up execution state */

  //| push rbp
  //| push r15
  //| push r14
  //| push r13
  //| push r12
  //| push rbx
  dasm_put(Dst, 365);
#line 678 "fd_vm_jitproto.dasc"

  /* Restore register context */

  //| call ->restore_regs
  //| jmp rdi
  dasm_put(Dst, 376);
#line 683 "fd_vm_jitproto.dasc"

  //ulong         text_skip  = prog->text_off >> 3;
  ulong * const text_start = prog->text;
  ulong *       text_end   = prog->text + prog->text_cnt;

  int bpf_label_off = next_label;

  for( ulong * cur=text_start; cur<text_end; cur++ ) {
    ulong instr = *cur;

    ulong opcode  = fd_vm_instr_opcode( instr ); /* in [0,256) even if malformed */
    ulong dst     = fd_vm_instr_dst   ( instr ); /* in [0, 16) even if malformed */
    ulong src     = fd_vm_instr_src   ( instr ); /* in [0, 16) even if malformed */
    short offset  = fd_vm_instr_offset( instr ); /* in [-2^15,2^15) even if malformed */
    uint  imm     = fd_vm_instr_imm   ( instr ); /* in [0,2^32) even if malformed */

    /* Macros for translating register accesses */

    uint x86_dst = reg_bpf2x86[ dst ];
    uint x86_src = reg_bpf2x86[ src ];

    //| .define dst64, Rq(x86_dst)
    //| .define src64, Rq(x86_src)
    //| .define dst32, Rd(x86_dst)
    //| .define src32, Rd(x86_src)
    //| .define src8,  Rb(x86_src)

    /* Macro for translating jumps */

    ulong * jmp_dst       = cur + 1 + offset; /* may be OOB, FIXME validate */
    int     jmp_dst_lbl   = bpf_label_off + (int)( jmp_dst - text_start );
    //int     jmp_bounds_ok = jmp_dst>=text_start && jmp<text_end;
    /* FIXME do a bounds check */
    /* FIXME what happens if the label is not set? */

    /* FIXME CU accounting */

    /* Create a dynamic label for each instruction */

    uint cur_pc = (uint)( cur - text_start );
    next_label = bpf_label_off + (int)cur_pc;
    //|=>next_label:
    dasm_put(Dst, 383, next_label);
#line 725 "fd_vm_jitproto.dasc"

    /* Translate instruction */

    switch( opcode ) {

    /* 0x00 - 0x0f ******************************************************/

    case 0x04:  /* FD_SBPF_OP_ADD_IMM */
      //| add dst32, imm
      dasm_put(Dst, 385, (x86_dst), imm);
#line 734 "fd_vm_jitproto.dasc"
      break;

    case 0x05:  /* FD_SBPF_OP_JA */
      //| jmp =>jmp_dst_lbl
      dasm_put(Dst, 392, jmp_dst_lbl);
#line 738 "fd_vm_jitproto.dasc"
      break;

    case 0x07:  /* FD_SBPF_OP_ADD64_IMM */
      //| add dst64, imm
      dasm_put(Dst, 396, (x86_dst), imm);
#line 742 "fd_vm_jitproto.dasc"
      break;

    case 0x0c:  /* FD_SBPF_OP_ADD_REG */
      //| add dst32, src32
      dasm_put(Dst, 403, (x86_src), (x86_dst));
#line 746 "fd_vm_jitproto.dasc"
      break;

    case 0x0f:  /* FD_SBPF_OP_ADD64_REG */
      //| add dst64, src64
      dasm_put(Dst, 411, (x86_src), (x86_dst));
#line 750 "fd_vm_jitproto.dasc"
      break;

    /* 0x10 - 0x1f ******************************************************/

    case 0x14:  /* FD_SBPF_OP_SUB_IMM */
      //| sub dst32, imm
      dasm_put(Dst, 419, (x86_dst), imm);
#line 756 "fd_vm_jitproto.dasc"
      break;

    case 0x15:  /* FD_SBPF_OP_JEQ_IMM */
      //| cmp dst64, imm
      dasm_put(Dst, 426, (x86_dst), imm);
#line 760 "fd_vm_jitproto.dasc"
      /* pre branch check here ... branchless cu update? */
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 434, jmp_dst_lbl);
#line 762 "fd_vm_jitproto.dasc"
      break;

    case 0x17:  /* FD_SBPF_OP_SUB64_IMM */
      //| sub dst64, imm
      dasm_put(Dst, 438, (x86_dst), imm);
#line 766 "fd_vm_jitproto.dasc"
      break;

    case 0x18:  /* FD_SBPF_OP_LDQ */
      cur++; {
      ulong imm64 = (ulong)imm | ( (ulong)fd_vm_instr_imm( *cur ) << 32 );
      if( imm64==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 445, (x86_dst), (x86_dst));
#line 773 "fd_vm_jitproto.dasc"
      } else {
        //| mov dst64, imm64
        dasm_put(Dst, 453, (x86_dst), imm64);
#line 775 "fd_vm_jitproto.dasc"
      }
      break;
    }

    case 0x1c:  /* FD_SBPF_OP_SUB_REG */
      //| sub dst32, src32
      dasm_put(Dst, 460, (x86_src), (x86_dst));
#line 781 "fd_vm_jitproto.dasc"
      break;

    case 0x1d:  /* FD_SBPF_OP_JEQ_REG */
      //| cmp dst64, src64
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 468, (x86_src), (x86_dst), jmp_dst_lbl);
#line 786 "fd_vm_jitproto.dasc"
      break;

    case 0x1f:  /* FD_SBPF_OP_SUB64_REG */
      //| sub dst64, src64
      dasm_put(Dst, 479, (x86_src), (x86_dst));
#line 790 "fd_vm_jitproto.dasc"
      break;

    /* 0x20 - 0x2f ******************************************************/

    case 0x24:  /* FD_SBPF_OP_MUL_IMM */
      /* TODO strength reduction? */
      //| imul dst32, imm
      dasm_put(Dst, 487, (x86_dst), (x86_dst), imm);
#line 797 "fd_vm_jitproto.dasc"
      break;

    case 0x25:  /* FD_SBPF_OP_JGT_IMM */
      //| cmp dst64, imm
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 496, (x86_dst), imm, jmp_dst_lbl);
#line 802 "fd_vm_jitproto.dasc"
      break;

    case 0x27:  /* FD_SBPF_OP_MUL64_IMM */
      /* TODO strength reduction? */
      //| imul dst64, imm
      dasm_put(Dst, 507, (x86_dst), (x86_dst), imm);
#line 807 "fd_vm_jitproto.dasc"
      break;

    case 0x2c:  /* FD_SBPF_OP_MUL_REG */
      //| imul dst32, src32
      dasm_put(Dst, 516, (x86_dst), (x86_src));
#line 811 "fd_vm_jitproto.dasc"
      break;

    case 0x2d:  /* FD_SBPF_OP_JGT_REG */
      //| cmp dst64, src64
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 525, (x86_src), (x86_dst), jmp_dst_lbl);
#line 816 "fd_vm_jitproto.dasc"
      break;

    case 0x2f:  /* FD_SBPF_OP_MUL64_REG */
      //| imul dst64, src64
      dasm_put(Dst, 536, (x86_dst), (x86_src));
#line 820 "fd_vm_jitproto.dasc"
      break;

    /* 0x30 - 0x3f ******************************************************/

    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 545);
#line 827 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg eax, dst32
      dasm_put(Dst, 550, (x86_dst), imm, (x86_dst));
#line 834 "fd_vm_jitproto.dasc"
      break;

    case 0x35:  /* FD_SBPF_OP_JGE_IMM */
      //| cmp dst64, imm
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 567, (x86_dst), imm, jmp_dst_lbl);
#line 839 "fd_vm_jitproto.dasc"
      break;

    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 545);
#line 844 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 578, (x86_dst), imm, (x86_dst));
#line 851 "fd_vm_jitproto.dasc"
      break;

    case 0x3c:  /* FD_SBPF_OP_DIV_REG */
      //| test src32, src32
      //| jz ->sigfpe
      dasm_put(Dst, 598, (x86_src), (x86_src));
#line 856 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 610, (x86_dst));
#line 858 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg eax, dst32
      dasm_put(Dst, 619, (x86_dst), (x86_src), (x86_dst));
#line 864 "fd_vm_jitproto.dasc"
      break;

    case 0x3d:  /* FD_SBPF_OP_JGE_REG */
      //| cmp dst64, src64
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 637, (x86_src), (x86_dst), jmp_dst_lbl);
#line 869 "fd_vm_jitproto.dasc"
      break;

    case 0x3f:  /* FD_SBPF_OP_DIV64_REG */
      //| test src64, src64
      //| jz ->sigfpe
      dasm_put(Dst, 648, (x86_src), (x86_src));
#line 874 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 610, (x86_dst));
#line 876 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rax, dst64
      dasm_put(Dst, 660, (x86_dst), (x86_src), (x86_dst));
#line 882 "fd_vm_jitproto.dasc"
      break;

    /* 0x40 - 0x4f ******************************************************/

    case 0x44:  /* FD_SBPF_OP_OR_IMM */
      //| or dst32, imm
      dasm_put(Dst, 678, (x86_dst), imm);
#line 888 "fd_vm_jitproto.dasc"
      break;

    case 0x45:  /* FD_SBPF_OP_JSET_IMM */
      //| test dst64, imm
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 685, (x86_dst), imm, jmp_dst_lbl);
#line 893 "fd_vm_jitproto.dasc"
      break;

    case 0x47:  /* FD_SBPF_OP_OR64_IMM */
      //| or dst64, imm
      dasm_put(Dst, 696, (x86_dst), imm);
#line 897 "fd_vm_jitproto.dasc"
      break;

    case 0x4c:  /* FD_SBPF_OP_OR_REG */
      //| or dst32, src32
      dasm_put(Dst, 703, (x86_src), (x86_dst));
#line 901 "fd_vm_jitproto.dasc"
      break;

    case 0x4d:  /* FD_SBPF_OP_JSET_REG */
      //| test dst64, src64
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 711, (x86_src), (x86_dst), jmp_dst_lbl);
#line 906 "fd_vm_jitproto.dasc"
      break;

    case 0x4f:  /* FD_SBPF_OP_OR64_REG */
      //| or dst64, src64
      dasm_put(Dst, 722, (x86_src), (x86_dst));
#line 910 "fd_vm_jitproto.dasc"
      break;

    /* 0x50 - 0x5f ******************************************************/

    case 0x54:  /* FD_SBPF_OP_AND_IMM */
      //| and dst32, imm
      dasm_put(Dst, 730, (x86_dst), imm);
#line 916 "fd_vm_jitproto.dasc"
      break;

    case 0x55:  /* FD_SBPF_OP_JNE_IMM */
      //| cmp dst64, imm
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 737, (x86_dst), imm, jmp_dst_lbl);
#line 921 "fd_vm_jitproto.dasc"
      break;

    case 0x57:  /* FD_SBPF_OP_AND64_IMM */
      //| and dst64, imm
      dasm_put(Dst, 748, (x86_dst), imm);
#line 925 "fd_vm_jitproto.dasc"
      break;

    case 0x5c:  /* FD_SBPF_OP_AND_REG */
      //| and dst32, src32
      dasm_put(Dst, 755, (x86_src), (x86_dst));
#line 929 "fd_vm_jitproto.dasc"
      break;

    case 0x5d:  /* FD_SBPF_OP_JNE_REG */
      //| cmp dst64, src64
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 763, (x86_src), (x86_dst), jmp_dst_lbl);
#line 934 "fd_vm_jitproto.dasc"
      break;

    case 0x5f:  /* FD_SBPF_OP_AND64_REG */
      //| and dst64, src64
      dasm_put(Dst, 774, (x86_src), (x86_dst));
#line 938 "fd_vm_jitproto.dasc"
      break;

    /* 0x60 - 0x6f ******************************************************/

    case 0x61:  /* FD_SBPF_OP_LDXW */
      //| lea translate_in, [src64+offset]
      //| translate_ro_4
      //| mov dst32, [translate_out]
      dasm_put(Dst, 782, (x86_src), offset, (x86_dst));
#line 946 "fd_vm_jitproto.dasc"
      break;

    case 0x62:  /* FD_SBPF_OP_STW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov dword [translate_out], imm
      dasm_put(Dst, 803, (x86_dst), offset, imm);
#line 952 "fd_vm_jitproto.dasc"
      break;

    case 0x63:  /* FD_SBPF_OP_STXW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov [translate_out], src32
      dasm_put(Dst, 822, (x86_dst), offset, (x86_src));
#line 958 "fd_vm_jitproto.dasc"
      break;

    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
      //| shl dst32, imm
      dasm_put(Dst, 843, (x86_dst), imm);
#line 962 "fd_vm_jitproto.dasc"
      break;

    case 0x65:  /* FD_SBPF_OP_JSGT_IMM */
      //| cmp dst64, imm
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 850, (x86_dst), imm, jmp_dst_lbl);
#line 967 "fd_vm_jitproto.dasc"
      break;

    case 0x67:  /* FD_SBPF_OP_LSH64_IMM */
      //| shl dst64, imm
      dasm_put(Dst, 861, (x86_dst), imm);
#line 971 "fd_vm_jitproto.dasc"
      break;

    case 0x69:  /* FD_SBPF_OP_LDXH */
      //| lea translate_in, [src64+offset]
      //| translate_ro_2
      //| xor dst32, dst32
      //| mov Rw(x86_dst), [translate_out]
      dasm_put(Dst, 868, (x86_src), offset, (x86_dst), (x86_dst), (x86_dst));
#line 978 "fd_vm_jitproto.dasc"
      break;

    case 0x6a:  /* FD_SBPF_OP_STH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov word [translate_out], imm
      dasm_put(Dst, 897, (x86_dst), offset, imm);
#line 984 "fd_vm_jitproto.dasc"
      break;

    case 0x6b:  /* FD_SBPF_OP_STXH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov [translate_out], src32
      dasm_put(Dst, 917, (x86_dst), offset, (x86_src));
#line 990 "fd_vm_jitproto.dasc"
      break;

    case 0x6c:  /* FD_SBPF_OP_LSH_REG */
      //| mov cl, src8
      //| shl dst32, cl
      dasm_put(Dst, 938, (x86_src), (x86_dst));
#line 995 "fd_vm_jitproto.dasc"
      break;

    case 0x6d:  /* FD_SBPF_OP_JSGT_REG */
      //| cmp dst64, src64
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 949, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1000 "fd_vm_jitproto.dasc"
      break;

    case 0x6f:  /* FD_SBPF_OP_LSH64_REG */
      //| mov cl, src8
      //| shl dst64, cl
      dasm_put(Dst, 960, (x86_src), (x86_dst));
#line 1005 "fd_vm_jitproto.dasc"
      break;

    /* 0x70 - 0x7f ******************************************************/

    case 0x71:  /* FD_SBPF_OP_LDXB */
      //| lea translate_in, [src64+offset]
      //| translate_ro_1
      dasm_put(Dst, 971, (x86_src), offset);
#line 1012 "fd_vm_jitproto.dasc"
      /* TODO is there a better way to zero upper and mov byte? */
      //| xor dst32, dst32
      //| mov Rb(x86_dst), [translate_out]
      dasm_put(Dst, 985, (x86_dst), (x86_dst), (x86_dst));
#line 1015 "fd_vm_jitproto.dasc"
      break;

    case 0x72:  /* FD_SBPF_OP_STB */
      //| lea translate_in, [src64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], imm
      dasm_put(Dst, 998, (x86_src), offset, imm);
#line 1021 "fd_vm_jitproto.dasc"
      break;

    case 0x73:  /* FD_SBPF_OP_STXB */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], Rb(x86_src)
      dasm_put(Dst, 1015, (x86_dst), offset, (x86_src));
#line 1027 "fd_vm_jitproto.dasc"
      break;

    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
      //| shr dst32, imm
      dasm_put(Dst, 1034, (x86_dst), imm);
#line 1031 "fd_vm_jitproto.dasc"
      break;

    case 0x75:  /* FD_SBPF_OP_JSGE_IMM */
      //| cmp dst64, imm
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1041, (x86_dst), imm, jmp_dst_lbl);
#line 1036 "fd_vm_jitproto.dasc"
      break;

    case 0x77:  /* FD_SBPF_OP_RSH64_IMM */
      //| shr dst64, imm
      dasm_put(Dst, 1052, (x86_dst), imm);
#line 1040 "fd_vm_jitproto.dasc"
      break;

    case 0x79:  /* FD_SBPF_OP_LDXQ */
      //| lea translate_in, [src64+offset]
      //| translate_ro_8
      //| mov dst64, [translate_out]
      dasm_put(Dst, 1059, (x86_src), offset, (x86_dst));
#line 1046 "fd_vm_jitproto.dasc"
      break;

    case 0x7a:  /* FD_SBPF_OP_STQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov rax, imm
      //| mov [translate_out], rax
      dasm_put(Dst, 1080, (x86_dst), offset, imm);
#line 1053 "fd_vm_jitproto.dasc"
      break;

    case 0x7b:  /* FD_SBPF_OP_STXQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov [translate_out], src64
      dasm_put(Dst, 1103, (x86_dst), offset, (x86_src));
#line 1059 "fd_vm_jitproto.dasc"
      break;

    case 0x7c:  /* FD_SBPF_OP_RSH_REG */
      //| mov cl, src8
      //| shr dst32, cl
      dasm_put(Dst, 1124, (x86_src), (x86_dst));
#line 1064 "fd_vm_jitproto.dasc"
      break;

    case 0x7d:  /* FD_SBPF_OP_JSGE_REG */
      //| cmp dst64, src64
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1135, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1069 "fd_vm_jitproto.dasc"
      break;

    case 0x7f:  /* FD_SBPF_OP_RSH64_REG */
      //| mov cl, src8
      //| shr dst64, cl
      dasm_put(Dst, 1146, (x86_src), (x86_dst));
#line 1074 "fd_vm_jitproto.dasc"
      break;

    /* 0x80-0x8f ********************************************************/

    case 0x84:  /* FD_SBPF_OP_NEG */
      //| neg dst32
      dasm_put(Dst, 1157, (x86_dst));
#line 1080 "fd_vm_jitproto.dasc"
      break;

    case 0x85: { /* FD_SBPF_OP_CALL_IMM */
      //| mov rdi, imm
      //| mov rdx, cur_pc
      dasm_put(Dst, 1164, imm, cur_pc);
#line 1085 "fd_vm_jitproto.dasc"
      ulong target_pc = (ulong)fd_pchash_inverse( imm );
      if( target_pc < prog->text_cnt ) {
        //| mov ebp, (uint)target_pc
        dasm_put(Dst, 1173, (uint)target_pc);
#line 1088 "fd_vm_jitproto.dasc"
      } else {
        //| xor ebp, ebp
        dasm_put(Dst, 1176);
#line 1090 "fd_vm_jitproto.dasc"
      }
      //| call ->emulate_call_imm
      dasm_put(Dst, 1180);
#line 1092 "fd_vm_jitproto.dasc"
      break;
    }

    case 0x87:  /* FD_SBPF_OP_NEG64 */
      //| neg dst64
      dasm_put(Dst, 1184, (x86_dst));
#line 1097 "fd_vm_jitproto.dasc"
      break;

    case 0x8d:  /* FD_SBPF_OP_CALL_REG */
      FD_LOG_WARNING(( "TODO: CALLX" ));
      break;

    /* 0x90 - 0x9f ******************************************************/

    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 545);
#line 1108 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg edx, dst32
      dasm_put(Dst, 1191, (x86_dst), imm, (x86_dst));
#line 1115 "fd_vm_jitproto.dasc"
      break;

    case 0x95:  /* FD_SBPF_OP_EXIT */
      //| call ->emulate_exit
      //| jmp ->success
      dasm_put(Dst, 1209);
#line 1120 "fd_vm_jitproto.dasc"
      break;

    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 545);
#line 1125 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 578, (x86_dst), imm, (x86_dst));
#line 1132 "fd_vm_jitproto.dasc"
      break;

    case 0x9c:  /* FD_SBPF_OP_MOD_REG */
      //| test src32, src32
      //| jz ->sigfpe
      dasm_put(Dst, 598, (x86_src), (x86_src));
#line 1137 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1217, (x86_dst));
#line 1139 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg edx, dst32
      dasm_put(Dst, 1226, (x86_dst), (x86_src), (x86_dst));
#line 1145 "fd_vm_jitproto.dasc"
      break;

    case 0x9f:  /* FD_SBPF_OP_MOD64_REG */
      //| test src64, src64
      //| jz ->sigfpe
      dasm_put(Dst, 648, (x86_src), (x86_src));
#line 1150 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1217, (x86_dst));
#line 1152 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rdx, dst64
      dasm_put(Dst, 1245, (x86_dst), (x86_src), (x86_dst));
#line 1158 "fd_vm_jitproto.dasc"
      break;

    /* 0xa0 - 0xaf ******************************************************/

    case 0xa4:  /* FD_SBPF_OP_XOR_IMM */
      //| xor dst32, imm
      dasm_put(Dst, 1264, (x86_dst), imm);
#line 1164 "fd_vm_jitproto.dasc"
      break;

    case 0xa5:  /* FD_SBPF_OP_JLT_IMM */
      //| cmp dst64, imm
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1272, (x86_dst), imm, jmp_dst_lbl);
#line 1169 "fd_vm_jitproto.dasc"
      break;

    case 0xa7:  /* FD_SBPF_OP_XOR64_IMM */
      // TODO sign extension
      //| xor dst64, imm
      dasm_put(Dst, 1283, (x86_dst), imm);
#line 1174 "fd_vm_jitproto.dasc"
      break;

    case 0xac:  /* FD_SBPF_OP_XOR_REG */
      //| xor dst32, src32
      dasm_put(Dst, 445, (x86_src), (x86_dst));
#line 1178 "fd_vm_jitproto.dasc"
      break;

    case 0xad:  /* FD_SBPF_OP_JLT_REG */
      //| cmp dst64, src64
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1291, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1183 "fd_vm_jitproto.dasc"
      break;

    case 0xaf:  /* FD_SBPF_OP_XOR64_REG */
      //| xor dst64, src64
      dasm_put(Dst, 1302, (x86_src), (x86_dst));
#line 1187 "fd_vm_jitproto.dasc"
      break;

    /* 0xb0 - 0xbf ******************************************************/

    case 0xb4:  /* FD_SBPF_OP_MOV_IMM */
      //| mov dst32, imm
      dasm_put(Dst, 1310, (x86_dst), imm);
#line 1193 "fd_vm_jitproto.dasc"
      break;

    case 0xb5:  /* FD_SBPF_OP_JLE_IMM */
      //| cmp dst64, imm
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1316, (x86_dst), imm, jmp_dst_lbl);
#line 1198 "fd_vm_jitproto.dasc"
      break;

    case 0xb7:  /* FD_SBPF_OP_MOV64_IMM */
      if( imm==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 445, (x86_dst), (x86_dst));
#line 1203 "fd_vm_jitproto.dasc"
      } else {
        //| mov dst64, imm
        dasm_put(Dst, 453, (x86_dst), imm);
#line 1205 "fd_vm_jitproto.dasc"
      }
      break;

    case 0xbc:  /* FD_SBPF_OP_MOV_REG */
      //| mov dst32, src32
      dasm_put(Dst, 1327, (x86_src), (x86_dst));
#line 1210 "fd_vm_jitproto.dasc"
      break;

    case 0xbd:  /* FD_SBPF_OP_JLE_REG */
      //| cmp dst64, src64
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1335, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1215 "fd_vm_jitproto.dasc"
      break;

    case 0xbf:  /* FD_SBPF_OP_MOV64_REG */
      //| mov dst64, src64
      dasm_put(Dst, 1346, (x86_src), (x86_dst));
#line 1219 "fd_vm_jitproto.dasc"
      break;

    /* 0xc0 - 0xcf ******************************************************/

    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      //| sar dst32, imm
      dasm_put(Dst, 1354, (x86_dst), imm);
#line 1225 "fd_vm_jitproto.dasc"
      break;

    case 0xc5:  /* FD_SBPF_OP_JSLT_IMM */
      //| cmp dst64, imm
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1362, (x86_dst), imm, jmp_dst_lbl);
#line 1230 "fd_vm_jitproto.dasc"
      break;

    case 0xc7:  /* FD_SBPF_OP_ARSH64_IMM */
      //| sar dst64, imm
      dasm_put(Dst, 1373, (x86_dst), imm);
#line 1234 "fd_vm_jitproto.dasc"
      break;

    case 0xcc:  /* FD_SBPF_OP_ARSH_REG */
      //| mov cl, src8
      //| sar dst32, cl
      dasm_put(Dst, 1381, (x86_src), (x86_dst));
#line 1239 "fd_vm_jitproto.dasc"
      break;

    case 0xcd:  /* FD_SBPF_OP_JSLT_REG */
      //| cmp dst64, src64
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1393, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1244 "fd_vm_jitproto.dasc"
      break;

    case 0xcf:  /* FD_SBPF_OP_ARSH64_REG */
      //| mov cl, src8
      //| sar dst64, cl
      dasm_put(Dst, 1404, (x86_src), (x86_dst));
#line 1249 "fd_vm_jitproto.dasc"
      break;

    /* 0xd0 - 0xdf ******************************************************/

    case 0xd4:  /* FD_SBPF_OP_END_LE */
      /* nop */
      break;

    case 0xd5:  /* FD_SBPF_OP_JSLE_IMM */
      //| cmp dst64, imm
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1416, (x86_dst), imm, jmp_dst_lbl);
#line 1260 "fd_vm_jitproto.dasc"
      break;

    case 0xdc:  /* FD_SBPF_OP_END_BE */
      switch( imm ) {
      case 16U:
        //| movzx dst32, Rw(x86_dst)
        //| ror Rw(x86_dst), 8
        dasm_put(Dst, 1427, (x86_dst), (x86_dst), (x86_dst));
#line 1267 "fd_vm_jitproto.dasc"
        break;
      case 32U:
        //| bswap dst32
        dasm_put(Dst, 1443, (x86_dst));
#line 1270 "fd_vm_jitproto.dasc"
        break;
      case 64U:
        //| bswap dst64
        dasm_put(Dst, 1449, (x86_dst));
#line 1273 "fd_vm_jitproto.dasc"
        break;
      default:
        break;
        // TODO sigill
      }
      break;

    case 0xdd:  /* FD_SBPF_OP_JSLE_REG */
      //| cmp dst64, src64
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1455, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1283 "fd_vm_jitproto.dasc"
      break;

    default:
      FD_LOG_WARNING(( "Unsupported opcode %x", opcode ));
      cur = text_end;
      break;

    }

  }

  /* Instruction overrun */

  //|->overrun: // FIXME
  //| mov rax, 999
  //| jmp ->leave
  dasm_put(Dst, 1466);
#line 1299 "fd_vm_jitproto.dasc"

  //|->success:
  //| mov rax, bpf_r0
  //|->leave:
  //| pop rbx
  //| pop r12
  //| pop r13
  //| pop r14
  //| pop r15
  //| pop rbp
  //| ret
  dasm_put(Dst, 1480);
#line 1310 "fd_vm_jitproto.dasc"

  /* Finish generating code */

  ulong sz;
  dasm_link( &d, &sz );
  FD_LOG_NOTICE(( "BPF code size: %lu bytes (%#lx)", prog->text_sz, prog->text_sz ));
  FD_LOG_NOTICE(( "x86 code size: %lu bytes (%#lx)", sz, sz ));

  void * buf = mmap( 0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( buf==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed" ));
  fd_jit_code_base = (ulong)buf;
  dasm_encode( &d, buf );
  ulong entry_pc    = prog->entry_pc;
  ulong entry_haddr = (ulong)buf + (ulong)dasm_getpclabel( &d, (uint)entry_pc );
  mprotect( buf, sz, PROT_READ | PROT_EXEC );

  /* Execute */

  int (* main_)( ulong entry_haddr ) = (int (*)( ulong ))( (ulong)labels[ lbl_main ] );
  printf("main at %p\n", (void *)(ulong)main_);
  //__asm__ __volatile__( "int3" );
  for( ulong j=0UL; j<3; j++ ) {
    long dt = -fd_log_wallclock();
    vm->pc = entry_pc;
    vm->reg[ 1] = 2UL<<32; /* account table address */
    vm->reg[ 2] = 2; /* account count */
    vm->reg[ 3] = 3UL<<32; /* instruction data address */
    vm->reg[ 4] = 0; /* instruction data size */
    vm->reg[10] = (1UL<<32) + 0x1000;
    int interp_err = fd_vm_exec_notrace( vm );
    //int interp_err = fd_vm_exec_trace( vm );
    // fd_vm_trace_printf( trace, syscalls );
    if( FD_UNLIKELY( interp_err!=FD_VM_SUCCESS ) ) FD_LOG_ERR(( "%d", interp_err ));
    FD_LOG_NOTICE(( "Interpreter took %g seconds to Blake2b hash %#x bytes", (double)(dt+fd_log_wallclock())/1e9, metas[0].data_len ));
  }
  for( ulong j=0UL; j<3; j++ ) {
    long dt = -fd_log_wallclock();
    vm->reg[ 1] = 2UL<<32; /* account table address */
    vm->reg[ 2] = 2; /* account count */
    vm->reg[ 3] = 3UL<<32; /* instruction data address */
    vm->reg[ 4] = 0; /* instruction data size */
    vm->reg[10] = (1UL<<32) + 0x1000;
    int rc = main_( entry_haddr );
    if( rc==999 ) {
      FD_LOG_ERR(( "Memory access fault at %#lx", fd_jit_segfault_vaddr ));
    }
    FD_LOG_NOTICE(( "JIT took %g seconds to Blake2b hash %#x bytes", (double)(dt+fd_log_wallclock())/1e9, metas[0].data_len ));
  }

  FD_LOG_HEXDUMP_NOTICE(( "account2", account2, sizeof(account2) ));
  FD_LOG_NOTICE(( "%*s", txn_ctx->log_collector.log_sz, txn_ctx->log_collector.buf ));

  fd_jit_dasm = NULL;
  dasm_free( &d );
  fd_halt();
  return 0;
}
