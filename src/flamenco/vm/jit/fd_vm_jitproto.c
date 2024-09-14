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

/* Thread-local storage ***************************************************

   For now, these are assumed to be absolute-addressed using the fs segment
   selector.  Practically, this means that fd_vm_jitproto only supports
   targets with FD_HAS_THREADS.  (Other targets might use absolute
   addressing without a segment selector or rip-relative) */

static FD_TL fd_vm_t * fd_jit_vm  = NULL;  /* current VM being executed */

/* Thread-local storage for address translation

   fd_jit_segment_cnt is number of memory regions mapped in by the VM.
   fd_jit_mem_{ro,rw}_sz are the number of read- and write-addressable
   bytes in each region.  fd_jit_mem_base points to the first byte of a
   region in host address space. */

static FD_TL uint  fd_jit_segment_cnt;
static FD_TL uint  fd_jit_mem_ro_sz[ FD_VM_JIT_SEGMENT_MAX ];
static FD_TL uint  fd_jit_mem_rw_sz[ FD_VM_JIT_SEGMENT_MAX ];
static FD_TL ulong fd_jit_mem_base [ FD_VM_JIT_SEGMENT_MAX ];

/* Thread-local storage for fast return to JIT entrypoint
   These are a setjmp()-like anchor for quickly exiting out of a VM
   execution, e.g. in case of a VM fault.
   Slots: 0=rbx 1=rbp 2=r12 3=r13 4=r14 5=r15 6=rsp 7=rip */

static FD_TL ulong fd_jit_jmp_buf[8];

/* Thread-local storage for exception handling */

static FD_TL ulong fd_jit_segfault_vaddr;
static FD_TL ulong fd_jit_segfault_rip;

//static FD_TL ulong     ic_correct = 0UL;   /* number of lddw instructions executed */


/* Mapping between sBPF registers and x86_64 registers ********************

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

/* GDB JIT debug interface ***********************************************/

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

/* fd_jit_labels is a table of function pointers to 'static' labels in the
   JIT code.  They are indexed by fd_jit_lbl_{...}. */

//| .globals fd_jit_lbl_
enum {
  fd_jit_lbl_vm_fault,
  fd_jit_lbl_longjmp,
  fd_jit_lbl_translate_fail,
  fd_jit_lbl_fd_jit_vm_translate_rw,
  fd_jit_lbl_fd_jit_vm_translate_ro,
  fd_jit_lbl_save_regs,
  fd_jit_lbl_restore_regs,
  fd_jit_lbl_setjmp,
  fd_jit_lbl_emulate_syscall,
  fd_jit_lbl_call_stack_push,
  fd_jit_lbl_call_stack_pop,
  fd_jit_lbl_entrypoint,
  fd_jit_lbl_return_to_callee,
  fd_jit_lbl_overrun,
  fd_jit_lbl__MAX
};
#line 186 "fd_vm_jitproto.dasc"
static FD_TL void * fd_jit_labels[ fd_jit_lbl__MAX ];

/* fd_jit_entrypoint is the entrypoint function of JIT compiled code.
   first_rip is a pointer to the x86 instruction in the host address space
   that corresponds to the BPF entrypoint. */

typedef int (* fd_jit_entrypoint_t)( ulong first_rip );

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

# define ACC1_SZ 0x100000
  uchar * account1 = fd_scratch_alloc( 32, ACC1_SZ );
  memset( account1, 0, ACC1_SZ );
  uchar account2[ 32 ] = {0};
  account_meta_t metas[2] = {
    {
      .pubkey   = {0},
      .owner    = {0},
      .data     = 3UL<<32,
      .data_len = ACC1_SZ,
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

  /* Set up dynasm */

  dasm_State * d;

  //| .section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 430 "fd_vm_jitproto.dasc"
  dasm_init( &d, DASM_MAXSECTION );

  dasm_setupglobal( &d, fd_jit_labels, fd_jit_lbl__MAX );

  dasm_growpc( &d, (uint)prog->text_cnt );
  int next_label = 0;

  //| .actionlist actions
static const unsigned char actions[1637] = {
  254,0,248,10,191,231,3,0,0,252,233,244,11,255,248,12,72,193,231,32,72,9,215,
  100,72,137,60,37,237,72,139,60,36,100,72,137,60,37,237,252,233,244,10,255,
  248,13,137,252,250,72,193,252,239,32,100,59,60,37,237,15,131,244,12,137,208,
  33,232,133,192,15,133,244,12,1,213,15,130,244,12,100,59,44,189,237,15,131,
  244,12,100,72,3,20,252,253,237,195,248,14,137,252,250,72,193,252,239,32,100,
  59,60,37,237,15,131,244,12,137,208,33,232,133,192,15,133,244,12,1,213,15,
  130,244,12,255,100,59,44,189,237,15,131,244,12,100,72,3,20,252,253,237,195,
  255,248,15,72,184,237,237,72,137,176,233,76,137,152,233,76,137,160,233,76,
  137,168,233,76,137,176,233,76,137,184,233,72,137,152,233,72,137,136,233,76,
  137,128,233,76,137,136,233,76,137,144,233,195,255,248,16,72,184,237,237,72,
  139,176,233,76,139,152,233,76,139,160,233,76,139,168,233,76,139,176,233,76,
  139,184,233,72,139,152,233,72,139,136,233,76,139,128,233,76,139,136,233,76,
  139,144,233,195,255,248,17,73,187,237,237,73,137,155,233,73,137,171,233,77,
  137,99,16,77,137,107,24,77,137,115,32,77,137,123,40,72,141,84,36,8,73,137,
  83,48,72,139,20,36,73,137,83,56,49,192,49,210,195,255,248,11,72,137,252,248,
  186,1,0,0,0,72,191,237,237,72,139,159,233,72,139,175,233,76,139,103,16,76,
  139,111,24,76,139,119,32,76,139,127,40,72,139,103,48,252,255,119,56,195,255,
  248,18,232,244,15,72,137,229,72,131,228,252,240,72,131,252,236,16,100,76,
  139,28,37,237,77,139,147,233,77,139,148,253,58,233,76,137,223,72,139,176,
  233,72,139,144,233,72,139,136,233,76,139,128,233,76,139,136,233,76,141,152,
  233,65,83,65,252,255,210,72,137,252,236,232,244,16,133,252,255,15,133,244,
  10,195,255,248,19,100,72,139,60,37,237,139,183,233,141,70,1,137,135,233,193,
  230,235,72,137,156,253,55,233,72,137,140,253,55,233,76,137,132,253,55,233,
  76,137,140,253,55,233,195,255,248,20,100,72,139,60,37,237,139,183,233,252,
  255,206,137,183,233,193,230,235,72,139,156,253,55,233,72,139,140,253,55,233,
  76,139,132,253,55,233,76,139,140,253,55,233,195,255,248,21,255,232,244,17,
  133,210,15,133,244,22,255,232,244,16,252,255,215,72,137,252,247,232,244,11,
  248,22,195,255,249,255,64,129,192,240,43,239,255,252,233,245,255,72,129,192,
  240,35,239,255,64,1,192,240,131,240,51,255,72,1,192,240,131,240,35,255,64,
  129,232,240,43,239,255,72,129,252,248,240,35,239,255,15,132,245,255,72,129,
  232,240,35,239,255,64,49,192,240,131,240,51,255,72,199,192,240,35,237,255,
  64,41,192,240,131,240,51,255,72,57,192,240,131,240,35,15,132,245,255,72,41,
  192,240,131,240,35,255,64,105,192,240,131,240,51,239,255,72,129,252,248,240,
  35,239,15,135,245,255,72,105,192,240,131,240,35,239,255,64,15,175,192,240,
  132,240,52,255,72,57,192,240,131,240,35,15,135,245,255,72,15,175,192,240,
  132,240,36,255,64,144,240,42,49,210,191,237,252,247,252,247,64,144,240,42,
  255,72,129,252,248,240,35,239,15,131,245,255,72,144,240,34,49,210,72,199,
  199,237,72,252,247,252,247,72,144,240,34,255,64,133,192,240,131,240,51,15,
  132,244,10,255,64,184,240,42,1,0,0,0,255,64,144,240,42,49,210,64,252,247,
  252,240,240,43,64,144,240,42,255,72,57,192,240,131,240,35,15,131,245,255,
  72,133,192,240,131,240,35,15,132,244,10,255,72,144,240,34,49,210,72,252,247,
  252,240,240,35,72,144,240,34,255,64,129,200,240,43,239,255,72,252,247,192,
  240,35,237,15,133,245,255,72,129,200,240,35,239,255,64,9,192,240,131,240,
  51,255,72,133,192,240,131,240,35,15,133,245,255,72,9,192,240,131,240,35,255,
  64,129,224,240,43,239,255,72,129,252,248,240,35,239,15,133,245,255,72,129,
  224,240,35,239,255,64,33,192,240,131,240,51,255,72,57,192,240,131,240,35,
  15,133,245,255,72,33,192,240,131,240,35,255,72,141,184,253,240,3,233,189,
  3,0,0,0,232,244,14,64,139,2,240,139,255,72,141,184,253,240,3,233,189,3,0,
  0,0,232,244,13,199,2,237,255,72,141,184,253,240,3,233,189,3,0,0,0,232,244,
  13,64,137,2,240,139,255,64,193,224,240,43,235,255,72,129,252,248,240,35,239,
  15,143,245,255,72,193,224,240,35,235,255,72,141,184,253,240,3,233,189,1,0,
  0,0,232,244,14,64,49,192,240,131,240,51,102,64,139,2,240,139,255,72,141,184,
  253,240,3,233,189,1,0,0,0,232,244,13,102,199,2,236,255,72,141,184,253,240,
  3,233,189,1,0,0,0,232,244,13,64,137,2,240,139,255,64,136,193,240,131,64,211,
  224,240,43,255,72,57,192,240,131,240,35,15,143,245,255,64,136,193,240,131,
  72,211,224,240,35,255,72,141,184,253,240,3,233,49,252,237,232,244,14,255,
  64,49,192,240,131,240,51,64,138,2,240,131,255,72,141,184,253,240,3,233,49,
  252,237,232,244,13,198,2,235,255,72,141,184,253,240,3,233,49,252,237,232,
  244,13,64,136,2,240,131,255,64,193,232,240,43,235,255,72,129,252,248,240,
  35,239,15,141,245,255,72,193,232,240,35,235,255,72,141,184,253,240,3,233,
  189,7,0,0,0,232,244,14,72,139,2,240,131,255,72,141,184,253,240,3,233,189,
  7,0,0,0,232,244,13,72,199,192,237,72,137,2,255,72,141,184,253,240,3,233,189,
  7,0,0,0,232,244,13,72,137,2,240,131,255,64,136,193,240,131,64,211,232,240,
  43,255,72,57,192,240,131,240,35,15,141,245,255,64,136,193,240,131,72,211,
  232,240,35,255,64,252,247,216,240,43,255,232,244,19,232,245,255,72,199,199,
  237,232,244,18,255,72,252,247,216,240,35,255,64,144,240,42,49,210,191,237,
  252,247,252,247,64,135,208,240,43,255,232,244,20,195,255,64,184,240,42,0,
  0,0,0,255,64,144,240,42,49,210,64,252,247,252,240,240,43,64,135,208,240,43,
  255,72,144,240,34,49,210,72,252,247,252,240,240,35,72,135,208,240,35,255,
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
  248,23,252,233,244,10,255
};

#line 438 "fd_vm_jitproto.dasc"
  dasm_setup( &d, actions );

  dasm_State ** Dst = &d;

  /* Start emitting code */

  //| .code
  dasm_put(Dst, 0);
#line 445 "fd_vm_jitproto.dasc"

  /* Exception handlers */

  //|->vm_fault:
  //| mov edi, 999
  //| jmp ->longjmp
  dasm_put(Dst, 2);
#line 451 "fd_vm_jitproto.dasc"

  /* Derive offsets of thread locals in FS "segment" */

# if defined(__FSGSBASE__)
  ulong fs_base; __asm__( "mov %%fs:0, %0" : "=r"(fs_base) );
# else
  ulong fs_base = __builtin_ia32_rdfsbase64();
# endif
# define FS_RELATIVE(ptr) ((uint)( (ulong)(ptr) - fs_base ))
  uint  fd_jit_vm_tpoff             = FS_RELATIVE( &fd_jit_vm             );
  uint  fd_jit_segment_cnt_tpoff    = FS_RELATIVE( &fd_jit_segment_cnt    );
  uint  fd_jit_mem_ro_sz_tpoff      = FS_RELATIVE( fd_jit_mem_ro_sz       );
  uint  fd_jit_mem_rw_sz_tpoff      = FS_RELATIVE( fd_jit_mem_rw_sz       );
  uint  fd_jit_mem_base_tpoff       = FS_RELATIVE( fd_jit_mem_base        );
  uint  fd_jit_segfault_vaddr_tpoff = FS_RELATIVE( &fd_jit_segfault_vaddr );
  uint  fd_jit_segfault_rip_tpoff   = FS_RELATIVE( &fd_jit_segfault_rip   );
# undef FD_RELATIVE

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

  //| .define translate_in,  rdi
  //| .define translate_out, rdx
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
  //| mov rdi, [rsp]
  //| fs
  //| mov [fd_jit_segfault_rip_tpoff], rdi
  //| jmp ->vm_fault
  dasm_put(Dst, 14, fd_jit_segfault_vaddr_tpoff, fd_jit_segfault_rip_tpoff);
#line 531 "fd_vm_jitproto.dasc"

  //|->fd_jit_vm_translate_rw:
  //| gen_scalar_translate, fd_jit_mem_rw_sz_tpoff
  //|->fd_jit_vm_translate_ro:
  //| gen_scalar_translate, fd_jit_mem_ro_sz_tpoff
  dasm_put(Dst, 44, fd_jit_segment_cnt_tpoff, fd_jit_mem_rw_sz_tpoff, fd_jit_mem_base_tpoff, fd_jit_segment_cnt_tpoff);
  dasm_put(Dst, 132, fd_jit_mem_ro_sz_tpoff, fd_jit_mem_base_tpoff);
#line 536 "fd_vm_jitproto.dasc"

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
  dasm_put(Dst, 150, (unsigned int)((ulong)vm), (unsigned int)(((ulong)vm)>>32), offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 591 "fd_vm_jitproto.dasc"

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
  dasm_put(Dst, 202, (unsigned int)((ulong)vm), (unsigned int)(((ulong)vm)>>32), offsetof(fd_vm_t, reg[ 0]), offsetof(fd_vm_t, reg[ 1]), offsetof(fd_vm_t, reg[ 2]), offsetof(fd_vm_t, reg[ 3]), offsetof(fd_vm_t, reg[ 4]), offsetof(fd_vm_t, reg[ 5]), offsetof(fd_vm_t, reg[ 6]), offsetof(fd_vm_t, reg[ 7]), offsetof(fd_vm_t, reg[ 8]), offsetof(fd_vm_t, reg[ 9]), offsetof(fd_vm_t, reg[10]));
#line 606 "fd_vm_jitproto.dasc"

  /* Generate setjmp/longjmp subroutines.  These can be called from any
     execution state with a valid stack.  The JIT uses them to restore a
     sane SystemV-ABI context when exiting JIT code.

     These are based on musl libc's setjmp/longjmp implementation.
     Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license

     setjmp takes no arguments.  longjmp takes a 64-bit value in rdi.
     When setjmp returns from setjmp, sets rax=0 and rdx=0.  When setjmp
     returns from longjmp, sets rax to the rdi argument of longjmp, and
     sets rdx=1.  setjmp preserves rdi. */

  //|->setjmp:
  //| mov64 r11, (ulong)fd_jit_jmp_buf
  //| mov [r11+ 0], rbx
  //| mov [r11+ 8], rbp
  //| mov [r11+16], r12
  //| mov [r11+24], r13
  //| mov [r11+32], r14
  //| mov [r11+40], r15
  //| // save callee's stack pointer
  //| // derived by removing our 8 byte stack frame (only return address)
  //| lea rdx, [rsp+8]
  //| mov [r11+48], rdx
  //| // save return address
  //| mov rdx, [rsp]
  //| mov [r11+56], rdx
  //| // normal return
  //| xor eax, eax
  //| xor edx, edx
  //| ret
  dasm_put(Dst, 254, (unsigned int)((ulong)fd_jit_jmp_buf), (unsigned int)(((ulong)fd_jit_jmp_buf)>>32), 0, 8);
#line 638 "fd_vm_jitproto.dasc"

  //|->longjmp:
  //| mov rax, rdi // move first argument to first output register
  //| mov edx, 1   // set second output register to 1
  //| mov64 rdi, (ulong)fd_jit_jmp_buf
  //| // restore execution state to callee of setjmp
  //| mov rbx, [rdi+ 0]
  //| mov rbp, [rdi+ 8]
  //| mov r12, [rdi+16]
  //| mov r13, [rdi+24]
  //| mov r14, [rdi+32]
  //| mov r15, [rdi+40]
  //| mov rsp, [rdi+48]
  //| push qword [rdi+56]
  //| ret // retpoline
  dasm_put(Dst, 307, (unsigned int)((ulong)fd_jit_jmp_buf), (unsigned int)(((ulong)fd_jit_jmp_buf)>>32), 0, 8);
#line 653 "fd_vm_jitproto.dasc"

  /* The emulate_syscall function switches from a JIT to an interpreter (C)
     execution context and invokes a syscall handler.  Register edi is
     assumed to hold the byte offset into the vm->syscalls table of the
     fd_sbpf_syscalls_t entry to invoke.
     On syscall return, switches back to the JIT execution context and
     resumes execution after the syscall instruction. */

  //|->emulate_syscall:
  //| call ->save_regs
  //| // rax points to the BPF register file
  //| mov rbp, rsp
  //| // Reserve 16 aligned bytes on the stack
  //| and rsp, -16
  //| sub rsp, 16
  //| fs
  //| mov r11, [fd_jit_vm_tpoff]
  //| mov r10, [r11 + offsetof(fd_vm_t, syscalls)]
  //| mov r10, [r10 + rdi + offsetof(fd_sbpf_syscalls_t, func)]
  //| mov rdi, r11
  //| // load BPF r1 through r5 into function arguments
  //| // FIXME could avoid spill to memory by shuffling registers
  //| mov rsi, [rax + offsetof(fd_vm_t, reg[1])]
  //| mov rdx, [rax + offsetof(fd_vm_t, reg[2])]
  //| mov rcx, [rax + offsetof(fd_vm_t, reg[3])]
  //| mov r8,  [rax + offsetof(fd_vm_t, reg[4])]
  //| mov r9,  [rax + offsetof(fd_vm_t, reg[5])]
  //| lea r11, [rax + offsetof(fd_vm_t, reg[0])]
  //| push r11
  //| call r10
  //| mov rsp, rbp
  //| call ->restore_regs
  //| test edi, edi
  //| jnz ->vm_fault
  //| ret
  dasm_put(Dst, 356, fd_jit_vm_tpoff, offsetof(fd_vm_t, syscalls), offsetof(fd_sbpf_syscalls_t, func), offsetof(fd_vm_t, reg[1]), offsetof(fd_vm_t, reg[2]), offsetof(fd_vm_t, reg[3]), offsetof(fd_vm_t, reg[4]), offsetof(fd_vm_t, reg[5]), offsetof(fd_vm_t, reg[0]));
#line 688 "fd_vm_jitproto.dasc"

  /* The call_stack_push function pushes the current program counter and
     eBPF registers r6, r7, r8, r9 to the shadow stack.  The frame register
     (r10) grows upwards.  FIXME implement shadow stack overflow. */

# define REG(n) (offsetof(fd_vm_t, shadow[0].r##n))

  //|->call_stack_push:
  //| fs
  //| mov rdi, [fd_jit_vm_tpoff]
  //| mov esi, [rdi + offsetof(fd_vm_t, frame_cnt)]
  //| // vm->frame_cnt++
  //| lea eax, [esi+1]
  //| mov [rdi + offsetof(fd_vm_t, frame_cnt)], eax
  //| // save registers
  //| shl esi, FD_VM_STACK_FRAME_LG_MAX
  //| mov [rdi+rsi+REG(6)], bpf_r6
  //| mov [rdi+rsi+REG(7)], bpf_r7
  //| mov [rdi+rsi+REG(8)], bpf_r8
  //| mov [rdi+rsi+REG(9)], bpf_r9
  //| ret
  dasm_put(Dst, 439, fd_jit_vm_tpoff, offsetof(fd_vm_t, frame_cnt), offsetof(fd_vm_t, frame_cnt), FD_VM_STACK_FRAME_LG_MAX, REG(6), REG(7), REG(8), REG(9));
#line 709 "fd_vm_jitproto.dasc"

  /* The call_stack_pop function undoes the effects of call_stack_push. */

  //|->call_stack_pop:
  //| fs
  //| mov rdi, [fd_jit_vm_tpoff]
  //| mov esi, [rdi + offsetof(fd_vm_t, frame_cnt)]
  //| // vm->frame_cnt--
  //| dec esi
  //| mov [rdi + offsetof(fd_vm_t, frame_cnt)], esi
  //| // restore registers
  //| shl esi, FD_VM_STACK_FRAME_LG_MAX
  //| mov bpf_r6, [rdi+esi+REG(6)]
  //| mov bpf_r7, [rdi+esi+REG(7)]
  //| mov bpf_r8, [rdi+esi+REG(8)]
  //| mov bpf_r9, [rdi+esi+REG(9)]
  //| ret
  dasm_put(Dst, 485, fd_jit_vm_tpoff, offsetof(fd_vm_t, frame_cnt), offsetof(fd_vm_t, frame_cnt), FD_VM_STACK_FRAME_LG_MAX, REG(6), REG(7), REG(8), REG(9));
#line 726 "fd_vm_jitproto.dasc"

# undef REG

  /* Start translating user code */

  //|->entrypoint:
  dasm_put(Dst, 531);
#line 732 "fd_vm_jitproto.dasc"

  /* Create setjmp anchor used to return from JIT */

  //| call ->setjmp // preserves rdi
  //| test edx, edx
  //| jnz ->return_to_callee
  dasm_put(Dst, 534);
#line 738 "fd_vm_jitproto.dasc"

  /* Enter JIT execution context */

  //| call ->restore_regs
  //| call rdi
  //| mov rdi, bpf_r0
  //| call ->longjmp
  //|->return_to_callee:
  //| ret
  dasm_put(Dst, 544);
#line 747 "fd_vm_jitproto.dasc"

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
    dasm_put(Dst, 561, next_label);
#line 789 "fd_vm_jitproto.dasc"

    /* Translate instruction */

    switch( opcode ) {

    /* 0x00 - 0x0f ******************************************************/

    case 0x04:  /* FD_SBPF_OP_ADD_IMM */
      //| add dst32, imm
      dasm_put(Dst, 563, (x86_dst), imm);
#line 798 "fd_vm_jitproto.dasc"
      break;

    case 0x05:  /* FD_SBPF_OP_JA */
      //| jmp =>jmp_dst_lbl
      dasm_put(Dst, 570, jmp_dst_lbl);
#line 802 "fd_vm_jitproto.dasc"
      break;

    case 0x07:  /* FD_SBPF_OP_ADD64_IMM */
      //| add dst64, imm
      dasm_put(Dst, 574, (x86_dst), imm);
#line 806 "fd_vm_jitproto.dasc"
      break;

    case 0x0c:  /* FD_SBPF_OP_ADD_REG */
      //| add dst32, src32
      dasm_put(Dst, 581, (x86_src), (x86_dst));
#line 810 "fd_vm_jitproto.dasc"
      break;

    case 0x0f:  /* FD_SBPF_OP_ADD64_REG */
      //| add dst64, src64
      dasm_put(Dst, 589, (x86_src), (x86_dst));
#line 814 "fd_vm_jitproto.dasc"
      break;

    /* 0x10 - 0x1f ******************************************************/

    case 0x14:  /* FD_SBPF_OP_SUB_IMM */
      //| sub dst32, imm
      dasm_put(Dst, 597, (x86_dst), imm);
#line 820 "fd_vm_jitproto.dasc"
      break;

    case 0x15:  /* FD_SBPF_OP_JEQ_IMM */
      //| cmp dst64, imm
      dasm_put(Dst, 604, (x86_dst), imm);
#line 824 "fd_vm_jitproto.dasc"
      /* pre branch check here ... branchless cu update? */
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 612, jmp_dst_lbl);
#line 826 "fd_vm_jitproto.dasc"
      break;

    case 0x17:  /* FD_SBPF_OP_SUB64_IMM */
      //| sub dst64, imm
      dasm_put(Dst, 616, (x86_dst), imm);
#line 830 "fd_vm_jitproto.dasc"
      break;

    case 0x18:  /* FD_SBPF_OP_LDQ */
      cur++; {
      ulong imm64 = (ulong)imm | ( (ulong)fd_vm_instr_imm( *cur ) << 32 );
      if( imm64==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 623, (x86_dst), (x86_dst));
#line 837 "fd_vm_jitproto.dasc"
      } else {
        //| mov dst64, imm64
        dasm_put(Dst, 631, (x86_dst), imm64);
#line 839 "fd_vm_jitproto.dasc"
      }
      break;
    }

    case 0x1c:  /* FD_SBPF_OP_SUB_REG */
      //| sub dst32, src32
      dasm_put(Dst, 638, (x86_src), (x86_dst));
#line 845 "fd_vm_jitproto.dasc"
      break;

    case 0x1d:  /* FD_SBPF_OP_JEQ_REG */
      //| cmp dst64, src64
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 646, (x86_src), (x86_dst), jmp_dst_lbl);
#line 850 "fd_vm_jitproto.dasc"
      break;

    case 0x1f:  /* FD_SBPF_OP_SUB64_REG */
      //| sub dst64, src64
      dasm_put(Dst, 657, (x86_src), (x86_dst));
#line 854 "fd_vm_jitproto.dasc"
      break;

    /* 0x20 - 0x2f ******************************************************/

    case 0x24:  /* FD_SBPF_OP_MUL_IMM */
      /* TODO strength reduction? */
      //| imul dst32, imm
      dasm_put(Dst, 665, (x86_dst), (x86_dst), imm);
#line 861 "fd_vm_jitproto.dasc"
      break;

    case 0x25:  /* FD_SBPF_OP_JGT_IMM */
      //| cmp dst64, imm
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 674, (x86_dst), imm, jmp_dst_lbl);
#line 866 "fd_vm_jitproto.dasc"
      break;

    case 0x27:  /* FD_SBPF_OP_MUL64_IMM */
      /* TODO strength reduction? */
      //| imul dst64, imm
      dasm_put(Dst, 685, (x86_dst), (x86_dst), imm);
#line 871 "fd_vm_jitproto.dasc"
      break;

    case 0x2c:  /* FD_SBPF_OP_MUL_REG */
      //| imul dst32, src32
      dasm_put(Dst, 694, (x86_dst), (x86_src));
#line 875 "fd_vm_jitproto.dasc"
      break;

    case 0x2d:  /* FD_SBPF_OP_JGT_REG */
      //| cmp dst64, src64
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 703, (x86_src), (x86_dst), jmp_dst_lbl);
#line 880 "fd_vm_jitproto.dasc"
      break;

    case 0x2f:  /* FD_SBPF_OP_MUL64_REG */
      //| imul dst64, src64
      dasm_put(Dst, 714, (x86_dst), (x86_src));
#line 884 "fd_vm_jitproto.dasc"
      break;

    /* 0x30 - 0x3f ******************************************************/

    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 39);
#line 891 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg eax, dst32
      dasm_put(Dst, 723, (x86_dst), imm, (x86_dst));
#line 898 "fd_vm_jitproto.dasc"
      break;

    case 0x35:  /* FD_SBPF_OP_JGE_IMM */
      //| cmp dst64, imm
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 740, (x86_dst), imm, jmp_dst_lbl);
#line 903 "fd_vm_jitproto.dasc"
      break;

    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 39);
#line 908 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 751, (x86_dst), imm, (x86_dst));
#line 915 "fd_vm_jitproto.dasc"
      break;

    case 0x3c:  /* FD_SBPF_OP_DIV_REG */
      //| test src32, src32
      //| jz ->vm_fault
      dasm_put(Dst, 771, (x86_src), (x86_src));
#line 920 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 783, (x86_dst));
#line 922 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg eax, dst32
      dasm_put(Dst, 792, (x86_dst), (x86_src), (x86_dst));
#line 928 "fd_vm_jitproto.dasc"
      break;

    case 0x3d:  /* FD_SBPF_OP_JGE_REG */
      //| cmp dst64, src64
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 810, (x86_src), (x86_dst), jmp_dst_lbl);
#line 933 "fd_vm_jitproto.dasc"
      break;

    case 0x3f:  /* FD_SBPF_OP_DIV64_REG */
      //| test src64, src64
      //| jz ->vm_fault
      dasm_put(Dst, 821, (x86_src), (x86_src));
#line 938 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 783, (x86_dst));
#line 940 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rax, dst64
      dasm_put(Dst, 833, (x86_dst), (x86_src), (x86_dst));
#line 946 "fd_vm_jitproto.dasc"
      break;

    /* 0x40 - 0x4f ******************************************************/

    case 0x44:  /* FD_SBPF_OP_OR_IMM */
      //| or dst32, imm
      dasm_put(Dst, 851, (x86_dst), imm);
#line 952 "fd_vm_jitproto.dasc"
      break;

    case 0x45:  /* FD_SBPF_OP_JSET_IMM */
      //| test dst64, imm
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 858, (x86_dst), imm, jmp_dst_lbl);
#line 957 "fd_vm_jitproto.dasc"
      break;

    case 0x47:  /* FD_SBPF_OP_OR64_IMM */
      //| or dst64, imm
      dasm_put(Dst, 869, (x86_dst), imm);
#line 961 "fd_vm_jitproto.dasc"
      break;

    case 0x4c:  /* FD_SBPF_OP_OR_REG */
      //| or dst32, src32
      dasm_put(Dst, 876, (x86_src), (x86_dst));
#line 965 "fd_vm_jitproto.dasc"
      break;

    case 0x4d:  /* FD_SBPF_OP_JSET_REG */
      //| test dst64, src64
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 884, (x86_src), (x86_dst), jmp_dst_lbl);
#line 970 "fd_vm_jitproto.dasc"
      break;

    case 0x4f:  /* FD_SBPF_OP_OR64_REG */
      //| or dst64, src64
      dasm_put(Dst, 895, (x86_src), (x86_dst));
#line 974 "fd_vm_jitproto.dasc"
      break;

    /* 0x50 - 0x5f ******************************************************/

    case 0x54:  /* FD_SBPF_OP_AND_IMM */
      //| and dst32, imm
      dasm_put(Dst, 903, (x86_dst), imm);
#line 980 "fd_vm_jitproto.dasc"
      break;

    case 0x55:  /* FD_SBPF_OP_JNE_IMM */
      //| cmp dst64, imm
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 910, (x86_dst), imm, jmp_dst_lbl);
#line 985 "fd_vm_jitproto.dasc"
      break;

    case 0x57:  /* FD_SBPF_OP_AND64_IMM */
      //| and dst64, imm
      dasm_put(Dst, 921, (x86_dst), imm);
#line 989 "fd_vm_jitproto.dasc"
      break;

    case 0x5c:  /* FD_SBPF_OP_AND_REG */
      //| and dst32, src32
      dasm_put(Dst, 928, (x86_src), (x86_dst));
#line 993 "fd_vm_jitproto.dasc"
      break;

    case 0x5d:  /* FD_SBPF_OP_JNE_REG */
      //| cmp dst64, src64
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 936, (x86_src), (x86_dst), jmp_dst_lbl);
#line 998 "fd_vm_jitproto.dasc"
      break;

    case 0x5f:  /* FD_SBPF_OP_AND64_REG */
      //| and dst64, src64
      dasm_put(Dst, 947, (x86_src), (x86_dst));
#line 1002 "fd_vm_jitproto.dasc"
      break;

    /* 0x60 - 0x6f ******************************************************/

    case 0x61:  /* FD_SBPF_OP_LDXW */
      //| lea translate_in, [src64+offset]
      //| translate_ro_4
      //| mov dst32, [translate_out]
      dasm_put(Dst, 955, (x86_src), offset, (x86_dst));
#line 1010 "fd_vm_jitproto.dasc"
      break;

    case 0x62:  /* FD_SBPF_OP_STW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov dword [translate_out], imm
      dasm_put(Dst, 976, (x86_dst), offset, imm);
#line 1016 "fd_vm_jitproto.dasc"
      break;

    case 0x63:  /* FD_SBPF_OP_STXW */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_4
      //| mov [translate_out], src32
      dasm_put(Dst, 995, (x86_dst), offset, (x86_src));
#line 1022 "fd_vm_jitproto.dasc"
      break;

    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
      //| shl dst32, imm
      dasm_put(Dst, 1016, (x86_dst), imm);
#line 1026 "fd_vm_jitproto.dasc"
      break;

    case 0x65:  /* FD_SBPF_OP_JSGT_IMM */
      //| cmp dst64, imm
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 1023, (x86_dst), imm, jmp_dst_lbl);
#line 1031 "fd_vm_jitproto.dasc"
      break;

    case 0x67:  /* FD_SBPF_OP_LSH64_IMM */
      //| shl dst64, imm
      dasm_put(Dst, 1034, (x86_dst), imm);
#line 1035 "fd_vm_jitproto.dasc"
      break;

    case 0x69:  /* FD_SBPF_OP_LDXH */
      //| lea translate_in, [src64+offset]
      //| translate_ro_2
      //| xor dst32, dst32
      //| mov Rw(x86_dst), [translate_out]
      dasm_put(Dst, 1041, (x86_src), offset, (x86_dst), (x86_dst), (x86_dst));
#line 1042 "fd_vm_jitproto.dasc"
      break;

    case 0x6a:  /* FD_SBPF_OP_STH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov word [translate_out], imm
      dasm_put(Dst, 1070, (x86_dst), offset, imm);
#line 1048 "fd_vm_jitproto.dasc"
      break;

    case 0x6b:  /* FD_SBPF_OP_STXH */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_2
      //| mov [translate_out], src32
      dasm_put(Dst, 1090, (x86_dst), offset, (x86_src));
#line 1054 "fd_vm_jitproto.dasc"
      break;

    case 0x6c:  /* FD_SBPF_OP_LSH_REG */
      //| mov cl, src8
      //| shl dst32, cl
      dasm_put(Dst, 1111, (x86_src), (x86_dst));
#line 1059 "fd_vm_jitproto.dasc"
      break;

    case 0x6d:  /* FD_SBPF_OP_JSGT_REG */
      //| cmp dst64, src64
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 1122, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1064 "fd_vm_jitproto.dasc"
      break;

    case 0x6f:  /* FD_SBPF_OP_LSH64_REG */
      //| mov cl, src8
      //| shl dst64, cl
      dasm_put(Dst, 1133, (x86_src), (x86_dst));
#line 1069 "fd_vm_jitproto.dasc"
      break;

    /* 0x70 - 0x7f ******************************************************/

    case 0x71:  /* FD_SBPF_OP_LDXB */
      //| lea translate_in, [src64+offset]
      //| translate_ro_1
      dasm_put(Dst, 1144, (x86_src), offset);
#line 1076 "fd_vm_jitproto.dasc"
      /* TODO is there a better way to zero upper and mov byte? */
      //| xor dst32, dst32
      //| mov Rb(x86_dst), [translate_out]
      dasm_put(Dst, 1158, (x86_dst), (x86_dst), (x86_dst));
#line 1079 "fd_vm_jitproto.dasc"
      break;

    case 0x72:  /* FD_SBPF_OP_STB */
      //| lea translate_in, [src64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], imm
      dasm_put(Dst, 1171, (x86_src), offset, imm);
#line 1085 "fd_vm_jitproto.dasc"
      break;

    case 0x73:  /* FD_SBPF_OP_STXB */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_1
      //| mov byte [translate_out], Rb(x86_src)
      dasm_put(Dst, 1188, (x86_dst), offset, (x86_src));
#line 1091 "fd_vm_jitproto.dasc"
      break;

    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
      //| shr dst32, imm
      dasm_put(Dst, 1207, (x86_dst), imm);
#line 1095 "fd_vm_jitproto.dasc"
      break;

    case 0x75:  /* FD_SBPF_OP_JSGE_IMM */
      //| cmp dst64, imm
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1214, (x86_dst), imm, jmp_dst_lbl);
#line 1100 "fd_vm_jitproto.dasc"
      break;

    case 0x77:  /* FD_SBPF_OP_RSH64_IMM */
      //| shr dst64, imm
      dasm_put(Dst, 1225, (x86_dst), imm);
#line 1104 "fd_vm_jitproto.dasc"
      break;

    case 0x79:  /* FD_SBPF_OP_LDXQ */
      //| lea translate_in, [src64+offset]
      //| translate_ro_8
      //| mov dst64, [translate_out]
      dasm_put(Dst, 1232, (x86_src), offset, (x86_dst));
#line 1110 "fd_vm_jitproto.dasc"
      break;

    case 0x7a:  /* FD_SBPF_OP_STQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov rax, imm
      //| mov [translate_out], rax
      dasm_put(Dst, 1253, (x86_dst), offset, imm);
#line 1117 "fd_vm_jitproto.dasc"
      break;

    case 0x7b:  /* FD_SBPF_OP_STXQ */
      //| lea translate_in, [dst64+offset]
      //| translate_rw_8
      //| mov [translate_out], src64
      dasm_put(Dst, 1276, (x86_dst), offset, (x86_src));
#line 1123 "fd_vm_jitproto.dasc"
      break;

    case 0x7c:  /* FD_SBPF_OP_RSH_REG */
      //| mov cl, src8
      //| shr dst32, cl
      dasm_put(Dst, 1297, (x86_src), (x86_dst));
#line 1128 "fd_vm_jitproto.dasc"
      break;

    case 0x7d:  /* FD_SBPF_OP_JSGE_REG */
      //| cmp dst64, src64
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 1308, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1133 "fd_vm_jitproto.dasc"
      break;

    case 0x7f:  /* FD_SBPF_OP_RSH64_REG */
      //| mov cl, src8
      //| shr dst64, cl
      dasm_put(Dst, 1319, (x86_src), (x86_dst));
#line 1138 "fd_vm_jitproto.dasc"
      break;

    /* 0x80-0x8f ********************************************************/

    case 0x84:  /* FD_SBPF_OP_NEG */
      //| neg dst32
      dasm_put(Dst, 1330, (x86_dst));
#line 1144 "fd_vm_jitproto.dasc"
      break;

    case 0x85: { /* FD_SBPF_OP_CALL_IMM */
      fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query_const( vm->syscalls, imm, NULL );
      if( !syscall ) {
        ulong target_pc = (ulong)fd_pchash_inverse( imm );
        //| call ->call_stack_push
        //| call =>target_pc
        dasm_put(Dst, 1337, target_pc);
#line 1152 "fd_vm_jitproto.dasc"
      } else {
        /* Optimize for code footprint: Generate an offset into the
           syscall table (32-bit) instead of the syscall address (64-bit) */
        //| mov rdi, (uint)( (ulong)syscall - (ulong)vm->syscalls );
        //| call ->emulate_syscall
        dasm_put(Dst, 1343, (uint)( (ulong)syscall - (ulong)vm->syscalls ));
#line 1157 "fd_vm_jitproto.dasc"
      }
      break;
    }

    case 0x87:  /* FD_SBPF_OP_NEG64 */
      //| neg dst64
      dasm_put(Dst, 1351, (x86_dst));
#line 1163 "fd_vm_jitproto.dasc"
      break;

    case 0x8d:  /* FD_SBPF_OP_CALL_REG */
      FD_LOG_WARNING(( "TODO: CALLX" ));
      break;

    /* 0x90 - 0x9f ******************************************************/

    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 39);
#line 1174 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg edx, dst32
      dasm_put(Dst, 1358, (x86_dst), imm, (x86_dst));
#line 1181 "fd_vm_jitproto.dasc"
      break;

    case 0x95:  /* FD_SBPF_OP_EXIT */
      //| call ->call_stack_pop
      //| ret
      dasm_put(Dst, 1376);
#line 1186 "fd_vm_jitproto.dasc"
      break;

    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->vm_fault
        dasm_put(Dst, 39);
#line 1191 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 751, (x86_dst), imm, (x86_dst));
#line 1198 "fd_vm_jitproto.dasc"
      break;

    case 0x9c:  /* FD_SBPF_OP_MOD_REG */
      //| test src32, src32
      //| jz ->vm_fault
      dasm_put(Dst, 771, (x86_src), (x86_src));
#line 1203 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1381, (x86_dst));
#line 1205 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg edx, dst32
      dasm_put(Dst, 1390, (x86_dst), (x86_src), (x86_dst));
#line 1211 "fd_vm_jitproto.dasc"
      break;

    case 0x9f:  /* FD_SBPF_OP_MOD64_REG */
      //| test src64, src64
      //| jz ->vm_fault
      dasm_put(Dst, 821, (x86_src), (x86_src));
#line 1216 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 1381, (x86_dst));
#line 1218 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rdx, dst64
      dasm_put(Dst, 1409, (x86_dst), (x86_src), (x86_dst));
#line 1224 "fd_vm_jitproto.dasc"
      break;

    /* 0xa0 - 0xaf ******************************************************/

    case 0xa4:  /* FD_SBPF_OP_XOR_IMM */
      //| xor dst32, imm
      dasm_put(Dst, 1428, (x86_dst), imm);
#line 1230 "fd_vm_jitproto.dasc"
      break;

    case 0xa5:  /* FD_SBPF_OP_JLT_IMM */
      //| cmp dst64, imm
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1436, (x86_dst), imm, jmp_dst_lbl);
#line 1235 "fd_vm_jitproto.dasc"
      break;

    case 0xa7:  /* FD_SBPF_OP_XOR64_IMM */
      // TODO sign extension
      //| xor dst64, imm
      dasm_put(Dst, 1447, (x86_dst), imm);
#line 1240 "fd_vm_jitproto.dasc"
      break;

    case 0xac:  /* FD_SBPF_OP_XOR_REG */
      //| xor dst32, src32
      dasm_put(Dst, 623, (x86_src), (x86_dst));
#line 1244 "fd_vm_jitproto.dasc"
      break;

    case 0xad:  /* FD_SBPF_OP_JLT_REG */
      //| cmp dst64, src64
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 1455, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1249 "fd_vm_jitproto.dasc"
      break;

    case 0xaf:  /* FD_SBPF_OP_XOR64_REG */
      //| xor dst64, src64
      dasm_put(Dst, 1466, (x86_src), (x86_dst));
#line 1253 "fd_vm_jitproto.dasc"
      break;

    /* 0xb0 - 0xbf ******************************************************/

    case 0xb4:  /* FD_SBPF_OP_MOV_IMM */
      //| mov dst32, imm
      dasm_put(Dst, 1474, (x86_dst), imm);
#line 1259 "fd_vm_jitproto.dasc"
      break;

    case 0xb5:  /* FD_SBPF_OP_JLE_IMM */
      //| cmp dst64, imm
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1480, (x86_dst), imm, jmp_dst_lbl);
#line 1264 "fd_vm_jitproto.dasc"
      break;

    case 0xb7:  /* FD_SBPF_OP_MOV64_IMM */
      if( imm==0 ) {
        //| xor dst32, dst32
        dasm_put(Dst, 623, (x86_dst), (x86_dst));
#line 1269 "fd_vm_jitproto.dasc"
      } else {
        //| mov dst64, imm
        dasm_put(Dst, 631, (x86_dst), imm);
#line 1271 "fd_vm_jitproto.dasc"
      }
      break;

    case 0xbc:  /* FD_SBPF_OP_MOV_REG */
      //| mov dst32, src32
      dasm_put(Dst, 1491, (x86_src), (x86_dst));
#line 1276 "fd_vm_jitproto.dasc"
      break;

    case 0xbd:  /* FD_SBPF_OP_JLE_REG */
      //| cmp dst64, src64
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 1499, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1281 "fd_vm_jitproto.dasc"
      break;

    case 0xbf:  /* FD_SBPF_OP_MOV64_REG */
      //| mov dst64, src64
      dasm_put(Dst, 1510, (x86_src), (x86_dst));
#line 1285 "fd_vm_jitproto.dasc"
      break;

    /* 0xc0 - 0xcf ******************************************************/

    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      //| sar dst32, imm
      dasm_put(Dst, 1518, (x86_dst), imm);
#line 1291 "fd_vm_jitproto.dasc"
      break;

    case 0xc5:  /* FD_SBPF_OP_JSLT_IMM */
      //| cmp dst64, imm
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1526, (x86_dst), imm, jmp_dst_lbl);
#line 1296 "fd_vm_jitproto.dasc"
      break;

    case 0xc7:  /* FD_SBPF_OP_ARSH64_IMM */
      //| sar dst64, imm
      dasm_put(Dst, 1537, (x86_dst), imm);
#line 1300 "fd_vm_jitproto.dasc"
      break;

    case 0xcc:  /* FD_SBPF_OP_ARSH_REG */
      //| mov cl, src8
      //| sar dst32, cl
      dasm_put(Dst, 1545, (x86_src), (x86_dst));
#line 1305 "fd_vm_jitproto.dasc"
      break;

    case 0xcd:  /* FD_SBPF_OP_JSLT_REG */
      //| cmp dst64, src64
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 1557, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1310 "fd_vm_jitproto.dasc"
      break;

    case 0xcf:  /* FD_SBPF_OP_ARSH64_REG */
      //| mov cl, src8
      //| sar dst64, cl
      dasm_put(Dst, 1568, (x86_src), (x86_dst));
#line 1315 "fd_vm_jitproto.dasc"
      break;

    /* 0xd0 - 0xdf ******************************************************/

    case 0xd4:  /* FD_SBPF_OP_END_LE */
      /* nop */
      break;

    case 0xd5:  /* FD_SBPF_OP_JSLE_IMM */
      //| cmp dst64, imm
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1580, (x86_dst), imm, jmp_dst_lbl);
#line 1326 "fd_vm_jitproto.dasc"
      break;

    case 0xdc:  /* FD_SBPF_OP_END_BE */
      switch( imm ) {
      case 16U:
        //| movzx dst32, Rw(x86_dst)
        //| ror Rw(x86_dst), 8
        dasm_put(Dst, 1591, (x86_dst), (x86_dst), (x86_dst));
#line 1333 "fd_vm_jitproto.dasc"
        break;
      case 32U:
        //| bswap dst32
        dasm_put(Dst, 1607, (x86_dst));
#line 1336 "fd_vm_jitproto.dasc"
        break;
      case 64U:
        //| bswap dst64
        dasm_put(Dst, 1613, (x86_dst));
#line 1339 "fd_vm_jitproto.dasc"
        break;
      default:
        break;
        // TODO sigill
      }
      break;

    case 0xdd:  /* FD_SBPF_OP_JSLE_REG */
      //| cmp dst64, src64
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 1619, (x86_src), (x86_dst), jmp_dst_lbl);
#line 1349 "fd_vm_jitproto.dasc"
      break;

    default:
      FD_LOG_WARNING(( "Unsupported opcode %x", opcode ));
      cur = text_end;
      break;

    }

  }

  /* Instruction overrun */

  //|->overrun: // FIXME
  //| jmp ->vm_fault
  dasm_put(Dst, 1630);
#line 1364 "fd_vm_jitproto.dasc"

  /* Finish generating code */

  ulong sz;
  dasm_link( &d, &sz );
  FD_LOG_NOTICE(( "BPF code size: %lu bytes (%#lx)", prog->text_sz, prog->text_sz ));
  FD_LOG_NOTICE(( "x86 code size: %lu bytes (%#lx)", sz, sz ));

  void * buf = mmap( 0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( buf==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed" ));
  dasm_encode( &d, buf );
  ulong entry_pc    = prog->entry_pc;
  ulong entry_haddr = (ulong)buf + (ulong)dasm_getpclabel( &d, (uint)entry_pc );
  dasm_free( &d );
  mprotect( buf, sz, PROT_READ | PROT_EXEC );

  /* Execute */

  FD_LOG_NOTICE(( "vm at %p", (void *)fd_jit_vm ));

  fd_jit_entrypoint_t jit_entry = (fd_jit_entrypoint_t)( (ulong)fd_jit_labels[ fd_jit_lbl_entrypoint ] );
  FD_LOG_NOTICE(( "x86 code at %p", (void *)(ulong)jit_entry ));

  long dt = -fd_log_wallclock();
  vm->reg[ 1] = 2UL<<32; /* account table address */
  vm->reg[ 2] = 2; /* account count */
  vm->reg[ 3] = 3UL<<32; /* instruction data address */
  vm->reg[ 4] = 0; /* instruction data size */
  vm->reg[10] = (1UL<<32) + 0x1000;
  vm->frame_cnt = 1; /* last exit writes to frame[0] */
  int rc = jit_entry( entry_haddr );
  if( rc==999 ) {
    FD_LOG_ERR(( "Memory access fault: Attempted to access %#lx at %#lx", fd_jit_segfault_vaddr, fd_jit_segfault_rip ));
  }
  FD_LOG_NOTICE(( "Executed program in %g seconds using JIT", (double)(dt+fd_log_wallclock())/1e9 ));

  FD_LOG_HEXDUMP_NOTICE(( "account2", account2, sizeof(account2) ));
  FD_LOG_NOTICE(( "%*s", txn_ctx->log_collector.log_sz, txn_ctx->log_collector.buf ));

  fd_halt();
  return 0;
}
