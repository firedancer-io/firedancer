/*
** This file has been pre-processed with DynASM.
** http://luajit.org/dynasm.html
** DynASM version 1.3.0, DynASM x64 version 1.3.0
** DO NOT EDIT! The original file is in "fd_vm_jitproto.dasc".
*/

#line 1 "fd_vm_jitproto.dasc"
/* fd_vm_jitproto is a first draft of a sBPF JIT compiler for
   Firedancer.  Nothing to see here, it's broken and work-in-progress. */

#define _GNU_SOURCE
#include "../../fd_flamenco_base.h"

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#include "dasm_proto.h"
#include "dasm_x86.h"
#pragma GCC diagnostic pop

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

  ulong cu_avail = 10000UL;
  txn_ctx->compute_meter      = cu_avail;
  txn_ctx->compute_unit_limit = cu_avail;

  fd_exec_instr_ctx_t instr_ctx[1] = {{0}};
  instr_ctx->epoch_ctx = epoch_ctx;
  instr_ctx->slot_ctx  = slot_ctx;
  instr_ctx->txn_ctx   = txn_ctx;

  /* Set up VM */

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  ulong   input_data_sz = 1000UL;
  uchar * input_data = fd_scratch_alloc( 16UL, input_data_sz );

  fd_vm_input_region_t input_region = {
    .vaddr_offset = 0UL,
    .haddr        = (ulong)input_data,
    .region_sz    = (uint)input_data_sz,
    .is_writable  = 1U,
    .pubkey       = NULL
  };
  fd_vm_input_region_t * mem_regions    = &input_region;
  ulong                  mem_region_cnt = 1UL;

  fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_scratch_alloc( fd_vm_align(), fd_vm_footprint() ) ) );
  FD_TEST( vm );
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
    NULL, /* trace */
    sha,
    mem_regions,
    mem_region_cnt,
    NULL, /* acc_region_metas */
    0 /* is_deprecated */ ) );

  vm->reg[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  vm->reg[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  printf( "vm at %p\n", (void *)vm );

  /* Set up dynasm */

  dasm_State * d;

  //| .arch x64
#if DASM_VERSION != 10300
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 205 "fd_vm_jitproto.dasc"
  //| .section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 206 "fd_vm_jitproto.dasc"
  dasm_init( &d, DASM_MAXSECTION );

  //| .globals lbl_
enum {
  lbl_sigfpe,
  lbl_leave,
  lbl_main,
  lbl_overrun,
  lbl__MAX
};
#line 209 "fd_vm_jitproto.dasc"
  void * labels[ lbl__MAX ];
  dasm_setupglobal( &d, labels, lbl__MAX );

  dasm_growpc( &d, prog->text_cnt );
  int next_label = 0;

  //| .actionlist actions
static const unsigned char actions[930] = {
  254,0,248,10,72,199,192,231,3,0,0,252,233,244,11,255,248,12,255,85,72,137,
  229,65,87,65,86,65,85,65,84,83,255,72,187,237,237,255,72,139,179,233,76,139,
  155,233,76,139,163,233,76,139,171,233,76,139,179,233,76,139,187,233,72,139,
  155,233,72,139,171,233,76,139,131,233,76,139,139,233,76,139,147,233,255,249,
  255,129,192,240,0,239,255,252,233,245,255,72,129,192,240,0,239,255,1,192,
  240,2,240,0,255,72,1,192,240,2,240,0,255,129,232,240,0,239,255,72,129,252,
  248,240,0,239,15,132,245,255,72,129,232,240,0,239,255,72,199,192,240,0,237,
  255,41,192,240,2,240,0,255,72,57,192,240,2,240,0,15,132,245,255,72,41,192,
  240,2,240,0,255,105,192,240,2,240,0,239,255,72,129,252,248,240,0,239,15,135,
  245,255,72,105,192,240,2,240,0,239,255,15,175,192,240,2,240,0,255,72,57,192,
  240,2,240,0,15,135,245,255,72,15,175,192,240,2,240,0,255,252,233,244,10,255,
  144,240,0,49,210,191,237,252,247,252,247,144,240,0,255,72,129,252,248,240,
  0,239,15,131,245,255,72,144,240,0,49,210,72,199,199,237,72,252,247,252,247,
  72,144,240,0,255,133,192,240,2,240,0,15,132,244,10,255,184,240,0,1,0,0,0,
  255,144,240,0,49,210,252,247,252,240,240,0,144,240,0,255,72,57,192,240,2,
  240,0,15,131,245,255,72,133,192,240,2,240,0,15,132,244,10,255,72,144,240,
  0,49,210,72,252,247,252,240,240,0,72,144,240,0,255,129,200,240,0,239,255,
  72,252,247,192,240,0,237,15,133,245,255,72,129,200,240,0,239,255,9,192,240,
  2,240,0,255,72,133,192,240,2,240,0,15,133,245,255,72,9,192,240,2,240,0,255,
  129,224,240,0,239,255,72,129,252,248,240,0,239,15,133,245,255,72,129,224,
  240,0,239,255,33,192,240,2,240,0,255,72,57,192,240,2,240,0,15,133,245,255,
  72,33,192,240,2,240,0,255,72,141,184,253,240,1,233,255,139,7,240,2,255,199,
  7,237,255,137,7,240,2,255,193,224,240,0,235,255,72,129,252,248,240,0,239,
  15,143,245,255,72,193,224,240,0,235,255,102,199,7,236,255,136,193,240,2,211,
  224,240,0,255,72,57,192,240,2,240,0,15,143,245,255,136,193,240,2,72,211,224,
  240,0,255,49,192,240,2,240,0,138,7,240,2,255,198,7,235,255,136,7,240,2,255,
  193,232,240,0,235,255,72,129,252,248,240,0,239,15,141,245,255,72,193,232,
  240,0,235,255,72,139,7,240,2,255,72,199,192,237,72,137,7,255,72,137,7,240,
  2,255,136,193,240,2,211,232,240,0,255,72,57,192,240,2,240,0,15,141,245,255,
  136,193,240,2,72,211,232,240,0,255,252,247,216,240,0,255,72,252,247,216,240,
  0,255,144,240,0,49,210,191,237,252,247,252,247,135,208,240,0,255,184,240,
  0,0,0,0,0,255,144,240,0,49,210,252,247,252,240,240,0,135,208,240,0,255,72,
  144,240,0,49,210,72,252,247,252,240,240,0,72,135,208,240,0,255,129,252,240,
  240,0,239,255,72,129,252,248,240,0,239,15,130,245,255,72,129,252,240,240,
  0,239,255,49,192,240,2,240,0,255,72,57,192,240,2,240,0,15,130,245,255,72,
  49,192,240,2,240,0,255,184,240,0,237,255,72,129,252,248,240,0,239,15,134,
  245,255,137,192,240,2,240,0,255,72,57,192,240,2,240,0,15,134,245,255,72,137,
  192,240,2,240,0,255,193,252,248,240,0,235,255,72,129,252,248,240,0,239,15,
  140,245,255,72,193,252,248,240,0,235,255,136,193,240,2,211,252,248,240,0,
  255,72,57,192,240,2,240,0,15,140,245,255,136,193,240,2,72,211,252,248,240,
  0,255,72,129,252,248,240,0,239,15,142,245,255,15,183,192,240,2,240,0,102,
  193,200,240,0,8,255,15,200,240,0,255,72,15,200,240,0,255,72,57,192,240,2,
  240,0,15,142,245,255,248,13,72,199,192,231,3,0,0,252,233,244,11,255,248,11,
  91,65,92,65,93,65,94,65,95,201,195,255
};

#line 216 "fd_vm_jitproto.dasc"
  dasm_setup( &d, actions );

  dasm_State ** Dst = &d;

  /* Define the BPF->x86 mapping (static) */

  //| .define bpf_r0,  rsi
  //| .define bpf_r1,  r11
  //| .define bpf_r2,  r12
  //| .define bpf_r3,  r13
  //| .define bpf_r4,  r14
  //| .define bpf_r5,  r15
  //| .define bpf_r6,  rbx
  //| .define bpf_r7,  rbp
  //| .define bpf_r8,  r8
  //| .define bpf_r9,  r9
  //| .define bpf_r10, r10

  /* Leaves the following registers unoccupied:
     rax, rdi, rcx, rdx */

  /* Define the BPF->x86 mapping (dynamic) */

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

  uchar reg_bpf2x86[11] = {
    [ 0] = FD_DASM_RSI,
    [ 1] = FD_DASM_R11,
    [ 2] = FD_DASM_R12,
    [ 3] = FD_DASM_R13,
    [ 4] = FD_DASM_R14,
    [ 5] = FD_DASM_R15,
    [ 6] = FD_DASM_RBX,
    [ 7] = FD_DASM_RBP,
    [ 8] = FD_DASM_R8,
    [ 9] = FD_DASM_R9,
    [10] = FD_DASM_R10
  };

  /* Start emitting code */

  //| .code
  dasm_put(Dst, 0);
#line 273 "fd_vm_jitproto.dasc"

  /* Exception handlers */

  /* TODO */
  //|->sigfpe:
  //| mov rax, 999
  //| jmp ->leave
  dasm_put(Dst, 2);
#line 280 "fd_vm_jitproto.dasc"

  /* Start translating user code */

  //|->main:
  dasm_put(Dst, 16);
#line 284 "fd_vm_jitproto.dasc"

  /* SysV function prologue */

  //| push rbp
  //| mov rbp, rsp
  //| push r15
  //| push r14
  //| push r13
  //| push r12
  //| push rbx
  dasm_put(Dst, 19);
#line 294 "fd_vm_jitproto.dasc"

  /* Remember the VM pointer */

  //| mov64 rbx, (ulong)vm
  //| .type aVm, fd_vm_t, rbx
#define Dt1(_V) (int)(ptrdiff_t)&(((fd_vm_t *)0)_V)
  dasm_put(Dst, 33, (unsigned int)((ulong)vm), (unsigned int)(((ulong)vm)>>32));
#line 299 "fd_vm_jitproto.dasc"

  /* Restore register context */

  //| mov bpf_r0,  aVm->reg[ 0]
  //| mov bpf_r1,  aVm->reg[ 1]
  //| mov bpf_r2,  aVm->reg[ 2]
  //| mov bpf_r3,  aVm->reg[ 3]
  //| mov bpf_r4,  aVm->reg[ 4]
  //| mov bpf_r5,  aVm->reg[ 5]
  //| mov bpf_r6,  aVm->reg[ 6]
  //| mov bpf_r7,  aVm->reg[ 7]
  //| mov bpf_r8,  aVm->reg[ 8]
  //| mov bpf_r9,  aVm->reg[ 9]
  //| mov bpf_r10, aVm->reg[10]
  dasm_put(Dst, 38, Dt1(->reg[ 0]), Dt1(->reg[ 1]), Dt1(->reg[ 2]), Dt1(->reg[ 3]), Dt1(->reg[ 4]), Dt1(->reg[ 5]), Dt1(->reg[ 6]), Dt1(->reg[ 7]), Dt1(->reg[ 8]), Dt1(->reg[ 9]), Dt1(->reg[10]));
#line 313 "fd_vm_jitproto.dasc"

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

    next_label = bpf_label_off + (int)( text_end - text_start );
    //|=>next_label:
    dasm_put(Dst, 83, next_label);
#line 353 "fd_vm_jitproto.dasc"

    /* Translate instruction */

    switch( opcode ) {

    /* 0x00 - 0x0f ******************************************************/

    case 0x04:  /* FD_SBPF_OP_ADD_IMM */
      //| add dst32, imm
      dasm_put(Dst, 85, (x86_dst), imm);
#line 362 "fd_vm_jitproto.dasc"
      break;

    case 0x05:  /* FD_SBPF_OP_JA */
      //| jmp =>jmp_dst_lbl
      dasm_put(Dst, 91, jmp_dst_lbl);
#line 366 "fd_vm_jitproto.dasc"
      break;

    case 0x07:  /* FD_SBPF_OP_ADD64_IMM */
      //| add dst64, imm
      dasm_put(Dst, 95, (x86_dst), imm);
#line 370 "fd_vm_jitproto.dasc"
      break;

    case 0x0c:  /* FD_SBPF_OP_ADD_REG */
      //| add dst32, src32
      dasm_put(Dst, 102, (x86_src), (x86_dst));
#line 374 "fd_vm_jitproto.dasc"
      break;

    case 0x0f:  /* FD_SBPF_OP_ADD64_REG */
      //| add dst64, src64
      dasm_put(Dst, 109, (x86_src), (x86_dst));
#line 378 "fd_vm_jitproto.dasc"
      break;

    /* 0x10 - 0x1f ******************************************************/

    case 0x14:  /* FD_SBPF_OP_SUB_IMM */
      //| sub dst32, imm
      dasm_put(Dst, 117, (x86_dst), imm);
#line 384 "fd_vm_jitproto.dasc"
      break;

    case 0x15:  /* FD_SBPF_OP_JEQ_IMM */
      //| cmp dst64, imm
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 123, (x86_dst), imm, jmp_dst_lbl);
#line 389 "fd_vm_jitproto.dasc"
      break;

    case 0x17:  /* FD_SBPF_OP_SUB64_IMM */
      //| sub dst64, imm
      dasm_put(Dst, 134, (x86_dst), imm);
#line 393 "fd_vm_jitproto.dasc"
      break;

    case 0x18:  /* FD_SBPF_OP_LDQ */
      cur++;
      imm |= ( (ulong)fd_vm_instr_imm( *cur ) << 32 );
      //| mov dst64, imm
      dasm_put(Dst, 141, (x86_dst), imm);
#line 399 "fd_vm_jitproto.dasc"
      break;

    case 0x1c:  /* FD_SBPF_OP_SUB_REG */
      //| sub dst32, src32
      dasm_put(Dst, 148, (x86_src), (x86_dst));
#line 403 "fd_vm_jitproto.dasc"
      break;

    case 0x1d:  /* FD_SBPF_OP_JEQ_REG */
      //| cmp dst64, src64
      //| je =>jmp_dst_lbl
      dasm_put(Dst, 155, (x86_src), (x86_dst), jmp_dst_lbl);
#line 408 "fd_vm_jitproto.dasc"
      break;

    case 0x1f:  /* FD_SBPF_OP_SUB64_REG */
      //| sub dst64, src64
      dasm_put(Dst, 166, (x86_src), (x86_dst));
#line 412 "fd_vm_jitproto.dasc"
      break;

    /* 0x20 - 0x2f ******************************************************/

    case 0x24:  /* FD_SBPF_OP_MUL_IMM */
      /* TODO strength reduction? */
      //| imul dst32, imm
      dasm_put(Dst, 174, (x86_dst), (x86_dst), imm);
#line 419 "fd_vm_jitproto.dasc"
      break;

    case 0x25:  /* FD_SBPF_OP_JGT_IMM */
      //| cmp dst64, imm
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 182, (x86_dst), imm, jmp_dst_lbl);
#line 424 "fd_vm_jitproto.dasc"
      break;

    case 0x27:  /* FD_SBPF_OP_MUL64_IMM */
      /* TODO strength reduction? */
      //| imul dst64, imm
      dasm_put(Dst, 193, (x86_dst), (x86_dst), imm);
#line 429 "fd_vm_jitproto.dasc"
      break;

    case 0x2c:  /* FD_SBPF_OP_MUL_REG */
      //| imul dst32, src32
      dasm_put(Dst, 202, (x86_dst), (x86_src));
#line 433 "fd_vm_jitproto.dasc"
      break;

    case 0x2d:  /* FD_SBPF_OP_JGT_REG */
      //| cmp dst64, src64
      //| ja =>jmp_dst_lbl
      dasm_put(Dst, 210, (x86_src), (x86_dst), jmp_dst_lbl);
#line 438 "fd_vm_jitproto.dasc"
      break;

    case 0x2f:  /* FD_SBPF_OP_MUL64_REG */
      //| imul dst64, src64
      dasm_put(Dst, 221, (x86_dst), (x86_src));
#line 442 "fd_vm_jitproto.dasc"
      break;

    /* 0x30 - 0x3f ******************************************************/

    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 230);
#line 449 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg eax, dst32
      dasm_put(Dst, 235, (x86_dst), imm, (x86_dst));
#line 456 "fd_vm_jitproto.dasc"
      break;

    case 0x35:  /* FD_SBPF_OP_JGE_IMM */
      //| cmp dst64, imm
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 250, (x86_dst), imm, jmp_dst_lbl);
#line 461 "fd_vm_jitproto.dasc"
      break;

    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 230);
#line 466 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 261, (x86_dst), imm, (x86_dst));
#line 473 "fd_vm_jitproto.dasc"
      break;

    case 0x3c:  /* FD_SBPF_OP_DIV_REG */
      //| test src32, src32
      //| jz ->sigfpe
      dasm_put(Dst, 281, (x86_src), (x86_src));
#line 478 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 292, (x86_dst));
#line 480 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg eax, dst32
      dasm_put(Dst, 300, (x86_dst), (x86_src), (x86_dst));
#line 486 "fd_vm_jitproto.dasc"
      break;

    case 0x3d:  /* FD_SBPF_OP_JGE_REG */
      //| cmp dst64, src64
      //| jae =>jmp_dst_lbl
      dasm_put(Dst, 315, (x86_src), (x86_dst), jmp_dst_lbl);
#line 491 "fd_vm_jitproto.dasc"
      break;

    case 0x3f:  /* FD_SBPF_OP_DIV64_REG */
      //| test src64, src64
      //| jz ->sigfpe
      dasm_put(Dst, 326, (x86_src), (x86_src));
#line 496 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 1
        dasm_put(Dst, 292, (x86_dst));
#line 498 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rax, dst64
      dasm_put(Dst, 338, (x86_dst), (x86_src), (x86_dst));
#line 504 "fd_vm_jitproto.dasc"
      break;

    /* 0x40 - 0x4f ******************************************************/

    case 0x44:  /* FD_SBPF_OP_OR_IMM */
      //| or dst32, imm
      dasm_put(Dst, 356, (x86_dst), imm);
#line 510 "fd_vm_jitproto.dasc"
      break;

    case 0x45:  /* FD_SBPF_OP_JSET_IMM */
      //| test dst64, imm
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 362, (x86_dst), imm, jmp_dst_lbl);
#line 515 "fd_vm_jitproto.dasc"
      break;

    case 0x47:  /* FD_SBPF_OP_OR64_IMM */
      //| or dst64, imm
      dasm_put(Dst, 373, (x86_dst), imm);
#line 519 "fd_vm_jitproto.dasc"
      break;

    case 0x4c:  /* FD_SBPF_OP_OR_REG */
      //| or dst32, src32
      dasm_put(Dst, 380, (x86_src), (x86_dst));
#line 523 "fd_vm_jitproto.dasc"
      break;

    case 0x4d:  /* FD_SBPF_OP_JSET_REG */
      //| test dst64, src64
      //| jnz =>jmp_dst_lbl
      dasm_put(Dst, 387, (x86_src), (x86_dst), jmp_dst_lbl);
#line 528 "fd_vm_jitproto.dasc"
      break;

    case 0x4f:  /* FD_SBPF_OP_OR64_REG */
      //| or dst64, src64
      dasm_put(Dst, 398, (x86_src), (x86_dst));
#line 532 "fd_vm_jitproto.dasc"
      break;

    /* 0x50 - 0x5f ******************************************************/

    case 0x54:  /* FD_SBPF_OP_AND_IMM */
      //| and dst32, imm
      dasm_put(Dst, 406, (x86_dst), imm);
#line 538 "fd_vm_jitproto.dasc"
      break;

    case 0x55:  /* FD_SBPF_OP_JNE_IMM */
      //| cmp dst64, imm
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 412, (x86_dst), imm, jmp_dst_lbl);
#line 543 "fd_vm_jitproto.dasc"
      break;

    case 0x57:  /* FD_SBPF_OP_AND64_IMM */
      //| and dst64, imm
      dasm_put(Dst, 423, (x86_dst), imm);
#line 547 "fd_vm_jitproto.dasc"
      break;

    case 0x5c:  /* FD_SBPF_OP_AND_REG */
      //| and dst32, src32
      dasm_put(Dst, 430, (x86_src), (x86_dst));
#line 551 "fd_vm_jitproto.dasc"
      break;

    case 0x5d:  /* FD_SBPF_OP_JNE_REG */
      //| cmp dst64, src64
      //| jne =>jmp_dst_lbl
      dasm_put(Dst, 437, (x86_src), (x86_dst), jmp_dst_lbl);
#line 556 "fd_vm_jitproto.dasc"
      break;

    case 0x5f:  /* FD_SBPF_OP_AND64_REG */
      //| and dst64, src64
      dasm_put(Dst, 448, (x86_src), (x86_dst));
#line 560 "fd_vm_jitproto.dasc"
      break;

    /* 0x60 - 0x6f ******************************************************/

    case 0x61:  /* FD_SBPF_OP_LDXW */
      //| lea rdi, [src64+offset]
      dasm_put(Dst, 456, (x86_src), offset);
#line 566 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov dst32, [rdi]
      dasm_put(Dst, 464, (x86_dst));
#line 569 "fd_vm_jitproto.dasc"
      break;

    case 0x62:  /* FD_SBPF_OP_STW */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 573 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov dword [rdi], imm
      dasm_put(Dst, 469, imm);
#line 576 "fd_vm_jitproto.dasc"
      break;

    case 0x63:  /* FD_SBPF_OP_STXW */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 580 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov [rdi], src32
      dasm_put(Dst, 473, (x86_src));
#line 583 "fd_vm_jitproto.dasc"
      break;

    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
      //| shl dst32, imm
      dasm_put(Dst, 478, (x86_dst), imm);
#line 587 "fd_vm_jitproto.dasc"
      break;

    case 0x65:  /* FD_SBPF_OP_JSGT_IMM */
      //| cmp dst64, imm
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 484, (x86_dst), imm, jmp_dst_lbl);
#line 592 "fd_vm_jitproto.dasc"
      break;

    case 0x67:  /* FD_SBPF_OP_LSH64_IMM */
      //| shl dst64, imm
      dasm_put(Dst, 495, (x86_dst), imm);
#line 596 "fd_vm_jitproto.dasc"
      break;

    case 0x69:  /* FD_SBPF_OP_LDXH */
      //| lea rdi, [src64+offset]
      dasm_put(Dst, 456, (x86_src), offset);
#line 600 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      break;

    case 0x6a:  /* FD_SBPF_OP_STH */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 606 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov word [rdi], imm
      dasm_put(Dst, 502, imm);
#line 609 "fd_vm_jitproto.dasc"
      break;

    case 0x6b:  /* FD_SBPF_OP_STXH */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 613 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov [rdi], src32
      dasm_put(Dst, 473, (x86_src));
#line 616 "fd_vm_jitproto.dasc"
      break;

    case 0x6c:  /* FD_SBPF_OP_LSH_REG */
      //| mov cl, src8
      //| shl dst32, cl
      dasm_put(Dst, 507, (x86_src), (x86_dst));
#line 621 "fd_vm_jitproto.dasc"
      break;

    case 0x6d:  /* FD_SBPF_OP_JSGT_REG */
      //| cmp dst64, src64
      //| jg =>jmp_dst_lbl
      dasm_put(Dst, 516, (x86_src), (x86_dst), jmp_dst_lbl);
#line 626 "fd_vm_jitproto.dasc"
      break;

    case 0x6f:  /* FD_SBPF_OP_LSH64_REG */
      //| mov cl, src8
      //| shl dst64, cl
      dasm_put(Dst, 527, (x86_src), (x86_dst));
#line 631 "fd_vm_jitproto.dasc"
      break;

    /* 0x70 - 0x7f ******************************************************/

    case 0x71:  /* FD_SBPF_OP_LDXB */
      //| lea rdi, [src64+offset]
      dasm_put(Dst, 456, (x86_src), offset);
#line 637 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      /* TODO is there a better way to zero upper and mov byte? */
      //| xor dst32, dst32
      //| mov Rb(x86_dst), [rdi]
      dasm_put(Dst, 537, (x86_dst), (x86_dst), (x86_dst));
#line 642 "fd_vm_jitproto.dasc"
      break;

    case 0x72:  /* FD_SBPF_OP_STB */
      //| lea rdi, [src64+offset]
      dasm_put(Dst, 456, (x86_src), offset);
#line 646 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov byte [rdi], imm
      dasm_put(Dst, 548, imm);
#line 649 "fd_vm_jitproto.dasc"
      break;

    case 0x73:  /* FD_SBPF_OP_STXB */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 653 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov byte [rdi], Rb(x86_src)
      dasm_put(Dst, 552, (x86_src));
#line 656 "fd_vm_jitproto.dasc"
      break;

    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
      //| shr dst32, imm
      dasm_put(Dst, 557, (x86_dst), imm);
#line 660 "fd_vm_jitproto.dasc"
      break;

    case 0x75:  /* FD_SBPF_OP_JSGE_IMM */
      //| cmp dst64, imm
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 563, (x86_dst), imm, jmp_dst_lbl);
#line 665 "fd_vm_jitproto.dasc"
      break;

    case 0x77:  /* FD_SBPF_OP_RSH64_IMM */
      //| shr dst64, imm
      dasm_put(Dst, 574, (x86_dst), imm);
#line 669 "fd_vm_jitproto.dasc"
      break;

    case 0x79:  /* FD_SBPF_OP_LDXQ */
      //| lea rdi, [src64+offset]
      dasm_put(Dst, 456, (x86_src), offset);
#line 673 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov dst64, [rdi]
      dasm_put(Dst, 581, (x86_dst));
#line 676 "fd_vm_jitproto.dasc"
      /* TODO need to skip ahead another instruction */
      break;

    case 0x7a:  /* FD_SBPF_OP_STQ */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 681 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov rax, imm
      //| mov [rdi], rax
      dasm_put(Dst, 587, imm);
#line 685 "fd_vm_jitproto.dasc"
      break;

    case 0x7b:  /* FD_SBPF_OP_STXQ */
      //| lea rdi, [dst64+offset]
      dasm_put(Dst, 456, (x86_dst), offset);
#line 689 "fd_vm_jitproto.dasc"
      // TODO translate
      // TODO check align
      //| mov [rdi], src64
      dasm_put(Dst, 595, (x86_src));
#line 692 "fd_vm_jitproto.dasc"
      break;

    case 0x7c:  /* FD_SBPF_OP_RSH_REG */
      //| mov cl, src8
      //| shr dst32, cl
      dasm_put(Dst, 601, (x86_src), (x86_dst));
#line 697 "fd_vm_jitproto.dasc"
      break;

    case 0x7d:  /* FD_SBPF_OP_JSGE_REG */
      //| cmp dst64, src64
      //| jge =>jmp_dst_lbl
      dasm_put(Dst, 610, (x86_src), (x86_dst), jmp_dst_lbl);
#line 702 "fd_vm_jitproto.dasc"
      break;

    case 0x7f:  /* FD_SBPF_OP_RSH64_REG */
      //| mov cl, src8
      //| shr dst64, cl
      dasm_put(Dst, 621, (x86_src), (x86_dst));
#line 707 "fd_vm_jitproto.dasc"
      break;

    /* 0x80-0x8f ********************************************************/

    case 0x84:  /* FD_SBPF_OP_NEG */
      //| neg dst32
      dasm_put(Dst, 631, (x86_dst));
#line 713 "fd_vm_jitproto.dasc"
      break;

    case 0x85:  /* FD_SBPF_OP_CALL_IMM */
      // TODO
      break;

    case 0x87:  /* FD_SBPF_OP_NEG64 */
      //| neg dst64
      dasm_put(Dst, 637, (x86_dst));
#line 721 "fd_vm_jitproto.dasc"
      break;

    case 0x8d:  /* FD_SBPF_OP_CALL_REG */
      // TODO
      break;

    /* 0x90 - 0x9f ******************************************************/

    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 230);
#line 732 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      //| xchg edx, dst32
      dasm_put(Dst, 644, (x86_dst), imm, (x86_dst));
#line 739 "fd_vm_jitproto.dasc"
      break;

    case 0x95:  /* FD_SBPF_OP_EXIT */
      //| jmp ->leave
      dasm_put(Dst, 11);
#line 743 "fd_vm_jitproto.dasc"
      break;

    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      if( FD_UNLIKELY( imm==0 ) ) {
        //| jmp ->sigfpe
        dasm_put(Dst, 230);
#line 748 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| mov rdi, imm
      //| div rdi
      //| xchg rax, dst64
      dasm_put(Dst, 261, (x86_dst), imm, (x86_dst));
#line 755 "fd_vm_jitproto.dasc"
      break;

    case 0x9c:  /* FD_SBPF_OP_MOD_REG */
      //| test src32, src32
      //| jz ->sigfpe
      dasm_put(Dst, 281, (x86_src), (x86_src));
#line 760 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 660, (x86_dst));
#line 762 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg eax, dst32
      //| xor edx, edx
      //| div src32
      //| xchg edx, dst32
      dasm_put(Dst, 668, (x86_dst), (x86_src), (x86_dst));
#line 768 "fd_vm_jitproto.dasc"
      break;

    case 0x9f:  /* FD_SBPF_OP_MOD64_REG */
      //| test src64, src64
      //| jz ->sigfpe
      dasm_put(Dst, 326, (x86_src), (x86_src));
#line 773 "fd_vm_jitproto.dasc"
      if( x86_dst==x86_src ) {
        //| mov dst32, 0
        dasm_put(Dst, 660, (x86_dst));
#line 775 "fd_vm_jitproto.dasc"
        break;
      }
      //| xchg rax, dst64
      //| xor edx, edx
      //| div src64
      //| xchg rdx, dst64
      dasm_put(Dst, 684, (x86_dst), (x86_src), (x86_dst));
#line 781 "fd_vm_jitproto.dasc"
      break;

    /* 0xa0 - 0xaf ******************************************************/

    case 0xa4:  /* FD_SBPF_OP_XOR_IMM */
      //| xor dst32, imm
      dasm_put(Dst, 703, (x86_dst), imm);
#line 787 "fd_vm_jitproto.dasc"
      break;

    case 0xa5:  /* FD_SBPF_OP_JLT_IMM */
      //| cmp dst64, imm
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 710, (x86_dst), imm, jmp_dst_lbl);
#line 792 "fd_vm_jitproto.dasc"
      break;

    case 0xa7:  /* FD_SBPF_OP_XOR64_IMM */
      // TODO sign extension
      //| xor dst64, imm
      dasm_put(Dst, 721, (x86_dst), imm);
#line 797 "fd_vm_jitproto.dasc"
      break;

    case 0xac:  /* FD_SBPF_OP_XOR_REG */
      //| xor dst32, src32
      dasm_put(Dst, 729, (x86_src), (x86_dst));
#line 801 "fd_vm_jitproto.dasc"
      break;

    case 0xad:  /* FD_SBPF_OP_JLT_REG */
      //| cmp dst64, src64
      //| jb =>jmp_dst_lbl
      dasm_put(Dst, 736, (x86_src), (x86_dst), jmp_dst_lbl);
#line 806 "fd_vm_jitproto.dasc"
      break;

    case 0xaf:  /* FD_SBPF_OP_XOR64_REG */
      //| xor dst64, src64
      dasm_put(Dst, 747, (x86_src), (x86_dst));
#line 810 "fd_vm_jitproto.dasc"
      break;

    /* 0xb0 - 0xbf ******************************************************/

    case 0xb4:  /* FD_SBPF_OP_MOV_IMM */
      //| mov dst32, imm
      dasm_put(Dst, 755, (x86_dst), imm);
#line 816 "fd_vm_jitproto.dasc"
      break;

    case 0xb5:  /* FD_SBPF_OP_JLE_IMM */
      //| cmp dst64, imm
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 760, (x86_dst), imm, jmp_dst_lbl);
#line 821 "fd_vm_jitproto.dasc"
      break;

    case 0xb7:  /* FD_SBPF_OP_MOV64_IMM */
      //| mov dst64, imm
      dasm_put(Dst, 141, (x86_dst), imm);
#line 825 "fd_vm_jitproto.dasc"
      break;

    case 0xbc:  /* FD_SBPF_OP_MOV_REG */
      //| mov dst32, src32
      dasm_put(Dst, 771, (x86_src), (x86_dst));
#line 829 "fd_vm_jitproto.dasc"
      break;

    case 0xbd:  /* FD_SBPF_OP_JLE_REG */
      //| cmp dst64, src64
      //| jbe =>jmp_dst_lbl
      dasm_put(Dst, 778, (x86_src), (x86_dst), jmp_dst_lbl);
#line 834 "fd_vm_jitproto.dasc"
      break;

    case 0xbf:  /* FD_SBPF_OP_MOV64_REG */
      //| mov dst64, src64
      dasm_put(Dst, 789, (x86_src), (x86_dst));
#line 838 "fd_vm_jitproto.dasc"
      break;

    /* 0xc0 - 0xcf ******************************************************/

    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      //| sar dst32, imm
      dasm_put(Dst, 797, (x86_dst), imm);
#line 844 "fd_vm_jitproto.dasc"
      break;

    case 0xc5:  /* FD_SBPF_OP_JSLT_IMM */
      //| cmp dst64, imm
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 804, (x86_dst), imm, jmp_dst_lbl);
#line 849 "fd_vm_jitproto.dasc"
      break;

    case 0xc7:  /* FD_SBPF_OP_ARSH64_IMM */
      //| sar dst64, imm
      dasm_put(Dst, 815, (x86_dst), imm);
#line 853 "fd_vm_jitproto.dasc"
      break;

    case 0xcc:  /* FD_SBPF_OP_ARSH_REG */
      //| mov cl, src8
      //| sar dst32, cl
      dasm_put(Dst, 823, (x86_src), (x86_dst));
#line 858 "fd_vm_jitproto.dasc"
      break;

    case 0xcd:  /* FD_SBPF_OP_JSLT_REG */
      //| cmp dst64, src64
      //| jl =>jmp_dst_lbl
      dasm_put(Dst, 833, (x86_src), (x86_dst), jmp_dst_lbl);
#line 863 "fd_vm_jitproto.dasc"
      break;

    case 0xcf:  /* FD_SBPF_OP_ARSH64_REG */
      //| mov cl, src8
      //| sar dst64, cl
      dasm_put(Dst, 844, (x86_src), (x86_dst));
#line 868 "fd_vm_jitproto.dasc"
      break;

    /* 0xd0 - 0xdf ******************************************************/

    case 0xd4:  /* FD_SBPF_OP_END_LE */
      /* nop */
      break;

    case 0xd5:  /* FD_SBPF_OP_JSLE_IMM */
      //| cmp dst64, imm
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 855, (x86_dst), imm, jmp_dst_lbl);
#line 879 "fd_vm_jitproto.dasc"
      break;

    case 0xdc:  /* FD_SBPF_OP_END_BE */
      switch( imm ) {
      case 16U:
        //| movzx dst32, Rw(x86_dst)
        //| ror Rw(x86_dst), 8
        dasm_put(Dst, 866, (x86_dst), (x86_dst), (x86_dst));
#line 886 "fd_vm_jitproto.dasc"
        break;
      case 32U:
        //| bswap dst32
        dasm_put(Dst, 880, (x86_dst));
#line 889 "fd_vm_jitproto.dasc"
        break;
      case 64U:
        //| bswap dst64
        dasm_put(Dst, 885, (x86_dst));
#line 892 "fd_vm_jitproto.dasc"
        break;
      default:
        break;
        // TODO sigill
      }
      break;

    case 0xdd:  /* FD_SBPF_OP_JSLE_REG */
      //| cmp dst64, src64
      //| jle =>jmp_dst_lbl
      dasm_put(Dst, 891, (x86_src), (x86_dst), jmp_dst_lbl);
#line 902 "fd_vm_jitproto.dasc"
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
  dasm_put(Dst, 902);
#line 918 "fd_vm_jitproto.dasc"

  //|->leave:
  //| pop rbx
  //| pop r12
  //| pop r13
  //| pop r14
  //| pop r15
  //| leave
  //| ret
  dasm_put(Dst, 916);
#line 927 "fd_vm_jitproto.dasc"

  /* Finish genearting code */

  ulong sz;
  dasm_link( &d, &sz );

  void * buf = mmap( 0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  dasm_encode( &d, buf );
  mprotect( buf, sz, PROT_READ | PROT_EXEC );

  dasm_free( &d );

  /* Execute */

  int (* main_)( void ) = (int (*)( void ))( (ulong)labels[ lbl_main ] );
  printf( "JIT returned %d\n", main_() );

  fd_halt();
  return 0;
}
