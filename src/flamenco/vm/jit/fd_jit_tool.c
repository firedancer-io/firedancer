/* fd_vm_jitproto is a first draft of a sBPF JIT compiler for
   Firedancer.  Nothing to see here, it's broken and work-in-progress.

   This version of the JIT compiler supports a linear memory mapping
   only. */

#define _GNU_SOURCE
#include "../../fd_flamenco_base.h"

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

/* GDB JIT debug interface ********************************************/

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
    mem_region_cnt,
    NULL, /* acc_region_metas */
    0 /* is_deprecated */ ) );

  vm->reg[ 1] = 2UL<<32; /* account table address */
  vm->reg[ 2] = 2; /* account count */
  vm->reg[ 3] = 3UL<<32; /* instruction data address */
  vm->reg[ 4] = 0; /* instruction data size */
  vm->reg[10] = (1UL<<32) + 0x1000;

  /* Finish generating code */

  void * buf = mmap( 0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( buf==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed" ));

  ulong entry_pc    = prog->entry_pc;

  mprotect( buf, sz, PROT_READ | PROT_EXEC );

  /* Execute */
  long dt = -fd_log_wallclock();
  vm->reg[ 1] = 2UL<<32; /* account table address */
  vm->reg[ 2] = 2; /* account count */
  vm->reg[ 3] = 3UL<<32; /* instruction data address */
  vm->reg[ 4] = 0; /* instruction data size */
  vm->reg[10] = (1UL<<32) + 0x1000;
  vm->frame_cnt = 1; /* last exit writes to frame[0] */

  fd_halt();
  return 0;
}
