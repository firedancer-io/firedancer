#include "fd_bpf_loader_v2_program.h"

#include "../fd_account.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm.h"
#include "fd_bpf_loader_serialization.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../context/fd_exec_instr_ctx.h"

#include <stdio.h>

int
fd_bpf_loader_v2_is_executable( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const *  pubkey ) {
  FD_BORROWED_ACCOUNT_DECL(rec);
  int read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, pubkey, rec );
  if( read_result != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  if( memcmp( rec->const_meta->info.owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) != 0 &&
      memcmp( rec->const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
    return -1;
  }

  if( rec->const_meta->info.executable != 1 ) {
    return -1;
  }

  return 0;
}


int
fd_bpf_loader_v2_user_execute( fd_exec_instr_ctx_t ctx ) {
  // FIXME: the program account is not in the instruction accounts?
  fd_borrowed_account_t * program_acc_view = NULL;
  int read_result = fd_txn_borrowed_account_view_idx( ctx.txn_ctx, ctx.instr->program_id, &program_acc_view );
  if (FD_UNLIKELY(read_result != FD_ACC_MGR_SUCCESS)) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_account_meta_t const * metadata = program_acc_view->const_meta;
  uchar const * program_data               = program_acc_view->const_data;
  ulong program_data_len = metadata->dlen;

  long dt = -fd_log_wallclock();
  fd_sbpf_elf_info_t elf_info;
  if (fd_sbpf_elf_peek( &elf_info, program_data, program_data_len ) == NULL) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* Allocate rodata segment */

  void * rodata = fd_valloc_malloc( ctx.valloc, 32UL,  elf_info.rodata_footprint );
  FD_TEST( rodata );

  /* Allocate program buffer */

  ulong  prog_align     = fd_sbpf_program_align();
  ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( ctx.valloc, prog_align, prog_footprint ), &elf_info, rodata );
  FD_TEST( prog );

  /* Allocate syscalls */

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( ctx.valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  fd_vm_syscall_register_all( syscalls );
  /* Load program */

  if(  0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
    FD_LOG_ERR(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
  }
  dt += fd_log_wallclock();
  (void)dt;
  // FD_LOG_WARNING(( "sbpf load: %32J - time: %6.6f ms", ctx.instr->program_id_pubkey.key, (double)dt*1e-6 ));

  ulong input_sz = 0;
  ulong pre_lens[256];
  uchar * input;
  if (FD_UNLIKELY(memcmp(metadata->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t)) == 0)) {
    input = fd_bpf_loader_input_serialize_unaligned(ctx, &input_sz, pre_lens);
  } else {
    input = fd_bpf_loader_input_serialize_aligned(ctx, &input_sz, pre_lens);
  }

  if( input==NULL ) {
    fd_valloc_free( ctx.valloc,  fd_sbpf_program_delete( prog ) );
    fd_valloc_free( ctx.valloc,  fd_sbpf_syscalls_delete( syscalls ) );
    fd_valloc_free( ctx.valloc, rodata);
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  fd_vm_init(
      /* vm        */ vm,
      /* instr_ctx */ &ctx,
      /* heap_max  */ FD_VM_HEAP_DEFAULT, /* TODO configure heap allocator */
      /* entry_cu  */ ctx.txn_ctx->compute_meter,
      /* rodata    */ prog->rodata,
      /* rodata_sz */ prog->rodata_sz,
      /* text      */ prog->text,
      /* text_cnt  */ prog->text_cnt,
      /* text_off  */ prog->text_off,
      /* entry_pc  */ prog->entry_pc,
      /* calldests */ prog->calldests,
      /* syscalls  */ syscalls,
      /* input     */ input,
      /* input_sz  */ input_sz,
      /* trace     */ NULL,
      /* sha       */ sha
  );

#ifdef FD_DEBUG_SBPF_TRACES
uchar * signature = (uchar*)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off;
uchar   sig[64];
fd_base58_decode_64( "mu7GV8tiEU58hnugxCcuuGh11MvM5tb2ib2qqYu9WYKHhc9Jsm187S31nEX1fg9RYM1NwWJiJkfXNNK21M6Yd8u", sig );
if( FD_UNLIKELY( !memcmp( signature, sig, 64UL ) ) ) {
  ulong event_max      = 1UL<<30;
  ulong event_data_max = 2048UL;
  vm->trace = fd_vm_trace_join( fd_vm_trace_new( fd_valloc_malloc(
    ctx.txn_ctx->valloc, fd_vm_trace_align(), fd_vm_trace_footprint( event_max, event_data_max ) ), event_max, event_data_max ) );
  if( FD_UNLIKELY( !vm->trace ) ) FD_LOG_ERR(( "unable to create trace" ));
}
#endif

  /* Technically no need to validate BPF Loader v2 programs as no more
     deploys are allowed.  Probably should validate regardless to
     prevent U.B. from malicious programs. */
//int validate_err = fd_vm_validate( &vm );
//if( FD_UNLIKELY( validate_err ) ) FD_LOG_ERR(( "fd_vm_validate failed (%i-%s)", validate_err, fd_vm_strerror( validate_err ) ));
//FD_LOG_WARNING(( "fd_vm_validate success" ));

  int exec_err = fd_vm_exec( vm );

#ifdef FD_DEBUG_SBPF_TRACES
if( FD_UNLIKELY( vm->trace ) ) {
  int err = fd_vm_trace_printf( vm->trace, vm->syscalls );
  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "fd_vm_trace_printf failed (%i-%s)", err, fd_vm_strerror( err ) ));
  fd_valloc_free( ctx.txn_ctx->valloc, fd_vm_trace_delete( fd_vm_trace_leave( vm->trace ) ) );
}
#endif

  ctx.txn_ctx->compute_meter = vm->cu;

  fd_valloc_free( ctx.valloc, fd_sbpf_program_delete( prog ) );
  fd_valloc_free( ctx.valloc, fd_sbpf_syscalls_delete( syscalls ) );
  fd_valloc_free( ctx.valloc, rodata );

//FD_LOG_WARNING(( "fd_vm_exec: %i-%s, ic: %lu, pc: %lu, ep: %lu, r0: %lu, cu: %lu, frame_cnt: %lu",
//                 exec_err, fd_vm_strerror( exec_err ), vm.ic, vm.pc, vm.entry_pc, vm.reg[0], vm.cu, vm.frame_cnt ));
//FD_LOG_WARNING(( "log: %s", vm.log_sz ? vm.log : "" )); /* What if log msg not '\0' terminated */

  if( FD_UNLIKELY( exec_err ) ) {
    fd_valloc_free( ctx.valloc, input);
    return -1;
  }

  if( FD_UNLIKELY( vm->reg[0] ) ) {
    fd_valloc_free( ctx.valloc, input);
    return -1;
  }

  if (FD_UNLIKELY(memcmp(metadata->info.owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t)) == 0)) {
    fd_bpf_loader_input_deserialize_unaligned(ctx, pre_lens, input, input_sz);
  } else {
    if( fd_bpf_loader_input_deserialize_aligned(ctx, pre_lens, input, input_sz)!=0 ) {
      FD_LOG_NOTICE(("HERE HERE"));
      return -1;
    }
  }

  return 0;
}

int
fd_bpf_loader_v2_program_execute( fd_exec_instr_ctx_t ctx ) {
  do {
    int err = fd_exec_consume_cus( ctx.txn_ctx, 570UL );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}
