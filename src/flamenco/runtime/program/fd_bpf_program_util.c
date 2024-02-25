#include "fd_bpf_program_util.h"
#include "fd_bpf_loader_v2_program.h"
#include "fd_bpf_loader_v3_program.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"

#include <assert.h>

fd_sbpf_validated_program_t *
fd_sbpf_validated_program_new( void * mem ) {
  return (fd_sbpf_validated_program_t *)mem;
}


ulong
fd_sbpf_validated_program_align( void ) {
  return alignof(fd_sbpf_validated_program_t);
}

ulong
fd_sbpf_validated_program_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sbpf_validated_program_t), sizeof(fd_sbpf_validated_program_t) );
  assert( l==offsetof(fd_sbpf_validated_program_t, calldests) );
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(elf_info->rodata_sz/8UL) );
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->rodata_footprint );
  l = FD_LAYOUT_FINI( l, 128UL );
  return l;
}

uchar *
fd_sbpf_validated_program_rodata( fd_sbpf_validated_program_t * prog ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sbpf_validated_program_t), sizeof(fd_sbpf_validated_program_t) );
  assert( l==offsetof(fd_sbpf_validated_program_t, calldests) );
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(prog->rodata_sz/8UL) );
  l = FD_LAYOUT_FINI( l, 8UL );
  return (uchar *)fd_type_pun(prog) + l;
}

int
fd_bpf_get_executable_program_content_for_loader_v2( fd_exec_slot_ctx_t * slot_ctx,
                                                     fd_pubkey_t const * program_pubkey,
                                                     uchar const ** program_data,
                                                     ulong * program_data_len ) {
  FD_BORROWED_ACCOUNT_DECL( program_rec );
  int read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, program_pubkey, program_rec );
  if( read_result != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  *program_data = program_rec->const_data;
  *program_data_len = program_rec->const_meta->dlen;

  return 0;
}

int
fd_bpf_get_executable_program_content_for_upgradeable_loader( fd_exec_slot_ctx_t * slot_ctx,
                                                              fd_pubkey_t const * program_pubkey,
                                                              uchar const ** program_data,
                                                              ulong * program_data_len ) {
  FD_SCRATCH_SCOPE_BEGIN {
    FD_BORROWED_ACCOUNT_DECL( program_rec );
    int read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, program_pubkey, program_rec );
    if( read_result != FD_ACC_MGR_SUCCESS ) {
      return -1;
    }

    /* Get the program state */
    fd_bpf_upgradeable_loader_state_t program_state;
    fd_bincode_decode_ctx_t ctx = {
      .data    = program_rec->const_data,
      .dataend = program_rec->const_data + program_rec->const_meta->dlen,
      .valloc  = fd_scratch_virtual(),
    };

    if ( fd_bpf_upgradeable_loader_state_decode( &program_state, &ctx ) ) {
      FD_LOG_DEBUG(("fd_bpf_upgradeable_loader_state_decode failed"));
      return -1;
    }

    /* Check if the account is of enum variant "Program" */
    if( !fd_bpf_upgradeable_loader_state_is_program( &program_state ) ) {
      return -1;
    }

    /* Get the program data state */
    fd_pubkey_t const * programdata_pubkey = &program_state.inner.program.programdata_address;
    FD_BORROWED_ACCOUNT_DECL( programdata_rec );
    read_result = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, programdata_pubkey, programdata_rec );
    if( read_result != FD_ACC_MGR_SUCCESS ) {
      return -1;
    }

    *program_data_len = programdata_rec->const_meta->dlen - PROGRAMDATA_METADATA_SIZE;
    *program_data = programdata_rec->const_data + PROGRAMDATA_METADATA_SIZE;

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

static inline fd_funk_rec_key_t
fd_acc_mgr_cache_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, pubkey, sizeof(fd_pubkey_t) );
  memset( id.uc + sizeof(fd_pubkey_t), 0, sizeof(fd_funk_rec_key_t) - sizeof(fd_pubkey_t) );

  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ELF_CACHE;

  return id;
}

int
fd_bpf_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                       fd_pubkey_t const *  program_pubkey ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_funk_t *       funk = slot_ctx->acc_mgr->funk;
    fd_funk_txn_t *       funk_txn = slot_ctx->funk_txn;
    fd_funk_rec_key_t id   = fd_acc_mgr_cache_key( program_pubkey );

    uchar const * program_data = NULL;
    ulong program_data_len = 0;
    if( fd_bpf_loader_v3_is_executable( slot_ctx, program_pubkey ) == 0 ) {
      if( fd_bpf_get_executable_program_content_for_upgradeable_loader( slot_ctx, program_pubkey, &program_data, &program_data_len ) != 0 ) {
        return -1;
      }
    } else if( fd_bpf_loader_v2_is_executable( slot_ctx, program_pubkey ) == 0) {
      if( fd_bpf_get_executable_program_content_for_loader_v2( slot_ctx, program_pubkey, &program_data, &program_data_len ) != 0 ) {
        return -1;
      }
    } else {
      return -1;
    }

    fd_sbpf_elf_info_t elf_info;
    if( fd_sbpf_elf_peek( &elf_info, program_data, program_data_len ) == NULL ) {
      FD_LOG_WARNING(( "fd_sbpf_elf_peek() failed: %s", fd_sbpf_strerror() ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    int funk_err = FD_FUNK_SUCCESS;
    fd_funk_rec_t * rec = fd_funk_rec_write_prepare( funk, funk_txn, &id, fd_sbpf_validated_program_footprint( &elf_info ), 1, NULL, &funk_err );
    if( rec == NULL || funk_err != FD_FUNK_SUCCESS ) {
      return -1;
    }

    uchar * val = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_sbpf_validated_program_t * validated_prog = (fd_sbpf_validated_program_t *)val;
    validated_prog->rodata_sz = elf_info.rodata_sz;
    uchar * rodata = fd_sbpf_validated_program_rodata( validated_prog );

    ulong  prog_align     = fd_sbpf_program_align();
    ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
    fd_sbpf_program_t * prog = fd_sbpf_program_new(  fd_scratch_alloc( prog_align, prog_footprint ), &elf_info, rodata );
    FD_TEST( prog );

    /* Allocate syscalls */

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    FD_TEST( syscalls );

    fd_vm_syscall_register_all( syscalls );

    /* Load program */

    if( 0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls ) ) {
      FD_LOG_DEBUG(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
      return -1;
    }

    fd_memcpy( validated_prog->calldests, prog->calldests, fd_sbpf_calldests_footprint(prog->rodata_sz/8UL) );

    validated_prog->entry_pc = prog->entry_pc;
    validated_prog->last_updated_slot = slot_ctx->slot_bank.slot;
    validated_prog->text_off = prog->text_off;
    validated_prog->text_cnt = prog->text_cnt;
    validated_prog->rodata_sz = prog->rodata_sz;

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int
fd_bpf_scan_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_funk_txn_t * funk_txn ) {
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  ulong cnt = 0;

  /* Use random-ish xid to avoid concurrency issues */
  fd_funk_txn_xid_t cache_xid;
  cache_xid.ul[0] = fd_log_cpu_id() + 1;
  cache_xid.ul[1] = fd_log_cpu_id() + 1;
  cache_xid.ul[2] = fd_log_app_id() + 1;
  cache_xid.ul[3] = fd_log_thread_id() + 1;

  fd_funk_txn_t * cache_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &cache_xid, 1 );
  if( !cache_txn ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare() failed" ));
    return -1;
  }

  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  slot_ctx->funk_txn = cache_txn;

  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, funk_txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec )) {
    if( !fd_funk_key_is_acc( rec->pair.key ) ) {
      continue;
    }

    fd_pubkey_t const * program_pubkey = fd_type_pun_const( rec->pair.key[0].uc );

    FD_BORROWED_ACCOUNT_DECL(exec_rec);
    if( fd_acc_mgr_view( slot_ctx->acc_mgr, funk_txn, program_pubkey, exec_rec ) != FD_ACC_MGR_SUCCESS ) {
      continue;
    }

    if( exec_rec->const_meta->info.executable != 1 ) {
      continue;
    }

    if( fd_bpf_loader_v3_is_executable( slot_ctx, program_pubkey ) == 0
      || fd_bpf_loader_v2_is_executable( slot_ctx, program_pubkey ) == 0 ) {
      if( fd_bpf_create_bpf_program_cache_entry( slot_ctx, program_pubkey ) != 0 ) {
        continue;
      }
    } else {
      continue;
    }

    cnt++;
  }

  FD_LOG_DEBUG(( "loaded program cache: %lu", cnt));

  if( fd_funk_txn_publish_into_parent( funk, cache_txn, 1 ) != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "fd_funk_txn_publish_into_parent() failed" ));
    return -1;
  }

  slot_ctx->funk_txn = parent_txn;
  return 0;
}

int
fd_bpf_load_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                         fd_pubkey_t const * program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog ) {
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;
  fd_funk_rec_key_t id   = fd_acc_mgr_cache_key( program_pubkey );

  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, funk_txn, &id);

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
    return -1;
  }

  void const * data = fd_funk_val_const( rec, fd_funk_wksp(funk) );

  /* TODO: magic check */

  *valid_prog = (fd_sbpf_validated_program_t *)data;

  return 0;
}
