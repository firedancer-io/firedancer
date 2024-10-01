#include "fd_bpf_program_util.h"
#include "fd_bpf_loader_program.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/syscall/fd_vm_syscall.h"

#include <assert.h>

fd_sbpf_validated_program_t *
fd_sbpf_validated_program_new( void * mem, fd_sbpf_elf_info_t const * elf_info ) {
  fd_sbpf_validated_program_t * validated_prog = (fd_sbpf_validated_program_t *)mem;

  ulong l = FD_LAYOUT_INIT;

  /* calldests backing memory */
  l = FD_LAYOUT_APPEND( l, alignof(fd_sbpf_validated_program_t), sizeof(fd_sbpf_validated_program_t) );
  validated_prog->calldests_shmem = (uchar *)mem + l;

  /* rodata backing memory */
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(elf_info->rodata_sz/8UL) );
  validated_prog->rodata = (uchar *)mem + l;

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
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(elf_info->rodata_sz/8UL) );
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->rodata_footprint );
  l = FD_LAYOUT_FINI( l, 128UL );
  return l;
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
fd_bpf_get_executable_program_content_for_upgradeable_loader( fd_exec_slot_ctx_t    * slot_ctx,
                                                              fd_borrowed_account_t * program_acc,
                                                              uchar const          ** program_data,
                                                              ulong                 * program_data_len ) {
  FD_BORROWED_ACCOUNT_DECL( programdata_acc );

  fd_bincode_decode_ctx_t ctx = {
    .data    = program_acc->const_data,
    .dataend = program_acc->const_data + program_acc->const_meta->dlen,
    .valloc  = fd_scratch_virtual(),
  };

  fd_bpf_upgradeable_loader_state_t program_account_state = {0};
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( &program_account_state, &ctx ) ) ) {
    return -1;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( &program_account_state ) ) {
    return -1;
  }

  fd_pubkey_t * programdata_address = &program_account_state.inner.program.programdata_address;

  if( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, programdata_address, programdata_acc ) != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  fd_bincode_decode_ctx_t ctx_programdata = {
    .data    = programdata_acc->const_data,
    .dataend = programdata_acc->const_data + programdata_acc->const_meta->dlen,
    .valloc  = fd_scratch_virtual(),
  };

  fd_bpf_upgradeable_loader_state_t program_data_account_state = {0};
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( &program_data_account_state, &ctx_programdata ) ) ) {
    return -1;
  }

  *program_data     = programdata_acc->const_data + PROGRAMDATA_METADATA_SIZE;
  *program_data_len = programdata_acc->const_meta->dlen - PROGRAMDATA_METADATA_SIZE;
  return 0;
}

int
fd_bpf_get_executable_program_content_for_v1_v2_loaders( fd_borrowed_account_t * program_acc,
                                                         uchar const          ** program_data,
                                                         ulong                 * program_data_len ) {
  *program_data     = program_acc->const_data;
  *program_data_len = program_acc->const_meta->dlen;
  return 0;
}

int
fd_bpf_create_bpf_program_cache_entry( fd_exec_slot_ctx_t    * slot_ctx,
                                       fd_borrowed_account_t * program_acc,
                                       int                     update_program_blacklist ) {
  FD_SCRATCH_SCOPE_BEGIN {

    fd_pubkey_t * program_pubkey = program_acc->pubkey;

    fd_funk_t     *   funk             = slot_ctx->acc_mgr->funk;
    fd_funk_txn_t *   funk_txn         = slot_ctx->funk_txn;
    fd_funk_rec_key_t id               = fd_acc_mgr_cache_key( program_pubkey );

    uchar const *     program_data     = NULL;
    ulong             program_data_len = 0UL;

    /* For v3 loaders, deserialize the program account and lookup the
       programdata account. Deserialize the programdata account. As a note,
       programs that have invalid programdata accounts are intentionally not
       added to the program blacklist. Likewise, for all loaders, if the
       program account can't be deserialized then it is also intentionally not
       added to the program blacklist. */

    if( !fd_account_is_executable( program_acc->const_meta ) ) {
      return -1;
    }

    int res;
    if( !memcmp( program_acc->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      res = fd_bpf_get_executable_program_content_for_upgradeable_loader( slot_ctx, program_acc, &program_data, &program_data_len );
    } else {
      res = fd_bpf_get_executable_program_content_for_v1_v2_loaders( program_acc, &program_data, &program_data_len );
    }

    if( res ) {
      return -1;
    }

    fd_sbpf_elf_info_t elf_info = {0};
    if( fd_sbpf_elf_peek( &elf_info, program_data, program_data_len, /* deploy checks */ 0 ) == NULL ) {
      FD_LOG_DEBUG(( "fd_sbpf_elf_peek() failed: %s", fd_sbpf_strerror() ));
      if( update_program_blacklist ) {
        fd_bpf_add_to_program_blacklist( slot_ctx, program_pubkey );
      }
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    int funk_err = FD_FUNK_SUCCESS;
    fd_funk_rec_t const * existing_rec = fd_funk_rec_query_global( funk, funk_txn, &id, NULL );
    fd_funk_rec_t *       rec          = fd_funk_rec_write_prepare( funk, funk_txn, &id, fd_sbpf_validated_program_footprint( &elf_info ), 1, existing_rec, &funk_err );
    if( rec == NULL || funk_err != FD_FUNK_SUCCESS ) {
      return -1;
    }

    void * val = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_sbpf_validated_program_t * validated_prog = fd_sbpf_validated_program_new( val, &elf_info );

    ulong  prog_align     = fd_sbpf_program_align();
    ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
    fd_sbpf_program_t * prog = fd_sbpf_program_new(  fd_scratch_alloc( prog_align, prog_footprint ), &elf_info, validated_prog->rodata );
    if( FD_UNLIKELY( !prog ) ) {
      if( update_program_blacklist ) {
        fd_bpf_add_to_program_blacklist( slot_ctx, program_pubkey );
      }
      return -1;
    }

    /* Allocate syscalls */

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    if( FD_UNLIKELY( !syscalls ) ) {
      FD_LOG_ERR(( "Call to fd_sbpf_syscalls_new() failed" ));
    }

    fd_vm_syscall_register_slot( syscalls, slot_ctx, 0 );

    /* Load program. If program loading fails add it to the blacklist. */

    if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls, false ) ) ) {
      /* Remove pending funk record */
      FD_LOG_DEBUG(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
      fd_funk_rec_remove( funk, rec, 0 );

      /* Update program blacklist */
      if( update_program_blacklist ) {
        fd_bpf_add_to_program_blacklist( slot_ctx, program_pubkey );
      }
      return -1;
    }

    /* Only validate the program for the purposes of updating the program
       blacklist. */

    if( update_program_blacklist ) {

      fd_vm_t _vm[ 1UL ];
      fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
      if( FD_UNLIKELY( !vm ) ) {
        FD_LOG_ERR(( "fd_vm_new() or fd_vm_join() failed" ));
      }
      fd_exec_instr_ctx_t dummy_instr_ctx = {0};
      dummy_instr_ctx.slot_ctx = slot_ctx;
      vm = fd_vm_init( vm,
                       &dummy_instr_ctx,
                       0UL,
                       0UL,
                       prog->rodata,
                       prog->rodata_sz,
                       prog->text,
                       prog->text_cnt,
                       prog->text_off,
                       prog->text_sz,
                       prog->entry_pc,
                       prog->calldests,
                       NULL,
                       NULL,
                       NULL,
                       NULL,
                       0U,
                       NULL,
                       0,
                       FD_FEATURE_ACTIVE( slot_ctx, bpf_account_data_direct_mapping ) );

      if( FD_UNLIKELY( !vm ) ) {
        FD_LOG_ERR(( "fd_vm_init() failed" ));
      }

      int res = fd_vm_validate( vm );
      if( FD_UNLIKELY( res ) ) {
        /* Remove pending funk record */
        FD_LOG_DEBUG(( "fd_vm_validate() failed" ));
        fd_funk_rec_remove( funk, rec, 0 );

        /* Add program to blacklist */
        fd_bpf_add_to_program_blacklist( slot_ctx, program_pubkey );
        return -1;
      }
    }

    fd_memcpy( validated_prog->calldests_shmem, prog->calldests_shmem, fd_sbpf_calldests_footprint(prog->rodata_sz/8UL) );
    validated_prog->calldests = fd_sbpf_calldests_join( validated_prog->calldests_shmem );

    validated_prog->entry_pc = prog->entry_pc;
    validated_prog->last_updated_slot = slot_ctx->slot_bank.slot;
    validated_prog->text_off = prog->text_off;
    validated_prog->text_cnt = prog->text_cnt;
    validated_prog->text_sz = prog->text_sz;
    validated_prog->rodata_sz = prog->rodata_sz;

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

static void FD_FN_UNUSED
fd_bpf_scan_task( void * tpool,
                  ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                  void * args FD_PARAM_UNUSED,
                  void * reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                  ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                  ulong m0, ulong m1 FD_PARAM_UNUSED,
                  ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED  ) {
  fd_funk_rec_t const * recs = ((fd_funk_rec_t const **)tpool)[m0];
  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *)args;
  uchar * is_bpf_program = (uchar *)reduce + m0;

  if( !fd_funk_key_is_acc( recs->pair.key ) ) {
    *is_bpf_program = 0;
    return;
  }

  fd_pubkey_t const * pubkey = fd_type_pun_const( recs->pair.key[0].uc );

  FD_BORROWED_ACCOUNT_DECL( exec_rec );
  if( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, pubkey, exec_rec ) != FD_ACC_MGR_SUCCESS ) {
    return;
  }

  if( memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key,  sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_program_id.key,             sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key,          sizeof(fd_pubkey_t) ) ) {
    *is_bpf_program = 0;
  } else {
    *is_bpf_program = 1;
  }
}

int
fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                                      fd_funk_txn_t *      funk_txn,
                                                      fd_tpool_t *         tpool,
                                                      int                  update_program_blacklist ) {
  long elapsed_ns = -fd_log_wallclock();
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  ulong cached_cnt = 0;

  /* Use random-ish xid to avoid concurrency issues */
  fd_funk_txn_xid_t cache_xid = fd_funk_generate_xid();

  fd_funk_txn_t * cache_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &cache_xid, 1 );
  if( !cache_txn ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare() failed" ));
    return -1;
  }

  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  slot_ctx->funk_txn = cache_txn;

  fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, funk_txn );
  while( rec!=NULL ) {
    FD_SCRATCH_SCOPE_BEGIN {
      fd_funk_rec_t const * * recs = fd_scratch_alloc( alignof(fd_funk_rec_t const *), 65536UL * sizeof(fd_funk_rec_t const *) );
      uchar * is_bpf_program = fd_scratch_alloc( 8UL, 65536UL * sizeof(uchar) );

      /* Make a list of rec ptrs to process */
      ulong rec_cnt = 0;
      for( ; NULL != rec; rec = fd_funk_txn_next_rec( funk, rec ) ) {
        recs[ rec_cnt ] = rec;

        if( rec_cnt==65536UL ) {
          break;
        }

        rec_cnt++;
      }

      fd_tpool_exec_all_block( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_bpf_scan_task, recs, slot_ctx, is_bpf_program, 1, 0, rec_cnt );

      for( ulong i = 0; i<rec_cnt; i++ ) {
        if( !is_bpf_program[ i ] ) {
          continue;
        }

        fd_pubkey_t const * pubkey = fd_type_pun_const( recs[i]->pair.key[0].uc );
        int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx, funk_txn, pubkey, update_program_blacklist );
        if( res==0 ) {
          cached_cnt++;
        }
      }

    } FD_SCRATCH_SCOPE_END;
  }

  if( fd_funk_txn_publish_into_parent( funk, cache_txn, 1 ) != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "fd_funk_txn_publish_into_parent() failed" ));
    return -1;
  }

  slot_ctx->funk_txn = parent_txn;

  elapsed_ns += fd_log_wallclock();

  FD_LOG_NOTICE(( "loaded program cache - entries: %lu, elapsed_seconds: %ld", cached_cnt, elapsed_ns/(long)1e9 ));

  return 0;
}

int
fd_bpf_scan_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_funk_txn_t *      funk_txn,
                                                int                  update_program_blacklist ) {
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  ulong cnt = 0;

  /* Use random-ish xid to avoid concurrency issues */
  fd_funk_txn_xid_t cache_xid = fd_funk_generate_xid();

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

    int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx,
                                                               funk_txn,
                                                               program_pubkey,
                                                               update_program_blacklist );

    if( res==0 ) {
      cnt++;
    }
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
fd_bpf_check_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                 fd_funk_txn_t *      funk_txn,
                                                 fd_pubkey_t const *  pubkey,
                                                 int                  update_program_blacklist ) {
  FD_BORROWED_ACCOUNT_DECL( exec_rec );
  if( fd_acc_mgr_view( slot_ctx->acc_mgr, funk_txn, pubkey, exec_rec ) != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  if( memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key,  sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_program_id.key,             sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key,          sizeof(fd_pubkey_t) ) ) {
    return -1;
  }

  if( fd_bpf_create_bpf_program_cache_entry( slot_ctx, exec_rec, update_program_blacklist ) != 0 ) {
    return -1;
  }

  return 0;
}

int
fd_bpf_load_cache_entry( fd_exec_slot_ctx_t *           slot_ctx,
                         fd_pubkey_t const *            program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog ) {
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;
  fd_funk_rec_key_t id   = fd_acc_mgr_cache_key( program_pubkey );

  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, funk_txn, &id, NULL);

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
    return -1;
  }

  void const * data = fd_funk_val_const( rec, fd_funk_wksp(funk) );

  /* TODO: magic check */

  *valid_prog = (fd_sbpf_validated_program_t *)data;

  return 0;
}

void
fd_bpf_add_to_program_blacklist( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_pubkey_t const  * program_pubkey ) {
  if( FD_UNLIKELY( slot_ctx->program_blacklist_cnt>=sizeof(slot_ctx->program_blacklist)/sizeof(fd_pubkey_t) ) ) {
    FD_LOG_ERR(("The program blacklist is full and needs to be resized" ));
  }

  fd_memcpy( &slot_ctx->program_blacklist[ slot_ctx->program_blacklist_cnt++ ], program_pubkey, sizeof(fd_pubkey_t) );
}

int
fd_bpf_is_in_program_blacklist( fd_exec_slot_ctx_t * slot_ctx,
                                fd_pubkey_t const  * program_pubkey ) {

  for( uint i=0U; i<slot_ctx->program_blacklist_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( &slot_ctx->program_blacklist[i], program_pubkey, sizeof(fd_pubkey_t) ) ) ) {
      return 1;
    }
  }
  return 0;
}
