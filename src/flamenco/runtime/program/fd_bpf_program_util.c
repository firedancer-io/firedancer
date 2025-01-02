#include "fd_bpf_program_util.h"
#include "fd_bpf_loader_program.h"
#include "fd_loader_v4_program.h"
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

  /* SBPF version */
  validated_prog->sbpf_version = elf_info->sbpf_version;

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

/* Similar to the below function, but gets the executable program content for the v4 loader. 
   Unlike the v3 loader, the programdata is stored in a single program account. The program must
   NOT be retracted to be added to the cache. */
static int
fd_bpf_get_executable_program_content_for_v4_loader( fd_borrowed_account_t * program_acc,
                                                     uchar const          ** program_data,
                                                     ulong                 * program_data_len ) {
  int err;
  fd_loader_v4_state_t state = {0};

  /* Get the current loader v4 state. This implicitly also checks the dlen. */
  err = fd_loader_v4_get_state( program_acc, &state );
  if( FD_UNLIKELY( err ) ) {
    return -1;
  }

  /* The program must be deployed or finalized. */
  if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( &state ) ) ) {
    return -1;
  }

  *program_data     = program_acc->const_data + LOADER_V4_PROGRAM_DATA_OFFSET;
  *program_data_len = program_acc->const_meta->dlen - LOADER_V4_PROGRAM_DATA_OFFSET;
  return 0;
}

static int
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

static int
fd_bpf_get_executable_program_content_for_v1_v2_loaders( fd_borrowed_account_t * program_acc,
                                                         uchar const          ** program_data,
                                                         ulong                 * program_data_len ) {
  *program_data     = program_acc->const_data;
  *program_data_len = program_acc->const_meta->dlen;
  return 0;
}

void
fd_bpf_get_sbpf_versions( uint *                     sbpf_min_version,
                          uint *                     sbpf_max_version,
                          fd_exec_slot_ctx_t const * slot_ctx ) {
  int disable_v0  = FD_FEATURE_ACTIVE( slot_ctx, disable_sbpf_v0_execution );
  int reenable_v0 = FD_FEATURE_ACTIVE( slot_ctx, reenable_sbpf_v0_execution );
  int enable_v0   = !disable_v0 || reenable_v0;
  int enable_v1   = FD_FEATURE_ACTIVE( slot_ctx, enable_sbpf_v1_deployment_and_execution );
  int enable_v2   = FD_FEATURE_ACTIVE( slot_ctx, enable_sbpf_v2_deployment_and_execution );
  int enable_v3   = FD_FEATURE_ACTIVE( slot_ctx, enable_sbpf_v3_deployment_and_execution );

  *sbpf_min_version = enable_v0 ? FD_SBPF_V0 : FD_SBPF_V3;
  if( enable_v3 ) {
    *sbpf_max_version = FD_SBPF_V3;
  } else if( enable_v2 ) {
    *sbpf_max_version = FD_SBPF_V2;
  } else if( enable_v1 ) {
    *sbpf_max_version = FD_SBPF_V1;
  } else {
    *sbpf_max_version = FD_SBPF_V0;
  }
}

int
fd_bpf_create_bpf_program_cache_entry( fd_exec_slot_ctx_t    * slot_ctx,
                                       fd_borrowed_account_t * program_acc ) {
  FD_SCRATCH_SCOPE_BEGIN {

    fd_pubkey_t * program_pubkey = program_acc->pubkey;

    fd_funk_t     *   funk             = slot_ctx->acc_mgr->funk;
    fd_funk_txn_t *   funk_txn         = slot_ctx->funk_txn;
    fd_funk_rec_key_t id               = fd_acc_mgr_cache_key( program_pubkey );

    uchar const *     program_data     = NULL;
    ulong             program_data_len = 0UL;

    /* For v3 loaders, deserialize the program account and lookup the
       programdata account. Deserialize the programdata account. */

    int res;
    if( !memcmp( program_acc->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      res = fd_bpf_get_executable_program_content_for_upgradeable_loader( slot_ctx, program_acc, &program_data, &program_data_len );
    } else if( !memcmp( program_acc->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
      res = fd_bpf_get_executable_program_content_for_v4_loader( program_acc, &program_data, &program_data_len );
    } else {
      res = fd_bpf_get_executable_program_content_for_v1_v2_loaders( program_acc, &program_data, &program_data_len );
    }

    if( res ) {
      return -1;
    }

    fd_sbpf_elf_info_t elf_info = {0};
    uint min_sbpf_version, max_sbpf_version;
    fd_bpf_get_sbpf_versions( &min_sbpf_version, &max_sbpf_version, slot_ctx );
    if( fd_sbpf_elf_peek( &elf_info, program_data, program_data_len, /* deploy checks */ 0, min_sbpf_version, max_sbpf_version ) == NULL ) {
      FD_LOG_DEBUG(( "fd_sbpf_elf_peek() failed: %s", fd_sbpf_strerror() ));
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
      return -1;
    }

    /* Allocate syscalls */

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    if( FD_UNLIKELY( !syscalls ) ) {
      FD_LOG_ERR(( "Call to fd_sbpf_syscalls_new() failed" ));
    }

    fd_vm_syscall_register_slot( syscalls, slot_ctx, 0 );

    /* Load program. */

    if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls, false ) ) ) {
      /* Remove pending funk record */
      FD_LOG_DEBUG(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
      fd_funk_rec_remove( funk, rec, funk_txn->xid.ul[0] );
      return -1;
    }

    /* Validate the program. */

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
                      elf_info.sbpf_version,
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

    res = fd_vm_validate( vm );
    if( FD_UNLIKELY( res ) ) {
      /* Remove pending funk record */
      FD_LOG_DEBUG(( "fd_vm_validate() failed" ));
      fd_funk_rec_remove( funk, rec, 0UL );
      return -1;
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
                                                      fd_tpool_t *         tpool ) {
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
        if( rec->flags & FD_FUNK_REC_FLAG_ERASE ) continue;
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
        int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx, funk_txn, pubkey );
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
                                                fd_funk_txn_t *      funk_txn ) {
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
    if( !fd_funk_key_is_acc( rec->pair.key ) || ( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
      continue;
    }

    fd_pubkey_t const * program_pubkey = fd_type_pun_const( rec->pair.key[0].uc );

    int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx,
                                                               funk_txn,
                                                               program_pubkey );

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
                                                 fd_pubkey_t const *  pubkey ) {
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

  if( fd_bpf_create_bpf_program_cache_entry( slot_ctx, exec_rec ) != 0 ) {
    return -1;
  }

  return 0;
}

int
fd_bpf_load_cache_entry( fd_exec_slot_ctx_t const *     slot_ctx,
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
