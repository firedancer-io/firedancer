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
  validated_prog->magic = FD_SBPF_VALIDATED_PROGRAM_MAGIC;

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

  id.uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ELF_CACHE;

  return id;
}

/* Similar to the below function, but gets the executable program content for the v4 loader.
   Unlike the v3 loader, the programdata is stored in a single program account. The program must
   NOT be retracted to be added to the cache. */
static int
fd_bpf_get_executable_program_content_for_v4_loader( fd_txn_account_t      * program_acc,
                                                     uchar const          ** program_data,
                                                     ulong                 * program_data_len ) {
  int err;

  /* Get the current loader v4 state. This implicitly also checks the dlen. */
  fd_loader_v4_state_t const * state = fd_loader_v4_get_state( program_acc, &err );
  if( FD_UNLIKELY( err ) ) {
    return -1;
  }

  /* The program must be deployed or finalized. */
  if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
    return -1;
  }

  *program_data     = program_acc->vt->get_data( program_acc ) + LOADER_V4_PROGRAM_DATA_OFFSET;
  *program_data_len = program_acc->vt->get_data_len( program_acc ) - LOADER_V4_PROGRAM_DATA_OFFSET;
  return 0;
}

static int
fd_bpf_get_executable_program_content_for_upgradeable_loader( fd_exec_slot_ctx_t *    slot_ctx,
                                                              fd_txn_account_t *      program_acc,
                                                              uchar const **          program_data,
                                                              ulong *                 program_data_len,
                                                              fd_spad_t *             runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( programdata_acc );

  fd_bpf_upgradeable_loader_state_t * program_account_state =
    fd_bincode_decode_spad(
      bpf_upgradeable_loader_state, runtime_spad,
      program_acc->vt->get_data( program_acc ),
      program_acc->vt->get_data_len( program_acc ),
      NULL );
  if( FD_UNLIKELY( !program_account_state ) ) {
    return -1;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    return -1;
  }

  fd_pubkey_t * programdata_address = &program_account_state->inner.program.programdata_address;

  if( fd_txn_account_init_from_funk_readonly( programdata_acc,
                                              programdata_address,
                                              slot_ctx->funk,
                                              slot_ctx->funk_txn ) != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  /* We don't actually need to decode here, just make sure that the account
     can be decoded successfully. */
  fd_bincode_decode_ctx_t ctx_programdata = {
    .data    = programdata_acc->vt->get_data( programdata_acc ),
    .dataend = programdata_acc->vt->get_data( programdata_acc ) + programdata_acc->vt->get_data_len( programdata_acc ),
  };

  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode_footprint( &ctx_programdata, &total_sz ) ) ) {
    return -1;
  }

  if( FD_UNLIKELY( programdata_acc->vt->get_data_len( programdata_acc )<PROGRAMDATA_METADATA_SIZE ) ) {
    return -1;
  }

  *program_data     = programdata_acc->vt->get_data( programdata_acc ) + PROGRAMDATA_METADATA_SIZE;
  *program_data_len = programdata_acc->vt->get_data_len( programdata_acc ) - PROGRAMDATA_METADATA_SIZE;
  return 0;
}

static int
fd_bpf_get_executable_program_content_for_v1_v2_loaders( fd_txn_account_t * program_acc,
                                                         uchar const     ** program_data,
                                                         ulong            * program_data_len ) {
  *program_data     = program_acc->vt->get_data( program_acc );
  *program_data_len = program_acc->vt->get_data_len( program_acc );
  return 0;
}

void
fd_bpf_get_sbpf_versions( uint *                sbpf_min_version,
                          uint *                sbpf_max_version,
                          ulong                 slot,
                          fd_features_t const * features ) {
  int disable_v0  = FD_FEATURE_ACTIVE_PTR( slot, features, disable_sbpf_v0_execution );
  int reenable_v0 = FD_FEATURE_ACTIVE_PTR( slot, features, reenable_sbpf_v0_execution );
  int enable_v0   = !disable_v0 || reenable_v0;
  int enable_v1   = FD_FEATURE_ACTIVE_PTR( slot, features, enable_sbpf_v1_deployment_and_execution );
  int enable_v2   = FD_FEATURE_ACTIVE_PTR( slot, features, enable_sbpf_v2_deployment_and_execution );
  int enable_v3   = FD_FEATURE_ACTIVE_PTR( slot, features, enable_sbpf_v3_deployment_and_execution );

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

static int
fd_bpf_create_bpf_program_cache_entry( fd_exec_slot_ctx_t *    slot_ctx,
                                       fd_txn_account_t *      program_acc,
                                       fd_spad_t *             runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    fd_pubkey_t * program_pubkey = program_acc->pubkey;

    fd_funk_t     *   funk             = slot_ctx->funk;
    fd_funk_txn_t *   funk_txn         = slot_ctx->funk_txn;
    fd_funk_rec_key_t id               = fd_acc_mgr_cache_key( program_pubkey );

    uchar const *     program_data     = NULL;
    ulong             program_data_len = 0UL;

    /* For v3 loaders, deserialize the program account and lookup the
       programdata account. Deserialize the programdata account. */

    int res;
    if( !memcmp( program_acc->vt->get_owner( program_acc ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      res = fd_bpf_get_executable_program_content_for_upgradeable_loader( slot_ctx, program_acc, &program_data, &program_data_len, runtime_spad );
    } else if( !memcmp( program_acc->vt->get_owner( program_acc ), fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
      res = fd_bpf_get_executable_program_content_for_v4_loader( program_acc, &program_data, &program_data_len );
    } else {
      res = fd_bpf_get_executable_program_content_for_v1_v2_loaders( program_acc, &program_data, &program_data_len );
    }

    if( res ) {
      return -1;
    }

    fd_sbpf_elf_info_t elf_info = {0};
    uint min_sbpf_version, max_sbpf_version;
    fd_bpf_get_sbpf_versions( &min_sbpf_version,
                              &max_sbpf_version,
                              slot_ctx->slot,
                              fd_bank_features_query( slot_ctx->bank ) );
    if( fd_sbpf_elf_peek( &elf_info, program_data, program_data_len, /* deploy checks */ 0, min_sbpf_version, max_sbpf_version ) == NULL ) {
      FD_LOG_DEBUG(( "fd_sbpf_elf_peek() failed: %s", fd_sbpf_strerror() ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    int funk_err = FD_FUNK_SUCCESS;
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, funk_txn, &id, prepare, NULL );
    if( rec == NULL || funk_err != FD_FUNK_SUCCESS ) {
      return -1;
    }

    ulong val_sz = fd_sbpf_validated_program_footprint( &elf_info );
    void * val = fd_funk_val_truncate(
        rec,
        fd_funk_alloc( funk ),
        fd_funk_wksp( funk ),
        0UL,
        val_sz,
        &funk_err );
    if( FD_UNLIKELY( funk_err ) ) {
      FD_LOG_ERR(( "fd_funk_val_truncate(sz=%lu) for account failed (%i-%s)", val_sz, funk_err, fd_funk_strerror( funk_err ) ));
    }

    fd_sbpf_validated_program_t * validated_prog = fd_sbpf_validated_program_new( val, &elf_info );

    ulong  prog_align     = fd_sbpf_program_align();
    ulong  prog_footprint = fd_sbpf_program_footprint( &elf_info );
    fd_sbpf_program_t * prog = fd_sbpf_program_new(  fd_spad_alloc( runtime_spad, prog_align, prog_footprint ), &elf_info, validated_prog->rodata );
    if( FD_UNLIKELY( !prog ) ) {
      fd_funk_rec_cancel( funk, prepare );
      return -1;
    }

    /* Allocate syscalls */

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_spad_alloc( runtime_spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
    if( FD_UNLIKELY( !syscalls ) ) {
      FD_LOG_ERR(( "Call to fd_sbpf_syscalls_new() failed" ));
    }

    fd_vm_syscall_register_slot( syscalls,
                                 slot_ctx->slot,
                                 fd_bank_features_query( slot_ctx->bank ),
                                 0 );

    /* Load program. */

    if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls, false ) ) ) {
      /* Remove pending funk record */
      FD_LOG_DEBUG(( "fd_sbpf_program_load() failed: %s", fd_sbpf_strerror() ));
      fd_funk_rec_cancel( funk, prepare );
      return -1;
    }

    /* Validate the program. */

    fd_vm_t _vm[ 1UL ];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    if( FD_UNLIKELY( !vm ) ) {
      FD_LOG_ERR(( "fd_vm_new() or fd_vm_join() failed" ));
    }
    fd_exec_instr_ctx_t dummy_instr_ctx = {0};
    fd_exec_txn_ctx_t   dummy_txn_ctx   = {0};
    dummy_txn_ctx.slot = slot_ctx->slot;

    if( FD_UNLIKELY( !slot_ctx->bank ) ) {
      /* We only handle this case for some unit tests. */
      dummy_txn_ctx.features = (fd_features_t){0};
    } else {
      dummy_txn_ctx.features = fd_bank_features_get( slot_ctx->bank );
    }
    dummy_instr_ctx.txn_ctx  = &dummy_txn_ctx;
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
                     syscalls,
                     NULL,
                     NULL,
                     NULL,
                     0U,
                     NULL,
                     0,
                     FD_FEATURE_ACTIVE_PTR( slot_ctx->slot, &dummy_txn_ctx.features, bpf_account_data_direct_mapping ),
                     0 );

    if( FD_UNLIKELY( !vm ) ) {
      FD_LOG_ERR(( "fd_vm_init() failed" ));
    }

    res = fd_vm_validate( vm );
    if( FD_UNLIKELY( res ) ) {
      /* Remove pending funk record */
      FD_LOG_DEBUG(( "fd_vm_validate() failed" ));
      fd_funk_rec_cancel( funk, prepare );
      return -1;
    }

    fd_memcpy( validated_prog->calldests_shmem, prog->calldests_shmem, fd_sbpf_calldests_footprint( prog->rodata_sz/8UL ) );
    validated_prog->calldests = fd_sbpf_calldests_join( validated_prog->calldests_shmem );

    validated_prog->entry_pc = prog->entry_pc;
    validated_prog->last_updated_slot = slot_ctx->slot;
    validated_prog->text_off = prog->text_off;
    validated_prog->text_cnt = prog->text_cnt;
    validated_prog->text_sz = prog->text_sz;
    validated_prog->rodata_sz = prog->rodata_sz;

    fd_funk_rec_publish( funk, prepare );

    return 0;
  } FD_SPAD_FRAME_END;
}

static int
fd_bpf_check_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                 fd_pubkey_t const *  pubkey,
                                                 fd_spad_t *          runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( exec_rec );
  if( fd_txn_account_init_from_funk_readonly( exec_rec, pubkey, slot_ctx->funk, slot_ctx->funk_txn ) != FD_ACC_MGR_SUCCESS ) {
    return -1;
  }

  if( memcmp( exec_rec->vt->get_owner( exec_rec ), fd_solana_bpf_loader_deprecated_program_id.key,  sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->vt->get_owner( exec_rec ), fd_solana_bpf_loader_program_id.key,             sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->vt->get_owner( exec_rec ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) &&
      memcmp( exec_rec->vt->get_owner( exec_rec ), fd_solana_bpf_loader_v4_program_id.key,          sizeof(fd_pubkey_t) ) ) {
    return -1;
  }

  if( fd_bpf_create_bpf_program_cache_entry( slot_ctx, exec_rec, runtime_spad ) != 0 ) {
    return -1;
  }

  return 0;
}

void
fd_bpf_is_bpf_program( fd_funk_rec_t const * rec,
                       fd_wksp_t *           funk_wksp,
                       uchar *               is_bpf_program ) {

  if( !fd_funk_key_is_acc( rec->pair.key ) ) {
    *is_bpf_program = 0;
    return;
  }

  void const * raw = fd_funk_val( rec, funk_wksp );

  fd_account_meta_t const * metadata = fd_type_pun_const( raw );

  if( metadata &&
      memcmp( metadata->info.owner, fd_solana_bpf_loader_deprecated_program_id.key,  sizeof(fd_pubkey_t) ) &&
      memcmp( metadata->info.owner, fd_solana_bpf_loader_program_id.key,             sizeof(fd_pubkey_t) ) &&
      memcmp( metadata->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) &&
      memcmp( metadata->info.owner, fd_solana_bpf_loader_v4_program_id.key,          sizeof(fd_pubkey_t) ) ) {
    *is_bpf_program = 0;
  } else {
    *is_bpf_program = 1;
  }
}

static void FD_FN_UNUSED
fd_bpf_scan_task( void * tpool, ulong t0, ulong t1,
                  void * args, void * reduce, ulong stride FD_PARAM_UNUSED,
                  ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                  ulong m0 FD_PARAM_UNUSED, ulong m1 FD_PARAM_UNUSED,
                  ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED  ) {
  fd_funk_rec_t const * * recs           = (fd_funk_rec_t const * *)tpool;
  ulong                   start_idx      = t0;
  ulong                   end_idx        = t1;
  uchar *                 is_bpf_program = (uchar *)args;
  fd_exec_slot_ctx_t *    slot_ctx       = (fd_exec_slot_ctx_t *)reduce;

  for( ulong i=start_idx; i<=end_idx; i++ ) {
    fd_funk_rec_t const * rec = recs[ i ];
    fd_bpf_is_bpf_program( rec, fd_funk_wksp( slot_ctx->funk ), &is_bpf_program[ i ] );
  }
}

static void
fd_bpf_scan_and_create_program_cache_entry_tpool_helper( fd_tpool_t *            tpool,
                                                         fd_funk_rec_t const * * recs,
                                                         uchar *                 is_bpf_program,
                                                         ulong                   rec_cnt,
                                                         fd_exec_slot_ctx_t *    slot_ctx ) {

  ulong wcnt           = fd_tpool_worker_cnt( tpool );
  ulong cnt_per_worker = rec_cnt / wcnt;
  for( ulong worker_idx=1UL; worker_idx<wcnt; worker_idx++ ) {
    ulong start_idx = (worker_idx-1UL) * cnt_per_worker;
    ulong end_idx   = worker_idx!=wcnt-1UL ? fd_ulong_sat_sub( start_idx + cnt_per_worker, 1UL ) :
                                            fd_ulong_sat_sub( rec_cnt, 1UL );

    fd_tpool_exec( tpool, worker_idx, fd_bpf_scan_task,
                   recs, start_idx, end_idx,
                   is_bpf_program, slot_ctx, 0UL,
                   0UL, 0UL, worker_idx, 0UL, 0UL, 0UL );
  }

  for( ulong worker_idx=1UL; worker_idx<wcnt; worker_idx++ ) {
    fd_tpool_wait( tpool, worker_idx );
  }
}

void
bpf_tpool_wrapper( void * para_arg_1,
                   void * para_arg_2 FD_PARAM_UNUSED,
                   void * fn_arg_1,
                   void * fn_arg_2,
                   void * fn_arg_3,
                   void * fn_arg_4 ) {

  (void)para_arg_2; /* unused */

  fd_tpool_t *            tpool          = (fd_tpool_t *)para_arg_1;
  fd_funk_rec_t const * * recs           = (fd_funk_rec_t const **)fn_arg_1;
  uchar *                 is_bpf_program = (uchar *)fn_arg_2;
  ulong                   rec_cnt        = (ulong)fn_arg_3;
  fd_exec_slot_ctx_t *    slot_ctx       = (fd_exec_slot_ctx_t *)fn_arg_4;

  fd_bpf_scan_and_create_program_cache_entry_tpool_helper( tpool, recs, is_bpf_program, rec_cnt, slot_ctx );
}

int
fd_bpf_scan_and_create_bpf_program_cache_entry_para( fd_exec_slot_ctx_t *    slot_ctx,
                                                     fd_spad_t *             runtime_spad,
                                                     fd_exec_para_cb_ctx_t * exec_para_ctx ) {
  long        elapsed_ns = -fd_log_wallclock();
  fd_funk_t * funk       = slot_ctx->funk;
  ulong       cached_cnt = 0UL;

  /* Use random-ish xid to avoid concurrency issues */
  fd_funk_txn_xid_t cache_xid = fd_funk_generate_xid();

  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * cache_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &cache_xid, 1 );
  if( !cache_txn ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare() failed" ));
    return -1;
  }
  fd_funk_txn_end_write( funk );

  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;
  slot_ctx->funk_txn = cache_txn;

  fd_funk_txn_start_read( funk );
  fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, funk_txn );
  while( rec!=NULL ) {
    FD_SPAD_FRAME_BEGIN( runtime_spad ) {
      fd_funk_rec_t const * * recs           = fd_spad_alloc( runtime_spad, alignof(fd_funk_rec_t*), 65536UL * sizeof(fd_funk_rec_t const *) );
      uchar *                 is_bpf_program = fd_spad_alloc( runtime_spad, 8UL, 65536UL * sizeof(uchar) );

      /* Make a list of rec ptrs to process */
      ulong rec_cnt = 0UL;
      for( ; NULL != rec; rec = fd_funk_txn_next_rec( funk, rec ) ) {
        if( rec->flags & FD_FUNK_REC_FLAG_ERASE ) continue;
        recs[ rec_cnt ] = rec;
        rec_cnt++;
        if( FD_UNLIKELY( rec_cnt==65536UL ) ) break;
      }

      /* Pass in args */
      exec_para_ctx->fn_arg_1 = (void*)recs;
      exec_para_ctx->fn_arg_2 = (void*)is_bpf_program;
      exec_para_ctx->fn_arg_3 = (void*)rec_cnt;
      exec_para_ctx->fn_arg_4 = (void*)slot_ctx;
      fd_exec_para_call_func( exec_para_ctx );

      for( ulong i=0UL; i<rec_cnt; i++ ) {
        if( !is_bpf_program[ i ] ) {
          continue;
        }

        fd_pubkey_t const * pubkey = fd_type_pun_const( recs[i]->pair.key[0].uc );
        int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx, pubkey, runtime_spad );
        if( res==0 ) {
          cached_cnt++;
        }
      }

    } FD_SPAD_FRAME_END;
  }
  fd_funk_txn_end_read( funk );

  fd_funk_txn_start_write( funk );
  if( fd_funk_txn_publish_into_parent( funk, cache_txn, 1 ) != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "fd_funk_txn_publish_into_parent() failed" ));
  }
  fd_funk_txn_end_write( funk );

  slot_ctx->funk_txn = funk_txn;

  elapsed_ns += fd_log_wallclock();

  FD_LOG_NOTICE(( "loaded program cache - entries: %lu, elapsed_seconds: %ld", cached_cnt, elapsed_ns/(long)1e9 ));

  return 0;
}

int
fd_bpf_scan_and_create_bpf_program_cache_entry( fd_exec_slot_ctx_t * slot_ctx,
                                                fd_spad_t *          runtime_spad ) {
  fd_funk_t * funk = slot_ctx->funk;
  ulong       cnt  = 0UL;

  /* Use random-ish xid to avoid concurrency issues */
  fd_funk_txn_xid_t cache_xid = fd_funk_generate_xid();

  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * cache_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, &cache_xid, 1 );
  if( !cache_txn ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare() failed" ));
    return -1;
  }
  fd_funk_txn_end_write( funk );

  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;
  slot_ctx->funk_txn = cache_txn;

  fd_funk_txn_start_read( funk );
  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, funk_txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec )) {
    if( !fd_funk_key_is_acc( rec->pair.key ) || ( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
      continue;
    }

    fd_pubkey_t const * pubkey = fd_type_pun_const( rec->pair.key[0].uc );

    int res = fd_bpf_check_and_create_bpf_program_cache_entry( slot_ctx, pubkey, runtime_spad );

    if( res==0 ) {
      cnt++;
    }
  }
  fd_funk_txn_end_read( funk );

  FD_LOG_DEBUG(( "loaded program cache: %lu", cnt));

  fd_funk_txn_start_write( funk );
  if( fd_funk_txn_publish_into_parent( funk, cache_txn, 1 ) != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "fd_funk_txn_publish_into_parent() failed" ));
    return -1;
  }
  fd_funk_txn_end_write( funk );

  slot_ctx->funk_txn = funk_txn;
  return 0;
}

int
fd_bpf_load_cache_entry( fd_funk_t *                    funk,
                         fd_funk_txn_t *                funk_txn,
                         fd_pubkey_t const *            program_pubkey,
                         fd_sbpf_validated_program_t ** valid_prog ) {
  fd_funk_rec_key_t id   = fd_acc_mgr_cache_key( program_pubkey );

  for(;;) {
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global(funk, funk_txn, &id, NULL, query);

    if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
      if( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) {
        return -1;
      } else {
        continue;
      }
    }

    void const * data = fd_funk_val_const( rec, fd_funk_wksp(funk) );

    *valid_prog = (fd_sbpf_validated_program_t *)data;

    /* This test is actually too early. It should happen after the
       data is actually consumed.

       TODO: this is likely fine because nothing else is modifying the
       program cache records at the same time. */
    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      if( FD_UNLIKELY( (*valid_prog)->magic != FD_SBPF_VALIDATED_PROGRAM_MAGIC ) ) FD_LOG_ERR(( "invalid magic" ));
      return 0;
    }

    /* Try again */
  }
}
