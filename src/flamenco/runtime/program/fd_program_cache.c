#include "fd_program_cache.h"
#include "fd_bpf_loader_program.h"
#include "fd_loader_v4_program.h"
#include "../../vm/fd_vm.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../funk/fd_funk_rec.h"

#include <assert.h>

fd_program_cache_entry_t *
fd_program_cache_entry_new( void *                     mem,
                            fd_sbpf_elf_info_t const * elf_info,
                            ulong                      last_slot_modified,
                            ulong                      last_slot_verified ) {
  fd_program_cache_entry_t * cache_entry = (fd_program_cache_entry_t *)mem;
  cache_entry->magic = FD_PROGRAM_CACHE_ENTRY_MAGIC;

  /* Failed verification flag */
  cache_entry->failed_verification = 0;

  /* Last slot the program was modified */
  cache_entry->last_slot_modified = last_slot_modified;

  /* Last slot verification checks were ran for this program */
  cache_entry->last_slot_verified = last_slot_verified;

  ulong l = FD_LAYOUT_INIT;

  /* calldests backing memory */
  l = FD_LAYOUT_APPEND( l, alignof(fd_program_cache_entry_t), sizeof(fd_program_cache_entry_t) );
  cache_entry->calldests_shmem_off = l;

  /* rodata backing memory */
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(elf_info->text_sz/8UL) );
  cache_entry->rodata_off = l;

  /* SBPF version */
  cache_entry->sbpf_version = elf_info->sbpf_version;

  return cache_entry;
}

/* Sets up defined fields for a record that failed verification. */
static void
fd_program_cache_entry_set_failed_verification( void * mem,
                                                ulong  last_slot_verified ) {
  fd_program_cache_entry_t * cache_entry = (fd_program_cache_entry_t *)mem;
  cache_entry->magic = FD_PROGRAM_CACHE_ENTRY_MAGIC;

  /* Failed verification flag */
  cache_entry->failed_verification = 1;

  /* Last slot the program was modified */
  cache_entry->last_slot_modified = 0UL;

  /* Last slot verification checks were ran for this program */
  cache_entry->last_slot_verified = last_slot_verified;

  /* All other fields are undefined. */
}

ulong
fd_program_cache_entry_footprint( fd_sbpf_elf_info_t const * elf_info ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_program_cache_entry_t), sizeof(fd_program_cache_entry_t) );
  l = FD_LAYOUT_APPEND( l, fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint(elf_info->text_sz/8UL) );
  l = FD_LAYOUT_APPEND( l, 8UL, elf_info->bin_sz );
  l = FD_LAYOUT_FINI( l, alignof(fd_program_cache_entry_t) );
  return l;
}

/* Returns the footprint of a record that failed verification. Note that
   all other fields are undefined besides the `failed_verification`,
   `last_slot_verified`, and `last_slot_modified` fields, so we can
   just return the core struct's size. */
static inline FD_FN_PURE ulong
fd_program_cache_failed_verification_entry_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_program_cache_entry_t), sizeof(fd_program_cache_entry_t) );
  l = FD_LAYOUT_FINI( l, alignof(fd_program_cache_entry_t) );
  return l;
}

fd_funk_rec_key_t
fd_program_cache_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, pubkey, sizeof(fd_pubkey_t) );
  memset( id.uc + sizeof(fd_pubkey_t), 0, sizeof(fd_funk_rec_key_t) - sizeof(fd_pubkey_t) );

  id.uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ELF_CACHE;

  return id;
}

/* Parse ELF info from programdata. */
static int
fd_program_cache_parse_elf_info( fd_bank_t *          bank,
                                 fd_sbpf_elf_info_t * elf_info,
                                 uchar const *        program_data,
                                 ulong                program_data_len ) {
  uint min_sbpf_version, max_sbpf_version;
  fd_bpf_get_sbpf_versions( &min_sbpf_version,
                            &max_sbpf_version,
                            fd_bank_slot_get( bank ),
                            fd_bank_features_query( bank ) );

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 0;
  config.sbpf_min_version = min_sbpf_version;
  config.sbpf_max_version = max_sbpf_version;

  if( FD_UNLIKELY( fd_sbpf_elf_peek( elf_info, program_data, program_data_len, &config )<0 ) ) {
    FD_LOG_DEBUG(( "fd_sbpf_elf_peek() failed" ));
    return -1;
  }
  return 0;
}

/* Similar to the below function, but gets the executable program content for the v4 loader.
   Unlike the v3 loader, the programdata is stored in a single program account. The program must
   NOT be retracted to be added to the cache. Returns a pointer to the programdata on success,
   and NULL on failure.

   Reasons for failure include:
   - The program state cannot be read from the account data or is in the `retracted` state. */
static uchar const *
fd_get_executable_program_content_for_v4_loader( fd_txn_account_t const * program_acc,
                                                 ulong *                  program_data_len ) {
  int err;

  /* Get the current loader v4 state. This implicitly also checks the dlen. */
  fd_loader_v4_state_t const * state = fd_loader_v4_get_state( program_acc, &err );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  /* The program must be deployed or finalized. */
  if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
    return NULL;
  }

  /* This subtraction is safe because get_state() implicitly checks the
     dlen. */
  *program_data_len = fd_txn_account_get_data_len( program_acc )-LOADER_V4_PROGRAM_DATA_OFFSET;
  return fd_txn_account_get_data( program_acc )+LOADER_V4_PROGRAM_DATA_OFFSET;
}

/* Gets the programdata for a v3 loader-owned account by decoding the account data
   as well as the programdata account. Returns a pointer to the programdata on success,
   and NULL on failure.

   Reasons for failure include:
   - The program account data cannot be decoded or is not in the `program` state.
   - The programdata account is not large enough to hold at least `PROGRAMDATA_METADATA_SIZE` bytes. */
static uchar const *
fd_get_executable_program_content_for_upgradeable_loader( fd_funk_t const *         funk,
                                                          fd_funk_txn_xid_t const * xid,
                                                          fd_txn_account_t const *  program_acc,
                                                          ulong *                   program_data_len ) {
  fd_bpf_upgradeable_loader_state_t program_account_state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      program_account_state,
      fd_txn_account_get_data( program_acc ),
      fd_txn_account_get_data_len( program_acc ),
      NULL ) ) ) {
    return NULL;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    return NULL;
  }

  fd_pubkey_t * programdata_address = &program_account_state->inner.program.programdata_address;
  FD_TXN_ACCOUNT_DECL( programdata_acc );
  if( fd_txn_account_init_from_funk_readonly( programdata_acc, programdata_address, funk, xid )!=FD_ACC_MGR_SUCCESS ) {
    return NULL;
  }

  /* We don't actually need to decode here, just make sure that the account
     can be decoded successfully. */
  fd_bincode_decode_ctx_t ctx_programdata = {
    .data    = fd_txn_account_get_data( programdata_acc ),
    .dataend = fd_txn_account_get_data( programdata_acc ) + fd_txn_account_get_data_len( programdata_acc ),
  };

  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode_footprint( &ctx_programdata, &total_sz ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( fd_txn_account_get_data_len( programdata_acc )<PROGRAMDATA_METADATA_SIZE ) ) {
    return NULL;
  }

  *program_data_len = fd_txn_account_get_data_len( programdata_acc ) - PROGRAMDATA_METADATA_SIZE;
  return fd_txn_account_get_data( programdata_acc ) + PROGRAMDATA_METADATA_SIZE;
}

/* Gets the programdata for a v1/v2 loader-owned account by returning a
   pointer to the account data. Returns a pointer to the programdata on
   success. Given the txn account API always returns a handle to the
   account data, this function should NEVER return NULL (since the
   programdata of v1 and v2 loader) accounts start at the beginning of
   the data. */
static uchar const *
fd_get_executable_program_content_for_v1_v2_loaders( fd_txn_account_t const * program_acc,
                                                     ulong *                  program_data_len ) {
  *program_data_len = fd_txn_account_get_data_len( program_acc );
  return fd_txn_account_get_data( program_acc );
}

uchar const *
fd_program_cache_get_account_programdata( fd_funk_t const *         funk,
                                          fd_funk_txn_xid_t const * xid,
                                          fd_txn_account_t const *  program_acc,
                                          ulong *                   out_program_data_len ) {
  /* v1/v2 loaders: Programdata is just the account data.
     v3 loader: Programdata lives in a separate account. Deserialize the
                program account and lookup the programdata account.
                Deserialize the programdata account.
     v4 loader: Programdata lives in the program account, offset by
                LOADER_V4_PROGRAM_DATA_OFFSET. */
  if( !memcmp( fd_txn_account_get_owner( program_acc ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_get_executable_program_content_for_upgradeable_loader( funk, xid, program_acc, out_program_data_len );
  } else if( !memcmp( fd_txn_account_get_owner( program_acc ), fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_get_executable_program_content_for_v4_loader( program_acc, out_program_data_len );
  } else if( !memcmp( fd_txn_account_get_owner( program_acc ), fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
             !memcmp( fd_txn_account_get_owner( program_acc ), fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_get_executable_program_content_for_v1_v2_loaders( program_acc, out_program_data_len );
  }
  return NULL;
}

/* This function is used to validate an sBPF program and set the
   program's flags accordingly. The return code only signifies whether
   the program was successfully validated or not. Regardless of the
   return code, the program should still be added to the cache.
   `cache_entry` is expected to be a pre-allocated struct with enough
   space to hold its field members + calldests info.

   Reasons for failure include:
   - Insufficient memory in the spad to allocate memory for local
     objects.
   - The sBPF program fails to be loaded or validated validated.

   On a failure that doesn't kill the client, the `failed_verification`
   flag for the record is set to 1, and the `last_slot_verified` field
   is set to the current slot.

   On success, `cache_entry` is updated with the loaded sBPF program
   metadata, as well as the `last_slot_modified`, `last_slot_verified`,
   and `failed_verification` flags. */
static int
fd_program_cache_validate_sbpf_program( fd_bank_t *                bank,
                                        fd_sbpf_elf_info_t const * elf_info,
                                        uchar const *              program_data,
                                        ulong                      program_data_len,
                                        fd_spad_t *                runtime_spad,
                                        fd_program_cache_entry_t * cache_entry /* out */ ) {
  ulong               prog_align     = fd_sbpf_program_align();
  ulong               prog_footprint = fd_sbpf_program_footprint( elf_info );
  void              * prog_mem       = fd_spad_alloc_check( runtime_spad, prog_align, prog_footprint );
  fd_sbpf_program_t * prog           = fd_sbpf_program_new( prog_mem , elf_info, fd_program_cache_get_rodata( cache_entry ) );
  if( FD_UNLIKELY( !prog ) ) {
    FD_LOG_DEBUG(( "fd_sbpf_program_new() failed" ));
    cache_entry->failed_verification = 1;
    return -1;
  }

  /* Allocate syscalls */

  void               * syscalls_mem = fd_spad_alloc_check( runtime_spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() );
  fd_sbpf_syscalls_t * syscalls     = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( syscalls_mem ) );
  if( FD_UNLIKELY( !syscalls ) ) {
    FD_LOG_CRIT(( "Call to fd_sbpf_syscalls_new() failed" ));
  }

  fd_vm_syscall_register_slot( syscalls,
                               fd_bank_slot_get( bank ),
                               fd_bank_features_query( bank ),
                               0 );

  /* Load program. */

  fd_sbpf_loader_config_t config = { 0 };
  if( FD_UNLIKELY( 0!=fd_sbpf_program_load( prog, program_data, program_data_len, syscalls, &config, NULL ) ) ) {
    FD_LOG_DEBUG(( "fd_sbpf_program_load() failed" ));
    cache_entry->failed_verification = 1;
    fd_sbpf_syscalls_leave( syscalls );
    return -1;
  }

  /* Validate the program. */

  fd_vm_t _vm[ 1UL ];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  if( FD_UNLIKELY( !vm ) ) {
    FD_LOG_CRIT(( "fd_vm_new() or fd_vm_join() failed" ));
  }

  int direct_mapping = FD_FEATURE_ACTIVE( fd_bank_slot_get( bank ), fd_bank_features_query( bank ), bpf_account_data_direct_mapping );

  vm = fd_vm_init( vm,
                   NULL, /* OK since unused in `fd_vm_validate()` */
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
                   elf_info->sbpf_version,
                   syscalls,
                   NULL,
                   NULL,
                   NULL,
                   0U,
                   NULL,
                   0,
                   direct_mapping,
                   0 );

  if( FD_UNLIKELY( !vm ) ) {
    FD_LOG_CRIT(( "fd_vm_init() failed" ));
  }

  int res = fd_vm_validate( vm );
  fd_sbpf_syscalls_leave( syscalls );
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_DEBUG(( "fd_vm_validate() failed" ));
    cache_entry->failed_verification = 1;
    return -1;
  }

  /* FIXME: Super expensive memcpy. */
  fd_memcpy( fd_program_cache_get_calldests_shmem( cache_entry ), prog->calldests_shmem, fd_sbpf_calldests_footprint( prog->text_sz/8UL ) );

  cache_entry->entry_pc            = prog->entry_pc;
  cache_entry->text_off            = prog->text_off;
  cache_entry->text_cnt            = prog->text_cnt;
  cache_entry->text_sz             = prog->text_sz;
  cache_entry->rodata_sz           = prog->rodata_sz;
  cache_entry->failed_verification = 0;

  return 0;
}

/* Publishes an in-prepare funk record for a program that failed
   verification. Creates a default sBPF validated program with the
   `failed_verification` flag set to 1 and `last_slot_verified` set to
   the current slot. The passed-in funk record is expected to be in a
   prepare. */
static void
fd_program_cache_publish_failed_verification_rec( fd_funk_t *             funk,
                                                  fd_funk_rec_prepare_t * prepare,
                                                  fd_funk_rec_t *         rec,
                                                  ulong                   current_slot ) {
  /* Truncate the record to have a minimal footprint */
  ulong record_sz = fd_program_cache_failed_verification_entry_footprint();
  void * data = fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), 0UL, record_sz, NULL );
  if( FD_UNLIKELY( data==NULL ) ) {
    FD_LOG_ERR(( "fd_funk_val_truncate() failed to truncate record to size %lu", record_sz ));
  }

  fd_program_cache_entry_set_failed_verification( data, current_slot );
  fd_funk_rec_publish( funk, prepare );
}

/* Validates an SBPF program and adds it to the program cache.
   Reasons for verification failure include:
   - The ELF info cannot be parsed or validated from the programdata.
   - The sBPF program fails to be validated.

   The program will still be added to the cache even if verifications
   fail. This is to prevent a DOS vector where an attacker could spam
   invocations to programs that failed verification. */
static void
fd_program_cache_create_cache_entry( fd_bank_t *               bank,
                                     fd_funk_t *               funk,
                                     fd_funk_txn_xid_t const * xid,
                                     fd_txn_account_t const *  program_acc,
                                     fd_spad_t *               runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    ulong current_slot = fd_bank_slot_get( bank );

    /* Prepare the funk record for the program cache. */
    fd_pubkey_t const * program_pubkey = program_acc->pubkey;
    fd_funk_rec_key_t   id             = fd_program_cache_key( program_pubkey );

    /* Try to get the programdata for the account. If it doesn't exist,
       simply return without publishing anything. The program could have
       been closed, but we do not want to touch the cache in this case. */
    ulong         program_data_len = 0UL;
    uchar const * program_data     = fd_program_cache_get_account_programdata( funk, xid, program_acc, &program_data_len );

    /* This prepare should never fail. */
    int funk_err = FD_FUNK_SUCCESS;
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, xid, &id, prepare, &funk_err );
    if( rec == NULL || funk_err != FD_FUNK_SUCCESS ) {
      FD_LOG_CRIT(( "fd_funk_rec_prepare() failed: %i-%s", funk_err, fd_funk_strerror( funk_err ) ));
    }

    /* In Agave's load_program_with_pubkey(), if program data cannot be
       obtained, a tombstone cache entry of type Closed or
       FailedVerification is created.  For correctness, we could just
       not insert a cache entry when there is no valid program data.
       Nonetheless, for purely conformance on instruction error log
       messages reasons, specifically "Program is not deployed" vs
       "Program is not cached", we would like to have a cache entry
       precisely when Agave does, such that we match Agave exactly on
       this error log.  So, we insert a cache entry here. */
    if( FD_UNLIKELY( program_data==NULL ) ) {
      fd_program_cache_publish_failed_verification_rec( funk, prepare, rec, current_slot );
      return;
    }

    fd_sbpf_elf_info_t elf_info = {0};
    if( FD_UNLIKELY( fd_program_cache_parse_elf_info( bank, &elf_info, program_data, program_data_len ) ) ) {
      fd_program_cache_publish_failed_verification_rec( funk, prepare, rec, current_slot );
      return;
    }

    ulong val_sz = fd_program_cache_entry_footprint( &elf_info );
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

    /* Note that the cache entry points to the funk record data
       and writes into the record directly to avoid an expensive memcpy.
       Since this record is fresh, we should set the last slot modified
       to 0. */
    fd_program_cache_entry_t * cache_entry = fd_program_cache_entry_new( val, &elf_info, 0UL, current_slot );
    int res = fd_program_cache_validate_sbpf_program( bank, &elf_info, program_data, program_data_len, runtime_spad, cache_entry );
    if( FD_UNLIKELY( res ) ) {
      fd_program_cache_publish_failed_verification_rec( funk, prepare, rec, current_slot );
      return;
    }

    fd_funk_rec_publish( funk, prepare );
  } FD_SPAD_FRAME_END;
}

int
fd_program_cache_load_entry( fd_funk_t const *                 funk,
                             fd_funk_txn_xid_t const *         xid,
                             fd_pubkey_t const *               program_pubkey,
                             fd_program_cache_entry_t const ** cache_entry ) {
  fd_funk_rec_key_t id = fd_program_cache_key( program_pubkey );

  for(;;) {
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global(funk, xid, &id, NULL, query);

    if( FD_UNLIKELY( !rec ) ) {
      /* If rec is NULL, we shouldn't inspect query below because it
         would contain uninitialized fields. */
      return -1;
    }

    if( FD_UNLIKELY( !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
      if( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) {
        return -1;
      } else {
        continue;
      }
    }

    void const * data = fd_funk_val_const( rec, fd_funk_wksp(funk) );

    *cache_entry = (fd_program_cache_entry_t const *)data;

    /* This test is actually too early. It should happen after the
       data is actually consumed.

       TODO: this is likely fine because nothing else is modifying the
       program cache records at the same time. */
    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      if( FD_UNLIKELY( (*cache_entry)->magic != FD_PROGRAM_CACHE_ENTRY_MAGIC ) ) FD_LOG_ERR(( "invalid magic" ));
      return 0;
    }

    /* Try again */
  }
}

void
fd_program_cache_update_program( fd_bank_t *               bank,
                                 fd_funk_t *               funk,
                                 fd_funk_txn_xid_t const * xid,
                                 fd_pubkey_t const *       program_key,
                                 fd_spad_t *               runtime_spad ) {
FD_SPAD_FRAME_BEGIN( runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( exec_rec );
  fd_funk_rec_key_t id = fd_program_cache_key( program_key );

  /* No need to touch the cache if the account no longer exists. */
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( exec_rec,
                                                           program_key,
                                                           funk,
                                                           xid ) ) ) {
    return;
  }

  /* The account owner must be a BPF loader to even be considered. */
  if( FD_UNLIKELY( !fd_executor_pubkey_is_bpf_loader( fd_txn_account_get_owner( exec_rec ) ) ) ) {
    return;
  }

  /* If the program is not present in the cache yet, then we should run
     verifications and add it to the cache.
     `fd_program_cache_create_cache_entry()` will insert the program
     into the cache and update the entry's flags accordingly if it fails
     verification. */
  fd_program_cache_entry_t const * existing_entry = NULL;
  int err = fd_program_cache_load_entry( funk, xid, program_key, &existing_entry );
  if( FD_UNLIKELY( err ) ) {
    fd_program_cache_create_cache_entry( bank, funk, xid, exec_rec, runtime_spad );
    return;
  }

  /* At this point, the program exists in the cache but we may need to
     reverify it and update the program cache. A program does NOT
     require reverification if both of the following conditions are met:
     - The program was already reverified in the current epoch
     - EITHER of the following are met:
       - The program was not modified in a recent slot (i.e. the program
         was already reverified since the last time it was modified)
       - The program was already verified in the current slot

      We must reverify the program for the current epoch if it has not
      been reverified yet. Additionally, we cannot break the invariant
      that a program cache entry will get reverified more than once
      per slot, otherwise the replay and exec tiles may race. */
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong current_slot                         = fd_bank_slot_get( bank );
  ulong current_epoch                        = fd_bank_epoch_get( bank );
  ulong last_epoch_verified                  = fd_slot_to_epoch( epoch_schedule, existing_entry->last_slot_verified, NULL );
  ulong last_slot_modified                   = existing_entry->last_slot_modified;
  if( FD_LIKELY( last_epoch_verified==current_epoch &&
                 ( last_slot_modified<existing_entry->last_slot_verified ||
                   current_slot==existing_entry->last_slot_verified ) ) ) {
    return;
  }

  /* Get the program data from the account. If the programdata does not
     exist, there is no need to touch the cache - if someone tries to
     invoke this program, account loading checks will fail. */
  ulong         program_data_len = 0UL;
  uchar const * program_data     = fd_program_cache_get_account_programdata( funk,
                                                                             xid,
                                                                             exec_rec,
                                                                             &program_data_len );
  if( FD_UNLIKELY( program_data==NULL ) ) {
    /* Unlike in fd_program_cache_create_cache_entry(), where we need to
       insert an entry into the cache when we cannot obtain valid
       program data, here we could simply return because we know, at
       this point, that the program is already in the cache.  So we
       don't need to do anything extra for matching Agave on cache entry
       presence. */
    return;
  }

  /* From here on out, we need to reverify the program. */

  /* Parse out the ELF info so we can determine the record footprint.
     If the parsing fails, then we need to make sure to later publish
     a failed verification record. */
  uchar              failed_elf_parsing = 0;
  ulong              record_sz          = 0UL;
  fd_sbpf_elf_info_t elf_info           = {0};
  if( FD_UNLIKELY( fd_program_cache_parse_elf_info( bank, &elf_info, program_data, program_data_len ) ) ) {
    failed_elf_parsing = 1;
    record_sz          = fd_program_cache_failed_verification_entry_footprint();
  } else {
    failed_elf_parsing = 0;
    record_sz = fd_program_cache_entry_footprint( &elf_info );
  }

  /* Resize the record to the new footprint if needed */
  uchar data[ record_sz ];
  fd_program_cache_entry_t * writable_entry = fd_type_pun( data );

  /* If the ELF header parsing failed, publish a failed verification
     record. */
  if( FD_UNLIKELY( failed_elf_parsing ) ) {
    fd_program_cache_entry_set_failed_verification( writable_entry, current_slot );
  } else {
    /* Validate the sBPF program. This will set the program's flags
       accordingly. We publish the funk record regardless of the return
       code. */
    writable_entry = fd_program_cache_entry_new( data, &elf_info, last_slot_modified, current_slot );
    int res = fd_program_cache_validate_sbpf_program( bank, &elf_info, program_data, program_data_len, runtime_spad, writable_entry );
    if( FD_UNLIKELY( res ) ) {
      FD_LOG_DEBUG(( "fd_program_cache_validate_sbpf_program() failed" ));
    }
  }

  fd_funk_rec_insert_para( funk, xid, &id, alignof(fd_program_cache_entry_t), record_sz, writable_entry );

} FD_SPAD_FRAME_END;
}

void
fd_program_cache_queue_program_for_reverification( fd_funk_t *               funk,
                                                   fd_funk_txn_xid_t const * xid,
                                                   fd_pubkey_t const *       program_key,
                                                   ulong                     current_slot ) {

  /* We want to access the program cache entry for this pubkey and
     queue it for reverification. If it exists, clone it down to the
     current funk txn and update the entry's `last_slot_modified`
     field.

     This read is thread-safe because if you have transaction A that
     modifies the program and transaction B that references the program,
     the dispatcher will not attempt to execute transaction B until
     transaction A is finalized. */
  fd_program_cache_entry_t const * existing_entry = NULL;
  int err = fd_program_cache_load_entry( funk, xid, program_key, &existing_entry );
  if( FD_UNLIKELY( err ) ) {
    return;
  }

  /* Ensure the record is in the current funk transaction */
  fd_funk_rec_key_t id = fd_program_cache_key( program_key );
  fd_program_cache_entry_t entry = *existing_entry;
  entry.last_slot_modified = current_slot;
  fd_funk_rec_insert_para( funk, xid, &id, alignof(fd_program_cache_entry_t), sizeof(fd_program_cache_entry_t), &entry );
}

int
fd_funk_rec_insert_para( fd_funk_t *               funk,
                         fd_funk_txn_xid_t const * xid,
                         fd_funk_rec_key_t const * key,
                         ulong                     val_align,
                         ulong                     val_sz,
                         void *                    val ) {
  if( FD_UNLIKELY( !funk           ) ) FD_LOG_ERR(( "NULL funk" ));
  if( FD_UNLIKELY( !xid            ) ) FD_LOG_ERR(( "NULL xid"  ));
  if( FD_UNLIKELY( !key            ) ) FD_LOG_ERR(( "NULL key"  ));
  if( FD_UNLIKELY( !val && val_sz  ) ) FD_LOG_ERR(( "NULL val"  ));

  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );

  for(;;) {
    /* See if the record already exists. */
    fd_funk_rec_query_t query[1];
    int err = fd_funk_rec_map_query_try( funk->rec_map, pair, NULL, query, 0 );
    if( err == FD_MAP_SUCCESS ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_query_ele( query );
      /* Set the value of the record */
      if( !fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), val_align, val_sz, &err ) ) {
        FD_LOG_ERR(( "fd_funk_val_truncate() failed (out of memory?)" ));
        return err;
      }
      memcpy( fd_funk_val( rec, fd_funk_wksp( funk ) ), val, val_sz );
      return FD_FUNK_SUCCESS;
    }

    /* The record doesn't exist. Create it. */
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, xid, key, prepare, &err );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_CRIT(( "fd_funk_rec_prepare returned err=%d", err ));
      return err;
    }
    /* Set the value of the record */
    if( !fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), val_align, val_sz, &err ) ) {
      FD_LOG_ERR(( "fd_funk_val_truncate() failed (out of memory?)" ));
      return err;
    }
    memcpy( fd_funk_val( rec, fd_funk_wksp( funk ) ), val, val_sz );
    fd_funk_rec_publish( funk, prepare );
    return FD_FUNK_SUCCESS;
  }
}
