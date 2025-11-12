/* fd_progcache_verify.c - Comprehensive integrity check for program cache

   This file implements extensive verification of program cache invariants
   including funk consistency, fork management, record structure validation,
   deduplication checks, and visibility rules. */

#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "fd_progcache_rec.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../funk/fd_funk_private.h"

/* Helper macro for verification tests with detailed error messages */
#define VERIFY_TEST(c, ...) do {                                              \
    if( FD_UNLIKELY( !(c) ) ) {                                               \
      FD_LOG_WARNING(( "PROGCACHE VERIFY FAIL: " __VA_ARGS__ ));              \
      FD_LOG_WARNING(( "  Condition failed: %s", #c ));                       \
      FD_LOG_WARNING(( "  Location: %s:%d", __FILE__, __LINE__ ));            \
      return FD_FUNK_ERR_INVAL;                                               \
    }                                                                          \
  } while(0)

/* Structure to track records during verification */
struct progcache_verify_rec {
  fd_funk_rec_t const * funk_rec;
  fd_progcache_rec_t const * prog_rec;
  fd_funk_txn_xid_t xid;
  fd_funk_rec_key_t key;
  ulong slot;
};

/* Verify fork management invariants */
static int
verify_fork_structure( fd_progcache_t * user_cache,
                      fd_funk_t *      funk,
                      ulong            epoch_slot0 ) {

  VERIFY_TEST( user_cache->fork_depth <= FD_PROGCACHE_DEPTH_MAX,
               "fork_depth %lu exceeds maximum %lu",
               user_cache->fork_depth, FD_PROGCACHE_DEPTH_MAX );

  if( user_cache->fork_depth == 0UL ) {
    return FD_FUNK_SUCCESS; /* Empty fork is valid */
  }

  /* Verify each XID in the fork array */
  for( ulong i = 0UL; i < user_cache->fork_depth; i++ ) {
    fd_funk_txn_xid_t const * xid = &user_cache->fork[i];

    /* Check if this is the root XID */
    if( fd_funk_txn_xid_eq_root( xid ) ) {
      /* Root should be the last entry if present */
      VERIFY_TEST( i == user_cache->fork_depth - 1UL,
                   "Root XID found at position %lu but fork_depth is %lu",
                   i, user_cache->fork_depth );
      continue;
    }

    /* Non-root XIDs must exist as transactions */
    fd_funk_txn_t const * txn = fd_funk_txn_query( xid, funk->txn_map );
    VERIFY_TEST( txn, "Fork entry %lu (XID %lu:%lu) not found in funk txn map",
                 i, xid->ul[0], xid->ul[1] );

    /* Verify slot is not before epoch start (unless it's the last entry) */
    if( i < user_cache->fork_depth - 1UL ) {
      VERIFY_TEST( xid->ul[0] >= epoch_slot0,
                   "Fork entry %lu slot %lu predates epoch_slot0 %lu",
                   i, xid->ul[0], epoch_slot0 );
    }

    /* Verify parent-child relationship if not the last entry */
    if( i < user_cache->fork_depth - 1UL ) {
      fd_funk_txn_xid_t const * parent_xid = &user_cache->fork[i + 1];

      if( !fd_funk_txn_xid_eq_root( parent_xid ) ) {
        /* Parent should be the actual parent of this transaction */
        fd_funk_txn_t const * parent_txn = fd_funk_txn_parent( txn, funk->txn_pool );
        if( parent_txn ) {
          VERIFY_TEST( fd_funk_txn_xid_eq( &parent_txn->xid, parent_xid ),
                       "Fork entry %lu parent mismatch", i );
        }
      }
    }
  }

  /* Verify ordering from newest to oldest */
  for( ulong i = 1UL; i < user_cache->fork_depth; i++ ) {
    if( !fd_funk_txn_xid_eq_root( &user_cache->fork[i] ) &&
        !fd_funk_txn_xid_eq_root( &user_cache->fork[i-1] ) ) {
      /* Skip root comparisons, but otherwise slots should be non-increasing */
      VERIFY_TEST( user_cache->fork[i-1].ul[0] >= user_cache->fork[i].ul[0],
                   "Fork not ordered newest to oldest at position %lu", i );
    }
  }

  return FD_FUNK_SUCCESS;
}

/* Verify a single progcache record structure */
static int
verify_record_structure( fd_progcache_rec_t const * rec,
                        fd_funk_rec_t const *       funk_rec,
                        fd_funk_t *                 funk ) {

  /* Get the value data */
  void const * val = fd_funk_val_const( funk_rec, funk->wksp );
  VERIFY_TEST( val == rec, "Progcache record pointer mismatch" );

  ulong val_sz = fd_funk_val_sz( funk_rec );

  if( rec->executable ) {
    /* Executable record invariants */
    VERIFY_TEST( val_sz >= sizeof(fd_progcache_rec_t),
                 "Executable record size %lu too small", val_sz );

    /* Verify text segment */
    VERIFY_TEST( rec->text_off >= sizeof(fd_progcache_rec_t),
                 "Invalid text_off %u", rec->text_off );
    VERIFY_TEST( rec->text_off + rec->text_sz <= val_sz,
                 "Text segment exceeds record bounds: off=%u sz=%u val_sz=%lu",
                 rec->text_off, rec->text_sz, val_sz );

    /* Verify rodata segment */
    VERIFY_TEST( rec->rodata_off >= sizeof(fd_progcache_rec_t),
                 "Invalid rodata_off %u", rec->rodata_off );
    VERIFY_TEST( rec->rodata_off + rec->rodata_sz <= val_sz,
                 "Rodata segment exceeds record bounds: off=%u sz=%u val_sz=%lu",
                 rec->rodata_off, rec->rodata_sz, val_sz );

    /* Verify entry point */
    VERIFY_TEST( rec->entry_pc < rec->text_cnt,
                 "Entry PC %u exceeds text_cnt %u", rec->entry_pc, rec->text_cnt );

    /* Verify calldests for older SBPF versions */
    if( !fd_sbpf_enable_stricter_elf_headers_enabled( rec->sbpf_version ) ) {
      VERIFY_TEST( rec->calldests_off >= sizeof(fd_progcache_rec_t),
                   "Invalid calldests_off %u", rec->calldests_off );

      ulong calldests_sz = fd_sbpf_calldests_footprint( fd_ulong_max( 1UL, rec->text_cnt ) );
      VERIFY_TEST( rec->calldests_off + calldests_sz <= val_sz,
                   "Calldests exceeds record bounds" );

      /* Verify calldests can be accessed */
      fd_sbpf_calldests_t const * calldests = fd_progcache_rec_calldests( rec );
      VERIFY_TEST( calldests, "Cannot access calldests" );
    }

    /* Verify segments don't overlap */
    if( rec->text_sz > 0 && rec->rodata_sz > 0 ) {
      ulong text_end = rec->text_off + rec->text_sz;
      ulong rodata_start = rec->rodata_off;
      VERIFY_TEST( text_end <= rodata_start || rec->rodata_off + rec->rodata_sz <= rec->text_off,
                   "Text and rodata segments overlap" );
    }

  } else {
    /* Non-executable record invariants */
    VERIFY_TEST( val_sz == sizeof(fd_progcache_rec_t),
                 "Non-executable record has unexpected size %lu", val_sz );
  }

  /* Verify slot consistency */
  if( !fd_funk_txn_xid_eq_root( funk_rec->pair.xid ) ) {
    VERIFY_TEST( rec->slot == funk_rec->pair.xid->ul[0],
                 "Record slot %lu doesn't match XID slot %lu",
                 rec->slot, funk_rec->pair.xid->ul[0] );
  }

  return FD_FUNK_SUCCESS;
}

/* Check for duplicate (xid, prog_addr) pairs */
static int
verify_no_duplicates( fd_funk_t * funk ) {

  /* Use a simple but thorough approach: iterate all records and check for duplicates
     This is O(n^2) but only runs during verification */

  /* Count records for progress tracking */
  ulong rec_cnt = 0UL;

  /* Iterate through all records */
  fd_funk_all_iter_t iter1[1];
  for( fd_funk_all_iter_new( funk, iter1 ); !fd_funk_all_iter_done( iter1 ); fd_funk_all_iter_next( iter1 ) ) {
    fd_funk_rec_t const * rec1 = fd_funk_all_iter_ele_const( iter1 );
    if( !rec1 ) continue;

    rec_cnt++;

    /* Check for duplicates with the same key and xid */
    fd_funk_all_iter_t iter2[1];
    ulong rec2_cnt = 0UL;
    for( fd_funk_all_iter_new( funk, iter2 ); !fd_funk_all_iter_done( iter2 ); fd_funk_all_iter_next( iter2 ) ) {
      fd_funk_rec_t const * rec2 = fd_funk_all_iter_ele_const( iter2 );
      if( !rec2 ) continue;

      /* Skip until we pass rec1 (to avoid duplicate comparisons) */
      if( rec2_cnt++ <= rec_cnt ) continue;

      /* Check if same XID and same key */
      if( fd_funk_txn_xid_eq( rec1->pair.xid, rec2->pair.xid ) &&
          fd_funk_rec_key_eq( rec1->pair.key, rec2->pair.key ) ) {

        char key_str[FD_BASE58_ENCODED_32_SZ];
        fd_base58_encode_32( rec1->pair.key->uc, NULL, key_str );

        VERIFY_TEST( 0, "Duplicate record found: XID=%lu:%lu key=%s",
                     rec1->pair.xid->ul[0], rec1->pair.xid->ul[1], key_str );
      }
    }
  }

  return FD_FUNK_SUCCESS;
}

/* Verify visibility and invalidation rules */
static int
verify_visibility_rules( fd_progcache_t * user_cache,
                        fd_funk_t *      funk,
                        ulong            epoch_slot0 ) {

  (void)user_cache;
  (void)epoch_slot0;

  /* Iterate through all records and check visibility rules */
  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * funk_rec = fd_funk_all_iter_ele_const( iter );
    if( !funk_rec ) continue;

    fd_progcache_rec_t const * prog_rec = fd_funk_val_const( funk_rec, funk->wksp );
    if( !prog_rec ) continue;

    /* Check invalidation flag consistency */
    if( prog_rec->invalidate ) {
      /* Invalidated records should only be visible in their specific slot */
      VERIFY_TEST( !prog_rec->executable,
                   "Invalidated record marked as executable" );

      /* Invalidated entries should not be at root */
      VERIFY_TEST( !fd_funk_txn_xid_eq_root( funk_rec->pair.xid ),
                   "Invalidated record at root" );
    }

    /* Verify slot is not in the future */
    if( prog_rec->slot != ULONG_MAX ) {
      /* We can't check against current slot without that info,
         but we can check basic sanity */
      VERIFY_TEST( prog_rec->slot < (1UL << 48),
                   "Record slot %lu appears invalid", prog_rec->slot );
    }

    /* Check records from old epochs are properly handled */
    if( prog_rec->slot < epoch_slot0 && prog_rec->slot != ULONG_MAX ) {
      /* Old epoch records should generally not be visible in queries,
         but they may still exist in funk */
      FD_LOG_DEBUG(( "Record from old epoch found: slot=%lu epoch_slot0=%lu",
                     prog_rec->slot, epoch_slot0 ));
    }
  }

  return FD_FUNK_SUCCESS;
}

/* Main comprehensive verification function */
int
fd_progcache_verify_comprehensive( fd_progcache_admin_t * admin_cache,
                                   fd_progcache_t *       user_cache,
                                   ulong                  epoch_slot0 ) {

  FD_LOG_NOTICE(( "Starting comprehensive progcache verification..." ));

  /* Step 1: Verify the underlying funk instance */
  FD_LOG_INFO(( "Verifying funk instance..." ));
  VERIFY_TEST( fd_funk_verify( admin_cache->funk ) == FD_FUNK_SUCCESS,
               "Funk verification failed" );

  fd_funk_t * funk = admin_cache->funk;

  /* Verify funk workspace accessibility */
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  VERIFY_TEST( wksp, "Funk workspace is NULL" );

  /* Step 2: Verify fork structure if user cache provided */
  if( user_cache ) {
    FD_LOG_INFO(( "Verifying fork structure..." ));
    VERIFY_TEST( user_cache->funk == admin_cache->funk,
                 "User cache and admin cache funk mismatch" );

    int fork_err = verify_fork_structure( user_cache, funk, epoch_slot0 );
    VERIFY_TEST( fork_err == FD_FUNK_SUCCESS,
                 "Fork structure verification failed" );

    /* Verify scratch buffer */
    if( user_cache->scratch_sz > 0UL ) {
      VERIFY_TEST( user_cache->scratch,
                   "Non-zero scratch_sz but NULL scratch" );
      VERIFY_TEST( fd_ulong_is_aligned( (ulong)user_cache->scratch, FD_PROGCACHE_SCRATCH_ALIGN ),
                   "Scratch buffer misaligned" );
    }
  }

  /* Step 3: Verify all progcache records */
  FD_LOG_INFO(( "Verifying progcache records..." ));
  ulong total_records = 0UL;
  ulong executable_records = 0UL;
  ulong invalidated_records = 0UL;

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * funk_rec = fd_funk_all_iter_ele_const( iter );
    if( !funk_rec ) continue;

    /* Get the progcache record */
    fd_progcache_rec_t const * prog_rec = fd_funk_val_const( funk_rec, funk->wksp );
    if( !prog_rec ) {
      /* This might be a non-progcache funk record, skip it */
      continue;
    }

    /* Verify record structure */
    int rec_err = verify_record_structure( prog_rec, funk_rec, funk );
    VERIFY_TEST( rec_err == FD_FUNK_SUCCESS,
                 "Record structure verification failed for record at %p",
                 (void*)prog_rec );

    total_records++;
    if( prog_rec->executable ) executable_records++;
    if( prog_rec->invalidate ) invalidated_records++;
  }

  FD_LOG_INFO(( "Found %lu progcache records (%lu executable, %lu invalidated)",
                total_records, executable_records, invalidated_records ));

  /* Step 4: Check for duplicates */
  FD_LOG_INFO(( "Checking for duplicate records..." ));
  int dup_err = verify_no_duplicates( funk );
  VERIFY_TEST( dup_err == FD_FUNK_SUCCESS,
               "Duplicate record check failed" );

  /* Step 5: Verify visibility rules */
  if( user_cache ) {
    FD_LOG_INFO(( "Verifying visibility rules..." ));
    int vis_err = verify_visibility_rules( user_cache, funk, epoch_slot0 );
    VERIFY_TEST( vis_err == FD_FUNK_SUCCESS,
                 "Visibility rules verification failed" );
  }

  /* Step 6: Additional consistency checks */
  FD_LOG_INFO(( "Performing additional consistency checks..." ));

  /* Verify alloc is accessible and valid */
  fd_alloc_t * alloc = fd_funk_alloc( funk );
  VERIFY_TEST( alloc, "Funk alloc is NULL" );

  /* Check last publish */
  fd_funk_txn_xid_t const * last_publish = fd_funk_last_publish( funk );
  VERIFY_TEST( last_publish, "Last publish is NULL" );

  /* If metrics available, do sanity checks */
  if( user_cache && user_cache->metrics ) {
    fd_progcache_metrics_t * metrics = user_cache->metrics;

    /* Basic sanity checks on metrics */
    VERIFY_TEST( metrics->fill_cnt >= metrics->dup_insert_cnt,
                 "fill_cnt < dup_insert_cnt (%lu < %lu)",
                 metrics->fill_cnt, metrics->dup_insert_cnt );
  }

  FD_LOG_NOTICE(( "Progcache verification completed successfully" ));
  FD_LOG_NOTICE(( "  Total records: %lu", total_records ));
  FD_LOG_NOTICE(( "  Executable: %lu", executable_records ));
  FD_LOG_NOTICE(( "  Invalidated: %lu", invalidated_records ));

  return FD_FUNK_SUCCESS;
}

/* Enhanced version of existing fd_progcache_verify that includes comprehensive checks */
void
fd_progcache_verify_enhanced( fd_progcache_admin_t * cache ) {
  /* First run the basic funk verify */
  FD_TEST( fd_funk_verify( cache->funk ) == FD_FUNK_SUCCESS );

  /* Run comprehensive verification with reasonable defaults */
  int result = fd_progcache_verify_comprehensive( cache, NULL, 0UL );
  FD_TEST( result == FD_FUNK_SUCCESS );

  FD_LOG_WARNING(( "Enhanced progcache verify success" ));
}
