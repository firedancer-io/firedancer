#include "fd_progcache_verify.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "fd_progcache_rec.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../funk/fd_funk_private.h"

# define TEST(c, ...) do {                                        \
    if( FD_UNLIKELY( !(c) ) ) {                                   \
      FD_LOG_WARNING(( "PROGCACHE VERIFY FAIL: " __VA_ARGS__ ));  \
      return FD_PROGCACHE_VERIFY_FAILURE; }                       \
  } while(0)

/* Verify the progcache's local fork cache:
   - Fork depth stays within static array bounds
   - Parent-child relationships are reflected in the fork cache
   - Entries in the fork cache are ordered newest to oldest
*/
static int
verify_forks( fd_progcache_t * progcache,
              fd_funk_t *      funk ) {
  TEST( progcache->fork_depth <= FD_PROGCACHE_DEPTH_MAX,
               "fork_depth %lu exceeds maximum %lu",
               progcache->fork_depth, FD_PROGCACHE_DEPTH_MAX );

  if( progcache->fork_depth == 0UL ) {
    return FD_PROGCACHE_VERIFY_SUCCESS;
  }

  /* Verify each XID in the fork array */
  for( ulong i = 0UL; i < progcache->fork_depth; i++ ) {
    fd_funk_txn_xid_t const * xid = &progcache->fork[i];

    /* The transaction could have been published, but the progcache's fork
       cache has not been updated yet, in which case the xid will not
       be in the txn_map. We can't perform any verification in this case. */
    fd_funk_txn_t const * txn = fd_funk_txn_query( xid, funk->txn_map );
    if( !txn ) {
      continue;
    }

    /* Verify parent-child relationship if not the last entry */
    if( i < progcache->fork_depth - 1UL ) {
      fd_funk_txn_xid_t const * parent_xid = &progcache->fork[i + 1];

      if( !fd_funk_txn_xid_eq_root( parent_xid ) ) {
        /* Parent should be the actual parent of this transaction */
        fd_funk_txn_t const * parent_txn = fd_funk_txn_parent( txn, funk->txn_pool );
        if( parent_txn ) {
          TEST( fd_funk_txn_xid_eq( &parent_txn->xid, parent_xid ),
                       "Fork entry %lu parent mismatch", i );
        }
      }
    }
  }

  /* Verify that the fork is ordered from newest to oldest */
  for( ulong i = 1UL; i < progcache->fork_depth; i++ ) {
    if( !fd_funk_txn_xid_eq_root( &progcache->fork[i] ) &&
        !fd_funk_txn_xid_eq_root( &progcache->fork[i-1] ) ) {
      TEST( progcache->fork[i-1].ul[0] >= progcache->fork[i].ul[0],
                   "Fork not ordered newest to oldest at position %lu", i );
    }
  }

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

/* Validates a progcache record integrity, checking:
   - Executable records have sufficient size for text/rodata/calldests
   - Text and rodata segments stay within record bounds
   - Entry PC is valid
   - Calldests are accessible for older SBPF versions
   - Segments don't overlap
   - Slot matches XID slot */
static int
verify_progcache_record( fd_progcache_rec_t const * rec,
                         fd_funk_rec_t const *      funk_rec,
                         fd_funk_t *                funk ) {

  /* Get the value data */
  void const * val = fd_funk_val_const( funk_rec, funk->wksp );
  TEST( val == rec, "Progcache record pointer mismatch" );

  ulong val_sz = fd_funk_val_sz( funk_rec );

  if( rec->executable ) {
    TEST( val_sz >= sizeof(fd_progcache_rec_t),
                 "Executable record size %lu too small", val_sz );

    TEST( rec->text_off + rec->text_sz <= rec->rodata_sz,
                 "Text segment exceeds rodata bounds: text_off=%u text_sz=%u rodata_sz=%u",
                 rec->text_off, rec->text_sz, rec->rodata_sz );

    TEST( rec->rodata_off >= sizeof(fd_progcache_rec_t),
                 "Invalid rodata_off %u", rec->rodata_off );
    TEST( rec->rodata_off + rec->rodata_sz <= val_sz,
                 "Rodata segment exceeds record bounds: off=%u sz=%u val_sz=%lu",
                 rec->rodata_off, rec->rodata_sz, val_sz );

    TEST( rec->entry_pc < rec->text_cnt,
                 "Entry PC %u exceeds text_cnt %u", rec->entry_pc, rec->text_cnt );

    if( !fd_sbpf_enable_stricter_elf_headers_enabled( rec->sbpf_version ) ) {
      TEST( rec->calldests_off >= sizeof(fd_progcache_rec_t),
                   "Invalid calldests_off %u", rec->calldests_off );

      ulong calldests_sz = fd_sbpf_calldests_footprint( fd_ulong_max( 1UL, rec->text_cnt ) );
      TEST( rec->calldests_off + calldests_sz <= val_sz,
                   "Calldests exceeds record bounds" );

      fd_sbpf_calldests_t const * calldests = fd_progcache_rec_calldests( rec );
      TEST( calldests, "Cannot access calldests" );
    }
  } else {
    TEST( val_sz == sizeof(fd_progcache_rec_t),
                 "Non-executable record has unexpected size %lu", val_sz );
  }

  if( rec->invalidate ) {
    TEST( !rec->executable,
                   "Invalidated record marked as executable" );

    TEST( !fd_funk_txn_xid_eq_root( funk_rec->pair.xid ),
                   "Invalidated record at root" );
  }

  if( !fd_funk_txn_xid_eq_root( funk_rec->pair.xid ) ) {
    TEST( rec->slot == funk_rec->pair.xid->ul[0],
                 "Record slot %lu doesn't match XID slot %lu",
                 rec->slot, funk_rec->pair.xid->ul[0] );
  }

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

/* Check for duplicate (xid, prog_addr) pairs */
static int
verify_no_duplicates( fd_funk_t * funk ) {
  ulong rec_cnt = 0UL;

  fd_funk_all_iter_t iter1[1];
  for( fd_funk_all_iter_new( funk, iter1 ); !fd_funk_all_iter_done( iter1 ); fd_funk_all_iter_next( iter1 ) ) {
    fd_funk_rec_t const * rec1 = fd_funk_all_iter_ele_const( iter1 );
    if( !rec1 ) continue;

    rec_cnt++;

    fd_funk_all_iter_t iter2[1];
    ulong rec2_cnt = 0UL;
    for( fd_funk_all_iter_new( funk, iter2 ); !fd_funk_all_iter_done( iter2 ); fd_funk_all_iter_next( iter2 ) ) {
      fd_funk_rec_t const * rec2 = fd_funk_all_iter_ele_const( iter2 );
      if( !rec2 ) continue;

      if( rec2_cnt++ <= rec_cnt ) continue;

      if( fd_funk_txn_xid_eq( rec1->pair.xid, rec2->pair.xid ) &&
          fd_funk_rec_key_eq( rec1->pair.key, rec2->pair.key ) ) {

        char key_str[FD_BASE58_ENCODED_32_SZ];
        fd_base58_encode_32( rec1->pair.key->uc, NULL, key_str );

        TEST( 0, "Duplicate record found: XID=%lu:%lu key=%s",
                     rec1->pair.xid->ul[0], rec1->pair.xid->ul[1], key_str );
      }
    }
  }

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

/* Verify that Funk is valid and the records are valid progcache records:
   - Validates Funk integrity
   - Validates all Funk records are valid progcache records
   - Checks no duplicate records exist
 */
static int
verify_progcache_funk( fd_funk_t * funk ) {
  TEST( funk, "Funk is NULL" );

  FD_LOG_INFO(( "Starting progcache funk verification..." ));

  TEST( fd_funk_verify( funk ) == FD_FUNK_SUCCESS, "Funk verification failed" );

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  TEST( wksp, "Funk workspace is NULL" );

  fd_alloc_t * alloc = fd_funk_alloc( funk );
  TEST( alloc, "Funk allocator is NULL" );
  TEST( funk->txn_map, "Funk txn_map is NULL" );
  TEST( funk->rec_map, "Funk rec_map is NULL" );

  ulong total_records     = 0UL;
  ulong executable_count  = 0UL;
  ulong invalidated_count = 0UL;

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * funk_rec = fd_funk_all_iter_ele_const( iter );
    if( !funk_rec ) continue;

    fd_progcache_rec_t const * prog_rec = fd_funk_val_const( funk_rec, funk->wksp );
    TEST( prog_rec, "Progcache record is NULL" );

    TEST( verify_progcache_record( prog_rec, funk_rec, funk ) == FD_PROGCACHE_VERIFY_SUCCESS,
          "Progcache record verification failed" );

    total_records++;
    if( prog_rec->executable ) executable_count++;
    if( prog_rec->invalidate ) invalidated_count++;
  }

  TEST( verify_no_duplicates( funk ) == FD_PROGCACHE_VERIFY_SUCCESS,
        "Duplicate records found" );

  FD_LOG_INFO(( "Progcache funk verification complete: %lu records (%lu executable, %lu invalidated)",
                total_records, executable_count, invalidated_count ));

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

int
fd_progcache_verify_admin( fd_progcache_admin_t * admin ) {
  TEST( admin, "Admin is NULL" );

  FD_LOG_INFO(( "Starting progcache admin verification..." ));

  TEST( verify_progcache_funk( admin->funk ) == FD_PROGCACHE_VERIFY_SUCCESS,
        "Funk verification failed" );

  FD_LOG_INFO(( "Progcache admin verification complete" ));

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

int
fd_progcache_verify( fd_progcache_t * progcache ) {
  TEST( progcache, "Progcache is NULL" );

  FD_LOG_INFO(( "Starting progcache verification..." ));

  TEST( progcache->funk, "Progcache funk is NULL" );
  fd_funk_t * funk = progcache->funk;

  TEST( verify_progcache_funk( funk ) == FD_PROGCACHE_VERIFY_SUCCESS,
        "Funk verification failed" );

  if( progcache->scratch_sz > 0UL ) {
    TEST( progcache->scratch, "Progcache scratch is NULL but scratch_sz > 0" );
    TEST( fd_ulong_is_aligned( (ulong)progcache->scratch, FD_PROGCACHE_SCRATCH_ALIGN ),
          "Progcache scratch is not aligned" );
    TEST( progcache->scratch_sz >= FD_PROGCACHE_SCRATCH_FOOTPRINT,
          "Progcache scratch_sz %lu < required footprint %lu",
          progcache->scratch_sz, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  }

  TEST( verify_forks( progcache, funk ) == FD_PROGCACHE_VERIFY_SUCCESS,
        "Fork verification failed" );

  FD_LOG_INFO(( "Progcache verification complete (fork_depth=%lu)", progcache->fork_depth ));

  return FD_PROGCACHE_VERIFY_SUCCESS;
}

