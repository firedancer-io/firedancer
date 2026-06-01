#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"
#include "fd_tower.h"
#include "fd_tower_serdes.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

static void
fuzz_vote_instruction( uchar const * data,
                       ulong         data_sz ) {

  /* Decode/encode round-trip for vote instruction data */

  fd_compact_tower_sync_serde_t serde[1];
  memset( serde, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err = fd_compact_tower_sync_de( serde, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return;
  }

  FD_FUZZ_MUST_BE_COVERED;

  uchar buf[1024];
  ulong out_sz = 0;

  int ser_err = fd_compact_tower_sync_ser( serde, buf, sizeof(buf), &out_sz );
  assert( !ser_err );

  FD_FUZZ_MUST_BE_COVERED;

  fd_compact_tower_sync_serde_t serde2[1];
  memset( serde2, 0, sizeof(fd_compact_tower_sync_serde_t) );

  int de_err2 = fd_compact_tower_sync_de( serde2, buf, out_sz );
  assert( !de_err2 );

  assert( serde->root         == serde2->root         );
  assert( serde->lockouts_cnt == serde2->lockouts_cnt );
  for( ushort i = 0; i < serde->lockouts_cnt; i++ ) {
    assert( serde->lockouts[i].offset             == serde2->lockouts[i].offset             );
    assert( serde->lockouts[i].confirmation_count == serde2->lockouts[i].confirmation_count );
  }
  assert( !memcmp( &serde->hash, &serde2->hash, sizeof(fd_hash_t) ) );
  assert( serde->timestamp_option == serde2->timestamp_option );
  if( serde->timestamp_option ) {
    assert( serde->timestamp == serde2->timestamp );
  }
  assert( !memcmp( &serde->block_id, &serde2->block_id, sizeof(fd_hash_t) ) );

  FD_FUZZ_MUST_BE_COVERED;
}

static void
fuzz_vote_state( uchar const * data,
                 ulong         data_sz ) {
  /* Test zero-copy vote state deserialization;
     differentially fuzz against the vote program's full decoder. */

  fd_vote_state_versioned_t vsv_[1];
  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_deserialize( vsv_, data, data_sz );
  fd_vote_acc_desc_t desc_[1];
  fd_vote_acc_desc_t * desc = fd_vote_acc_desc( desc_, data, data_sz );

  if( desc ) {
    /* Decoded invariants */
    assert( desc->kind>=FD_VOTE_ACC_V2 && desc->kind<=FD_VOTE_ACC_V4 );
    assert( desc->vote_cnt <= FD_TOWER_VOTE_MAX );
    assert( desc->vote_stride );
    ulong vote0 = (ulong)fd_vote_acc_desc_vote( desc, data, 0UL );
    ulong vote1 = vote0 + ( (ulong)desc->vote_cnt * (ulong)desc->vote_stride );
    assert( vote0>=(ulong)data && vote1<=(ulong)data+data_sz );
  }

  if( vsv ) {
    /* If the vote state is valid, peek must also support it
       (The opposite is not true, as peek does not do full validation) */
    if( vsv->kind!=fd_vote_state_versioned_enum_uninitialized ) {
      assert( desc );
    }

    /* Ensure content is the same */
    switch( vsv->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      assert( desc==NULL );
      break;
    case fd_vote_state_versioned_enum_v1_14_11: {
      assert( desc->root_slot ==
              ( vsv->v1_14_11.has_root_slot ? vsv->v1_14_11.root_slot : ULONG_MAX ) );
      assert( desc->vote_cnt == deq_fd_landed_vote_t_cnt( vsv->v1_14_11.votes ) );
      fd_vote_acc_vote_v2_t const * vote0 = fd_vote_acc_desc_vote( desc, data, 0UL );
      for( ulong i=0UL; i<(desc->vote_cnt); i++ ) {
        fd_landed_vote_t const * lv = deq_fd_landed_vote_t_peek_index_const( vsv->v1_14_11.votes, i );
        assert( vote0[ i ].slot == lv->lockout.slot );
        assert( vote0[ i ].conf == lv->lockout.confirmation_count );
      }
      break;
    }
    case fd_vote_state_versioned_enum_v3: {
      assert( desc->root_slot ==
              ( vsv->v3.has_root_slot ? vsv->v3.root_slot : ULONG_MAX ) );
      assert( desc->vote_cnt == deq_fd_landed_vote_t_cnt( vsv->v3.votes ) );
      fd_vote_acc_vote_t const * vote0 = fd_vote_acc_desc_vote( desc, data, 0UL );
      for( ulong i=0UL; i<(desc->vote_cnt); i++ ) {
        fd_landed_vote_t const * lv = deq_fd_landed_vote_t_peek_index_const( vsv->v3.votes, i );
        assert( vote0[ i ].latency == lv->latency );
        assert( vote0[ i ].slot == lv->lockout.slot );
        assert( vote0[ i ].conf == lv->lockout.confirmation_count );
      }
      break;
    }
    case fd_vote_state_versioned_enum_v4: {
      assert( desc->root_slot ==
              ( vsv->v4.has_root_slot ? vsv->v4.root_slot : ULONG_MAX ) );
      assert( desc->vote_cnt == deq_fd_landed_vote_t_cnt( vsv->v4.votes ) );
      fd_vote_acc_vote_t const * vote0 = fd_vote_acc_desc_vote( desc, data, 0UL );
      for( ulong i=0UL; i<(desc->vote_cnt); i++ ) {
        fd_landed_vote_t const * lv = deq_fd_landed_vote_t_peek_index_const( vsv->v4.votes, i );
        assert( vote0[ i ].latency == lv->latency );
        assert( vote0[ i ].slot == lv->lockout.slot );
        assert( vote0[ i ].conf == lv->lockout.confirmation_count );
      }
      break;
    }
    default:
      abort();
    }
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fuzz_vote_instruction( data, data_sz );
  fuzz_vote_state      ( data, data_sz );
  return 0;
}
