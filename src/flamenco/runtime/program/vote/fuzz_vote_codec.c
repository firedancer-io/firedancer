#include "fd_vote_codec.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  fd_log_level_logfile_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_vote_state_versioned_t vsv[1];
  if( fd_vote_state_versioned_deserialize( vsv, data, size ) ) {
    switch( vsv->kind ) {
    case fd_vote_state_versioned_enum_uninitialized:
      break;
    case fd_vote_state_versioned_enum_v1_14_11:
      assert( !fd_vote_authorized_voters_treap_verify( vsv->v1_14_11.authorized_voters.treap, vsv->v1_14_11.authorized_voters.pool ) );
      assert( deq_fd_landed_vote_t_cnt( vsv->v1_14_11.votes )<=MAX_LOCKOUT_HISTORY );
      assert( deq_fd_vote_epoch_credits_t_cnt( vsv->v1_14_11.epoch_credits )<=MAX_EPOCH_CREDITS_HISTORY );
      break;
    case fd_vote_state_versioned_enum_v3:
      assert( !fd_vote_authorized_voters_treap_verify( vsv->v3.authorized_voters.treap, vsv->v3.authorized_voters.pool ) );
      assert( deq_fd_landed_vote_t_cnt( vsv->v3.votes )<=MAX_LOCKOUT_HISTORY );
      assert( deq_fd_vote_epoch_credits_t_cnt( vsv->v3.epoch_credits )<=MAX_EPOCH_CREDITS_HISTORY );
      break;
    case fd_vote_state_versioned_enum_v4:
      assert( !fd_vote_authorized_voters_treap_verify( vsv->v4.authorized_voters.treap, vsv->v4.authorized_voters.pool ) );
      assert( deq_fd_landed_vote_t_cnt( vsv->v4.votes )<=MAX_LOCKOUT_HISTORY );
      assert( deq_fd_vote_epoch_credits_t_cnt( vsv->v4.epoch_credits )<=MAX_EPOCH_CREDITS_HISTORY );
      break;
    default:
      FD_LOG_CRIT(( "unsupported vote state version: %u", vsv->kind ));
    }
  }
  ulong cnt;
  fd_vote_epoch_credits_t const * ec = fd_vote_account_epoch_credits( data, size, &cnt );
  if( ec ) {
    assert( cnt<=MAX_EPOCH_CREDITS_HISTORY );
    ulong ptr0 = (ulong)ec;
    ulong ptr1 = (ulong)( ec + cnt );
    assert( ptr0<=ptr1 && ptr1<=(ulong)( data+size ) );
  }
  return 0;
}
