#include "fd_epoch.h"
#include <stdarg.h>

fd_epoch_t *
epoch( fd_wksp_t * wksp, ulong total_stake, ulong voter_cnt, ... ) {
  void * epoch_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_align(), fd_epoch_footprint( voter_cnt ), 1UL );
  FD_TEST( epoch_mem );
  fd_epoch_t * epoch = fd_epoch_join( fd_epoch_new( epoch_mem, voter_cnt ) );
  FD_TEST( epoch );

  va_list ap;
  va_start( ap, voter_cnt );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    fd_pubkey_t key = va_arg( ap, fd_pubkey_t );
    fd_voter_t * voter = fd_epoch_voters_insert( fd_epoch_voters( epoch ), key );
    voter->stake       = va_arg( ap, ulong );
    voter->replay_vote = FD_SLOT_NULL;
  }
  va_end( ap );

  epoch->total_stake = total_stake;
  return epoch;
}
