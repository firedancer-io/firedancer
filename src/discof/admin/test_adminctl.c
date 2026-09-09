#include "fd_adminctl.c"
#include "../../util/fd_util.h"

struct fixture {
  uchar before[ 64 ];
  fd_adminctl_t ctl;
  uchar after[ 64 ];
};

static void
init( struct fixture * f ) {
  fd_memset( f, 0xA5, sizeof(*f) );
  FD_TEST( fd_adminctl_join( fd_adminctl_new( &f->ctl ) )==&f->ctl );
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT; i++ ) {
    void * payload;
    ulong max;
    FD_TEST( fd_adminctl_reserve( &f->ctl, &payload, &max )==i );
    FD_TEST( max==FD_ADMINCTL_PAYLOAD_MAX );
    fd_memset( payload, (int)(i+1UL), max );
  }
}

static void
check_neighbors( struct fixture const * f,
                 struct fixture const * saved,
                 ulong                  idx ) {
  FD_TEST( !memcmp( f->before, saved->before, sizeof(f->before) ) );
  FD_TEST( !memcmp( f->after,  saved->after,  sizeof(f->after)  ) );
  FD_TEST( f->ctl.magic==saved->ctl.magic );
  FD_TEST( f->ctl.next_request_id==saved->ctl.next_request_id );
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT; i++ ) {
    if( i==idx ) continue;
    FD_TEST( !memcmp( &f->ctl.slots[i], &saved->ctl.slots[i], sizeof(fd_adminctl_slot_t) ) );
  }
}

static void
check_zero( void const * mem, ulong sz ) {
  uchar const * bytes = mem;
  for( ulong i=0UL; i<sz; i++ ) FD_TEST( !bytes[i] );
}

static void
test_request_lengths( void ) {
  ulong sizes[] = { 0UL, 1UL, 8UL, 255UL, 256UL, 257UL, 512UL, ULONG_MAX };
  for( ulong idx=0UL; idx<FD_ADMINCTL_SLOT_CNT; idx++ ) {
    for( ulong n=0UL; n<sizeof(sizes)/sizeof(sizes[0]); n++ ) {
      struct fixture f;
      init( &f );
      fd_adminctl_publish( &f.ctl, idx, FD_ADMINCTL_CMD_FAILOVER_STATUS, 8UL );
      /* Simulate a workspace writer, bypassing publish's size check. */
      f.ctl.slots[idx].payload_sz = sizes[n];
      f.ctl.poll_idx = idx;
      struct fixture saved = f;
      ulong got_idx = ULONG_MAX;
      ulong got_sz = ULONG_MAX;
      void * got = NULL;
      ulong cmd = fd_adminctl_poll( &f.ctl, &got_idx, &got, &got_sz );
      if( sizes[n]>FD_ADMINCTL_PAYLOAD_MAX ) {
        FD_TEST( cmd==FD_ADMINCTL_CMD_IDLE );
        FD_TEST( got_idx==ULONG_MAX && got_sz==ULONG_MAX && !got );
        FD_TEST( f.ctl.slots[idx].result==FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
      } else {
        FD_TEST( cmd==FD_ADMINCTL_CMD_FAILOVER_STATUS );
        FD_TEST( got_idx==idx && got_sz==sizes[n] && got==f.ctl.slots[idx].payload );
        FD_TEST( fd_adminctl_state( f.ctl.slots[idx].state_pid_seq )==FD_ADMINCTL_STATE_PROCESSING );
        fd_adminctl_complete( &f.ctl, idx, FD_ADMINCTL_RESULT_SUCCESS );
      }
      FD_TEST( fd_adminctl_state( f.ctl.slots[idx].state_pid_seq )==FD_ADMINCTL_STATE_DONE );
      FD_TEST( !f.ctl.slots[idx].payload_sz );
      check_zero( f.ctl.slots[idx].payload, FD_ADMINCTL_PAYLOAD_MAX );
      check_neighbors( &f, &saved, idx );
      FD_TEST( fd_adminctl_wait( &f.ctl, idx )==(sizes[n]>FD_ADMINCTL_PAYLOAD_MAX
                                               ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                                               : FD_ADMINCTL_RESULT_SUCCESS) );
      FD_TEST( fd_adminctl_state( f.ctl.slots[idx].state_pid_seq )==FD_ADMINCTL_STATE_FREE );
      check_neighbors( &f, &saved, idx );
    }
  }
  FD_LOG_NOTICE(( "pass: request length bounds in every command slot" ));
}

static void
test_completion_lengths( void ) {
  ulong mutations[] = { 0UL, 257UL, ULONG_MAX };
  ulong responses[] = { 0UL, 8UL, FD_ADMINCTL_PAYLOAD_MAX };
  uchar response[ FD_ADMINCTL_PAYLOAD_MAX ];
  fd_memset( response, 0xCD, sizeof(response) );
  for( ulong idx=0UL; idx<FD_ADMINCTL_SLOT_CNT; idx++ ) {
    for( ulong m=0UL; m<sizeof(mutations)/sizeof(mutations[0]); m++ ) {
      for( ulong r=0UL; r<sizeof(responses)/sizeof(responses[0]); r++ ) {
        struct fixture f;
        init( &f );
        fd_adminctl_publish( &f.ctl, idx, FD_ADMINCTL_CMD_FAILOVER_STATUS, 8UL );
        f.ctl.poll_idx = idx;
        ulong got_idx;
        ulong got_sz;
        void * got;
        FD_TEST( fd_adminctl_poll( &f.ctl, &got_idx, &got, &got_sz )==FD_ADMINCTL_CMD_FAILOVER_STATUS );
        /* The length may change after poll has validated the request. */
        f.ctl.slots[idx].payload_sz = mutations[m];
        struct fixture saved = f;
        ulong sz = responses[r];
        if( sz ) fd_adminctl_complete_response( &f.ctl, idx, FD_ADMINCTL_RESULT_SUCCESS, response, sz );
        else     fd_adminctl_complete( &f.ctl, idx, FD_ADMINCTL_RESULT_SUCCESS );
        FD_TEST( f.ctl.slots[idx].payload_sz==sz );
        FD_TEST( !memcmp( f.ctl.slots[idx].payload, response, sz ) );
        check_zero( f.ctl.slots[idx].payload+sz, FD_ADMINCTL_PAYLOAD_MAX-sz );
        check_neighbors( &f, &saved, idx );
        uchar out[ FD_ADMINCTL_PAYLOAD_MAX ];
        ulong out_sz;
        FD_TEST( !fd_adminctl_wait_response( &f.ctl, idx, out, sizeof(out), &out_sz ) );
        FD_TEST( out_sz==sz && !memcmp( out, response, sz ) );
        check_zero( f.ctl.slots[idx].payload, FD_ADMINCTL_PAYLOAD_MAX );
        check_neighbors( &f, &saved, idx );
      }
    }
  }
  FD_LOG_NOTICE(( "pass: completion ignores mutated request lengths and clears the full slot" ));
}

static void
test_response_lengths( void ) {
  ulong sizes[] = { 0UL, 8UL, 256UL, 257UL, ULONG_MAX };
  ulong limits[] = { 0UL, 7UL, 256UL, 300UL };
  for( ulong idx=0UL; idx<FD_ADMINCTL_SLOT_CNT; idx++ ) {
    for( ulong s=0UL; s<sizeof(sizes)/sizeof(sizes[0]); s++ ) {
      for( ulong l=0UL; l<sizeof(limits)/sizeof(limits[0]); l++ ) {
        struct fixture f;
        init( &f );
        fd_adminctl_slot_t * slot = &f.ctl.slots[idx];
        slot->payload_sz = sizes[s];
        slot->result = FD_ADMINCTL_RESULT_SUCCESS;
        slot->state_pid_seq = fd_adminctl_state_update( slot->state_pid_seq, FD_ADMINCTL_STATE_DONE );
        struct fixture saved = f;
        uchar out[ 364 ];
        fd_memset( out, 0xCD, sizeof(out) );
        ulong out_sz;
        FD_TEST( !fd_adminctl_wait_response( &f.ctl, idx, out+32UL, limits[l], &out_sz ) );
        FD_TEST( out_sz==fd_ulong_min( sizes[s], FD_ADMINCTL_PAYLOAD_MAX ) );
        ulong copied = fd_ulong_min( out_sz, limits[l] );
        for( ulong i=0UL; i<sizeof(out); i++ ) {
          FD_TEST( out[i]==(i>=32UL && i<32UL+copied ? (uchar)(idx+1UL) : (uchar)0xCD) );
        }
        check_zero( slot->payload, out_sz );
        check_neighbors( &f, &saved, idx );
      }
    }
  }
  FD_LOG_NOTICE(( "pass: response copy bounds, including forged lengths" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_request_lengths();
  test_completion_lengths();
  test_response_lengths();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
