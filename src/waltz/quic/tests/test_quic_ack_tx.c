#include "../fd_quic_ack_tx.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_quic_ack_gen_t gen[1];

  /* Test ack_gen_init */
  fd_quic_ack_gen_init( gen );
  FD_TEST( gen->head == 0 && gen->tail == 0 );
  for( uint j=0; j<FD_QUIC_ACK_QUEUE_CNT; j++ ) {
    fd_quic_ack_t * ack = fd_quic_ack_queue_ele( gen, j );
    FD_TEST( ack->pkt_number.offset_lo == ack->pkt_number.offset_hi );
  }
  FD_TEST( gen->pending_bytes == 0 );
  FD_TEST( gen->deadline      == ULONG_MAX );
  FD_TEST( !gen->is_elicited );
  FD_TEST( !gen->is_instant  );

  /* Ensure initial and handshake packets are immediately scheduled */
  gen->deadline = ULONG_MAX;

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
