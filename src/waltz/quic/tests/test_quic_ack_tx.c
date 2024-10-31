#include "../fd_quic_ack_tx.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_quic_ack_gen_t gen[1];

  /* Test ack_gen_init */

  fd_quic_ack_gen_init( gen );
  FD_TEST( gen->head==0 && gen->tail==0 );
  for( uint j=0; j<FD_QUIC_ACK_QUEUE_CNT; j++ ) {
    fd_quic_ack_t * ack = fd_quic_ack_queue_ele( gen, j );
    FD_TEST( ack->pkt_number.offset_lo == ack->pkt_number.offset_hi );
  }
  FD_TEST( !gen->is_elicited );

  /* Test fd_quic_ack_pkt insertion */

  fd_quic_ack_pkt( gen, 1UL, 0U, 9UL ); /* new range */
  FD_TEST( gen->head==1 && gen->tail==0 );
  FD_TEST( gen->queue[0].pkt_number.offset_lo==1UL && gen->queue[0].pkt_number.offset_hi==2UL );
  FD_TEST( gen->queue[0].ts==9UL );
  FD_TEST( gen->queue[0].enc_level==0U );

  fd_quic_ack_pkt( gen, 0UL, 0U, 10UL ); /* extend downwards */
  FD_TEST( gen->head==1 && gen->tail==0 );
  FD_TEST( gen->queue[0].pkt_number.offset_lo==0UL && gen->queue[0].pkt_number.offset_hi==2UL );
  FD_TEST( gen->queue[0].ts==9UL );

  fd_quic_ack_pkt( gen, 2UL, 0U, 11UL ); /* extend upwards */
  FD_TEST( gen->head==1 && gen->tail==0 );
  FD_TEST( gen->queue[0].pkt_number.offset_lo==0UL && gen->queue[0].pkt_number.offset_hi==3UL );
  FD_TEST( gen->queue[0].ts==11UL );

  for( ulong j=0UL; j<=2UL; j++ ) {
    fd_quic_ack_pkt( gen, j, 0U, 99UL ); /* dup */
    FD_TEST( gen->head==1 && gen->tail==0 );
    FD_TEST( gen->queue[0].pkt_number.offset_lo==0UL && gen->queue[0].pkt_number.offset_hi==3UL );
    FD_TEST( gen->queue[0].ts==11UL );
  }

  fd_quic_ack_pkt( gen, 4UL, 0U, 18UL ); /* gap */
  FD_TEST( gen->head==2 && gen->tail==0 );
  FD_TEST( gen->queue[0].pkt_number.offset_lo==0UL && gen->queue[0].pkt_number.offset_hi==3UL );
  FD_TEST( gen->queue[1].pkt_number.offset_lo==4UL && gen->queue[1].pkt_number.offset_hi==5UL );
  FD_TEST( gen->queue[1].ts==18UL );
  FD_TEST( gen->queue[0].enc_level==0U );
  FD_TEST( gen->queue[1].enc_level==0U );

  fd_quic_ack_pkt( gen, 0UL, 1U, 12UL ); /* switch encryption level */
  FD_TEST( gen->head==3 && gen->tail==0 );
  FD_TEST( gen->queue[2].pkt_number.offset_lo==0UL && gen->queue[2].pkt_number.offset_hi==1UL );
  FD_TEST( gen->queue[2].ts==12UL );
  FD_TEST( gen->queue[1].enc_level==0U );
  FD_TEST( gen->queue[2].enc_level==1U );

  /* Test fd_quic_ack_pkt overflow */

  while( gen->head - gen->tail < FD_QUIC_ACK_QUEUE_CNT ) {
    ulong pkt_number = gen->head * 2UL;
    fd_quic_ack_pkt( gen, pkt_number, 2U, 13UL );
    FD_TEST( gen->queue[ gen->head-1 ].pkt_number.offset_lo==pkt_number     );
    FD_TEST( gen->queue[ gen->head-1 ].pkt_number.offset_hi==pkt_number+1UL );
  }
  FD_TEST( gen->head==FD_QUIC_ACK_QUEUE_CNT && gen->tail==0 );

  /* Test fd_quic_gen_ack_frames */

  uchar buf[1024];
  gen->is_elicited = 1;

  /* requested wrong encryption level */
  FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+sizeof(buf), 1U, 2009UL )==buf );
  FD_TEST( gen->tail==0UL && gen->head==FD_QUIC_ACK_QUEUE_CNT );
  FD_TEST( gen->is_elicited==1 );

  /* not enough buffer space */
  for( ulong j=0UL; j<=4UL; j++ ) {
    FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+j, 0U, 2009UL )==buf );
    FD_TEST( gen->tail==0UL && gen->head==FD_QUIC_ACK_QUEUE_CNT );
    FD_TEST( gen->is_elicited==1 );
  }

  /* generate one frame */
  FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+16, 0U, 2011UL )==buf+5UL );
  FD_TEST( gen->tail==1UL && gen->head==FD_QUIC_ACK_QUEUE_CNT );
  fd_quic_ack_frame_t ack_frame[2];
  FD_TEST( fd_quic_decode_ack_frame( ack_frame, buf, 5UL )==5UL );
  FD_TEST( ack_frame[0].type           ==0x02 );
  FD_TEST( ack_frame[0].largest_ack    ==   2 );
  FD_TEST( ack_frame[0].ack_delay      ==   2 );
  FD_TEST( ack_frame[0].ack_range_count==   0 );
  FD_TEST( ack_frame[0].first_ack_range==   2 );
  FD_TEST( gen->is_elicited==1 );

  /* generate two frames */
  gen->tail = 0UL;
  FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+sizeof(buf), 0U, 2011UL )==buf+10UL );
  FD_TEST( gen->tail==2UL && gen->head==FD_QUIC_ACK_QUEUE_CNT );
  FD_TEST( fd_quic_decode_ack_frame( ack_frame,   buf,     128UL )==5UL );
  FD_TEST( fd_quic_decode_ack_frame( ack_frame+1, buf+5UL, 128UL )==5UL );
  FD_TEST( ack_frame[1].type           ==0x02 );
  FD_TEST( ack_frame[1].largest_ack    ==   4 );
  FD_TEST( ack_frame[1].ack_delay      ==   1 );
  FD_TEST( ack_frame[1].ack_range_count==   0 );
  FD_TEST( ack_frame[1].first_ack_range==   0 );
  FD_TEST( gen->is_elicited==1 );

  /* generate last frame */
  gen->tail = gen->head - 1;
  FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+sizeof(buf), 2U, 1UL )==buf+6UL );
  FD_TEST( gen->tail==gen->head );
  FD_TEST( fd_quic_decode_ack_frame( ack_frame, buf, 128UL )==6UL );
  FD_TEST( ack_frame[0].type           ==0x02 );
  FD_TEST( ack_frame[0].largest_ack    ==(FD_QUIC_ACK_QUEUE_CNT-1)*2UL );
  FD_TEST( ack_frame[0].ack_delay      ==   0 );
  FD_TEST( ack_frame[0].ack_range_count==   0 );
  FD_TEST( ack_frame[0].first_ack_range==   0 );
  FD_TEST( gen->is_elicited==0 );

  /* refuse to generate ACK frames when no ACK eliciting frame was received */
  gen->tail = gen->head - 1;
  FD_TEST( fd_quic_gen_ack_frames( gen, buf, buf+sizeof(buf), 2U, 1UL )==buf );
  FD_TEST( gen->tail==gen->head-1 );
  FD_TEST( gen->is_elicited==0 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
