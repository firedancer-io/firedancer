#include "fd_votor_hist.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_votor_hist_t hist = { .anchor=100UL, .last_leader_slot=ULONG_MAX, .vote_bound=99UL, .rec_cnt=1UL };
  hist.rec[0].slot  = 101UL;
  hist.rec[0].flags = FD_VOTOR_HIST_FLAG_VOTED|FD_VOTOR_HIST_FLAG_VOTED_NOTAR;
  fd_memset( &hist.rec[0].notar_hash, 0x42, sizeof(fd_block_hash_t) );
  uchar buf[FD_VOTOR_HIST_SER_MAX];
  ulong sz;
  FD_TEST( !fd_votor_hist_ser( &hist, buf, sizeof(buf), &sz ) );
  FD_TEST( sz==FD_VOTOR_HIST_HDR_SZ+FD_VOTOR_HIST_REC_MAX_SZ );
  fd_votor_hist_t out;
  FD_TEST( !fd_votor_hist_de( buf, sz, &out ) );
  FD_TEST( out.anchor==hist.anchor && out.rec_cnt==1UL && out.last_leader_slot==ULONG_MAX && out.vote_bound==99UL );
  FD_TEST( out.rec[0].slot==101UL && out.rec[0].flags==hist.rec[0].flags );
  FD_TEST( fd_memeq( &out.rec[0].notar_hash, &hist.rec[0].notar_hash, sizeof(fd_block_hash_t) ) );
  fd_votor_hist_t saved = out;
  FD_TEST( fd_votor_hist_de( buf, sz-1UL, &out )==-1 );
  FD_TEST( fd_memeq( &out, &saved, sizeof(out) ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
