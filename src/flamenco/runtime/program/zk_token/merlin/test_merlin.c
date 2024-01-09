#include "fd_merlin.h"
#include "../../../../fd_flamenco.h"
#include "../../../../../ballet/hex/fd_hex.h"

// https://github.com/zkcrypto/merlin/blob/3.0.0/src/strobe.rs
// https://github.com/zkcrypto/merlin/blob/3.0.0/src/transcript.rs

/*
void
test_strobe128_dbg(fd_merlin_strobe128_t* ctx) {
  printf("state: ");
  for (ulong i=0; i<200; i++) { printf("%02x ", ctx->state_bytes[i]); }
  printf("\npos: %d\n", ctx->pos);
  printf("pos_begin: %d\n", ctx->pos_begin);
  printf("cur_flags: %d\n", ctx->cur_flags);
}
*/

static void
test_equivalence_simple( FD_FN_UNUSED fd_rng_t * rng ) {
  fd_merlin_transcript_t t[1];
  uchar challenge[ 32 ];
  uchar expected [ 32 ];

  fd_merlin_transcript_init( t, FD_MERLIN_LITERAL("test protocol") );
  // test_strobe128_dbg(&t->sctx);
  fd_merlin_transcript_append_message( t, FD_MERLIN_LITERAL("some label"), (uchar *)FD_MERLIN_LITERAL("some data") );
  fd_merlin_transcript_challenge_bytes( t, FD_MERLIN_LITERAL("challenge"), challenge, 32 );

  fd_hex_decode( expected, "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615", 64 );
  // for (ulong i=0; i<32; i++) { printf("%02x ", challenge[i]); } printf("\n");
  FD_TEST( memcmp( challenge, expected, 32 )==0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_equivalence_simple( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
