#include "ag_vote_history_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"

static uchar buf[ 1UL<<20 ];
static ag_vote_history_file_t out[ 1 ];

#define PUT( T, v )   do { FD_STORE( T, buf+sz, (v) ); sz += sizeof(T); } while(0)
#define PUT_HASH( b ) do { fd_memset( buf+sz, (b), 32UL ); sz += 32UL; } while(0)

/* build writes a vote history with root 10 into buf, signed by
   priv/pub, and returns its size.  node is the embedded node pubkey,
   bad_slot, if nonzero, replaces the only voted slot, and pr_cnt is
   the number of distinct parents ready for slot 12. */

static ulong
build( uchar const pub [ 32 ],
       uchar const priv[ 32 ],
       uchar const node[ 32 ],
       ulong       bad_slot,
       ulong       pr_cnt ) {
  ulong sz = 0UL;
  PUT( uint, 0U );         /* SavedVoteHistoryVersions::Current */
  sz += 64UL;              /* signature */
  sz += 8UL;               /* data_sz */
  ulong data_off = sz;

  fd_memcpy( buf+sz, node, 32UL ); sz += 32UL;

  PUT( ulong, 1UL ); PUT( ulong, bad_slot ? bad_slot : 11UL );                 /* voted */
  PUT( ulong, 1UL ); PUT( ulong, 11UL ); PUT_HASH( 0xAA );                     /* voted_notar */
  PUT( ulong, 1UL );                                                           /* voted_notar_fallback */
  PUT( ulong, 12UL ); PUT( ulong, 2UL );
    PUT_HASH( 0xB1 ); PUT_HASH( 0xB2 );
  PUT( ulong, 1UL ); PUT( ulong, 12UL );                                       /* voted_skip_fallback */
  PUT( ulong, 2UL ); PUT( ulong, 12UL ); PUT( ulong, 13UL );                   /* skipped */
  PUT( ulong, 0UL );                                                           /* its_over */
  PUT( ulong, 2UL );                                                           /* votes_cast */
  PUT( ulong, 11UL ); PUT( ulong, 1UL );
    PUT( uchar, 1 ); PUT( ulong, 11UL ); PUT_HASH( 0xAA ); PUT( ushort, 0 );   /* Notar */
  PUT( ulong, 12UL ); PUT( ulong, 2UL );
    PUT( uchar, 3 ); PUT( ulong, 12UL ); PUT( ushort, 0 );                     /* Skip */
    PUT( uchar, 5 ); PUT( ulong, 12UL ); PUT( ushort, 0 );                     /* SkipFallback */
  PUT( ulong, 1UL ); PUT( ulong, 11UL ); PUT_HASH( 0xAA );                     /* notarized_blocks */
  PUT( ulong, 1UL );                                                           /* parent_ready_slots */
  PUT( ulong, 12UL ); PUT( ulong, pr_cnt );
  for( ulong i=0UL; i<pr_cnt; i++ ) { PUT( ulong, 11UL ); PUT_HASH( 0xAA ); FD_STORE( ulong, buf+sz-32UL, i ); }
  PUT( ulong, 10UL );                                                          /* root */

  FD_STORE( ulong, buf+4UL+64UL, sz-data_off );
  fd_sha512_t sha[ 1 ];
  fd_ed25519_sign( buf+4UL, buf+data_off, sz-data_off, pub, priv, sha );
  return sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_t sha[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  uchar priv [ 32 ]; fd_memset( priv,  1, 32UL );
  uchar priv2[ 32 ]; fd_memset( priv2, 2, 32UL );
  uchar pub  [ 32 ]; fd_ed25519_public_from_private( pub,  priv,  sha );
  uchar pub2 [ 32 ]; fd_ed25519_public_from_private( pub2, priv2, sha );

  ulong sz = build( pub, priv, pub, 0UL, 1UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_SUCCESS );
  FD_TEST( out->root==10UL );
  FD_TEST( out->voted_cnt==1UL && out->voted[0]==11UL );
  FD_TEST( out->voted_notar_cnt==1UL && out->voted_notar[0].slot==11UL && out->voted_notar[0].hash[0]==0xAA );
  FD_TEST( out->voted_notar_fallback_cnt==2UL && out->voted_notar_fallback[1].slot==12UL && out->voted_notar_fallback[1].hash[31]==0xB2 );
  FD_TEST( out->voted_skip_fallback_cnt==1UL );
  FD_TEST( out->skipped_cnt==2UL && out->skipped[1]==13UL );
  FD_TEST( out->its_over_cnt==0UL );
  FD_TEST( out->votes_cast_cnt==3UL );
  FD_TEST( out->votes_cast[0].kind==AG_VOTE_HISTORY_KIND_NOTAR && out->votes_cast[0].block.hash[0]==0xAA );
  FD_TEST( out->votes_cast[2].kind==AG_VOTE_HISTORY_KIND_SKIP_FALLBACK && out->votes_cast[2].block.slot==12UL );
  FD_TEST( out->notarized_blocks_cnt==1UL );
  FD_TEST( out->parent_ready_cnt==1UL && out->parent_ready[0].slot==12UL && out->parent_ready[0].block.slot==11UL );

  /* every truncation fails; signed body prefixes exercise decoder bounds */
  for( ulong i=0UL; i<sz; i++ ) {
    if( i>=76UL ) {
      FD_STORE( ulong, buf+68UL, i-76UL );
      fd_ed25519_sign( buf+4UL, buf+76UL, i-76UL, pub, priv, sha );
    }
    FD_TEST( ag_vote_history_file_de( buf, i, pub, out )==AG_VOTE_HISTORY_FILE_ERR_SIZE );
  }
  sz = build( pub, priv, pub, 0UL, 1UL );

  /* trailing bytes */
  FD_TEST( ag_vote_history_file_de( buf, sz+1UL, pub, out )==AG_VOTE_HISTORY_FILE_ERR_SIZE );

  /* wrong verifier */
  FD_TEST( ag_vote_history_file_de( buf, sz, pub2, out )==AG_VOTE_HISTORY_FILE_ERR_SIG );

  /* signed by identity but for another node */
  sz = build( pub, priv, pub2, 0UL, 1UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_IDENTITY );

  /* slot below root */
  sz = build( pub, priv, pub, 9UL, 1UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_HISTORY );

  /* bad outer version */
  sz = build( pub, priv, pub, 0UL, 1UL );
  FD_STORE( uint, buf, 1U );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_VERSION );

  /* parent ready sets grow quadratically with fallback certificates,
     so they are not bounded by AG_VOTE_HISTORY_BLOCK_MAX */
  sz = build( pub, priv, pub, 0UL, AG_VOTE_HISTORY_BLOCK_MAX+1UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_SUCCESS );
  FD_TEST( out->parent_ready_cnt==AG_VOTE_HISTORY_BLOCK_MAX+1UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
