#include "ag_vote_history_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"

static uchar buf[ 16UL<<20 ];
static ag_vote_history_file_t out[ 1 ];

#define PUT( T, v )   do { FD_STORE( T, buf+sz, (v) ); sz += sizeof(T); } while(0)
#define PUT_HASH( b ) do { fd_memset( buf+sz, (b), 32UL ); sz += 32UL; } while(0)

/* BAD_* name where build puts slot 9, below the root of 10. */
#define BAD_NONE           (0)
#define BAD_VOTED          (1) /* the only voted slot */
#define BAD_NOTAR_FALLBACK (2) /* an extra, empty voted_notar_fallback entry */
#define BAD_VOTES_CAST     (3) /* an extra, empty votes_cast entry */
#define BAD_PARENT_READY   (4) /* an extra, empty parent_ready_slots entry */

/* build writes a vote history with root 10 into buf, signed by
   priv/pub, and returns its size.  node is the embedded node pubkey
   and bad is a BAD_*. */

static ulong
build( uchar const pub [ 32 ],
       uchar const priv[ 32 ],
       uchar const node[ 32 ],
       int         bad ) {
  ulong sz = 0UL;
  PUT( uint, 0U );         /* SavedVoteHistoryVersions::Current */
  sz += 64UL;              /* signature */
  sz += 8UL;               /* data_sz */
  ulong data_off = sz;

  fd_memcpy( buf+sz, node, 32UL ); sz += 32UL;

  PUT( ulong, 1UL ); PUT( ulong, bad==BAD_VOTED ? 9UL : 11UL );                /* voted */
  PUT( ulong, 1UL ); PUT( ulong, 11UL ); PUT_HASH( 0xAA );                     /* voted_notar */
  PUT( ulong, 1UL+(bad==BAD_NOTAR_FALLBACK) );                                 /* voted_notar_fallback */
  PUT( ulong, 12UL ); PUT( ulong, 2UL );
    PUT_HASH( 0xB1 ); PUT_HASH( 0xB2 );
  if( bad==BAD_NOTAR_FALLBACK ) { PUT( ulong, 9UL ); PUT( ulong, 0UL ); }
  PUT( ulong, 1UL ); PUT( ulong, 12UL );                                       /* voted_skip_fallback */
  PUT( ulong, 2UL ); PUT( ulong, 12UL ); PUT( ulong, 13UL );                   /* skipped */
  PUT( ulong, 0UL );                                                           /* its_over */
  PUT( ulong, 2UL+(bad==BAD_VOTES_CAST) );                                     /* votes_cast */
  PUT( ulong, 11UL ); PUT( ulong, 1UL );
    PUT( uchar, 1 ); PUT( ulong, 11UL ); PUT_HASH( 0xAA ); PUT( ushort, 0 );   /* Notar */
  PUT( ulong, 12UL ); PUT( ulong, 2UL );
    PUT( uchar, 3 ); PUT( ulong, 12UL ); PUT( ushort, 0 );                     /* Skip */
    PUT( uchar, 5 ); PUT( ulong, 12UL ); PUT( ushort, 0 );                     /* SkipFallback */
  if( bad==BAD_VOTES_CAST ) { PUT( ulong, 9UL ); PUT( ulong, 0UL ); }
  PUT( ulong, 1UL ); PUT( ulong, 11UL ); PUT_HASH( 0xAA );                     /* notarized_blocks */
  PUT( ulong, 2UL+(bad==BAD_PARENT_READY) );                                   /* parent_ready_slots */
  PUT( ulong, 12UL ); PUT( ulong, 1UL );
    PUT( ulong, 11UL ); PUT_HASH( 0xAA );
  PUT( ulong, 11UL ); PUT( ulong, 1UL );
    PUT( ulong, 10UL ); PUT_HASH( 0xCC );
  if( bad==BAD_PARENT_READY ) { PUT( ulong, 9UL ); PUT( ulong, 0UL ); }
  PUT( ulong, 10UL );                                                          /* root */

  FD_STORE( ulong, buf+4UL+64UL, sz-data_off );
  fd_sha512_t sha[ 1 ];
  fd_ed25519_sign( buf+4UL, buf+data_off, sz-data_off, pub, priv, sha );
  return sz;
}

/* build_long writes a vote history rooted at 0 into buf, signed by
   priv/pub, and returns its size.  Like Agave's 30,000 slot test it
   notarizes and finalizes every slot in [1,slot_cnt], and like Agave's
   worst case size estimate each leader window start s is parent ready
   from the root block and from nf_cnt blocks in each slot in [1,s). */

static ulong
build_long( uchar const pub [ 32 ],
            uchar const priv[ 32 ],
            ulong       slot_cnt,
            ulong       nf_cnt ) {
  ulong sz = 0UL;
  PUT( uint, 0U ); sz += 64UL+8UL; /* kind, signature, data_sz */
  ulong data_off = sz;

  fd_memcpy( buf+sz, pub, 32UL ); sz += 32UL;

  PUT( ulong, slot_cnt );     /* voted */
  for( ulong s=1UL; s<=slot_cnt; s++ ) PUT( ulong, s );
  PUT( ulong, slot_cnt );     /* voted_notar */
  for( ulong s=1UL; s<=slot_cnt; s++ ) { PUT( ulong, s ); PUT_HASH( 0 ); }
  PUT( ulong, 0UL );          /* voted_notar_fallback */
  PUT( ulong, 0UL );          /* voted_skip_fallback */
  PUT( ulong, 0UL );          /* skipped */
  PUT( ulong, slot_cnt );     /* its_over */
  for( ulong s=1UL; s<=slot_cnt; s++ ) PUT( ulong, s );
  PUT( ulong, slot_cnt );     /* votes_cast */
  for( ulong s=1UL; s<=slot_cnt; s++ ) {
    PUT( ulong, s ); PUT( ulong, 2UL );
    PUT( uchar, 1 ); PUT( ulong, s ); PUT_HASH( 0 ); PUT( ushort, 0 );
    PUT( uchar, 2 ); PUT( ulong, s ); PUT( ushort, 0 );
  }
  PUT( ulong, slot_cnt );     /* notarized_blocks */
  for( ulong s=1UL; s<=slot_cnt; s++ ) { PUT( ulong, s ); PUT_HASH( 0 ); }
  PUT( ulong, slot_cnt/4UL ); /* parent_ready_slots */
  for( ulong s=4UL; s<=slot_cnt; s+=4UL ) {
    PUT( ulong, s ); PUT( ulong, 1UL+nf_cnt*(s-1UL) );
    PUT( ulong, 0UL ); PUT_HASH( 0 );
    for( ulong t=1UL; t<s; t++ ) for( ulong j=1UL; j<=nf_cnt; j++ ) { PUT( ulong, t ); PUT_HASH( (int)j ); }
  }
  PUT( ulong, 0UL );          /* root */

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

  ulong sz = build( pub, priv, pub, BAD_NONE );
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
  FD_TEST( out->parent_ready_slot==12UL && out->parent_ready_cnt==1UL && out->parent_ready[0].slot==11UL );

  /* every truncation fails; signed body prefixes exercise decoder bounds */
  for( ulong i=0UL; i<sz; i++ ) {
    if( i>=76UL ) {
      FD_STORE( ulong, buf+68UL, i-76UL );
      fd_ed25519_sign( buf+4UL, buf+76UL, i-76UL, pub, priv, sha );
    }
    FD_TEST( ag_vote_history_file_de( buf, i, pub, out )==AG_VOTE_HISTORY_FILE_ERR_SIZE );
  }
  sz = build( pub, priv, pub, BAD_NONE );

  /* trailing bytes */
  FD_TEST( ag_vote_history_file_de( buf, sz+1UL, pub, out )==AG_VOTE_HISTORY_FILE_ERR_SIZE );

  /* wrong verifier */
  FD_TEST( ag_vote_history_file_de( buf, sz, pub2, out )==AG_VOTE_HISTORY_FILE_ERR_SIG );

  /* signed by identity but for another node */
  sz = build( pub, priv, pub2, BAD_NONE );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_IDENTITY );

  /* slots below root, including keys of empty map entries */
  for( int bad=BAD_VOTED; bad<=BAD_PARENT_READY; bad++ ) {
    sz = build( pub, priv, pub, bad );
    if( ag_vote_history_file_de( buf, sz, pub, out )!=AG_VOTE_HISTORY_FILE_ERR_HISTORY ) FD_LOG_ERR(( "bad %i not rejected", bad ));
  }

  /* bad outer version */
  sz = build( pub, priv, pub, BAD_NONE );
  FD_STORE( uint, buf, 1U );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_VERSION );

  /* 180 slots without finalization fit, Agave's 30,000 do not */
  sz = build_long( pub, priv, 180UL, 0UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_SUCCESS );
  FD_TEST( out->voted_cnt==180UL && out->votes_cast_cnt==360UL && out->notarized_blocks_cnt==180UL );
  FD_TEST( out->parent_ready_slot==180UL && out->parent_ready_cnt==1UL );
  sz = build_long( pub, priv, 30000UL, 0UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_ERR_SIZE );

  /* quadratic parent ready growth, only the highest slot's parents are
     kept */
  sz = build_long( pub, priv, 16UL, 4UL );
  FD_TEST( ag_vote_history_file_de( buf, sz, pub, out )==AG_VOTE_HISTORY_FILE_SUCCESS );
  FD_TEST( out->parent_ready_slot==16UL && out->parent_ready_cnt==1UL+4UL*15UL );
  FD_TEST( out->parent_ready[ out->parent_ready_cnt-1UL ].slot==15UL && out->parent_ready[ out->parent_ready_cnt-1UL ].hash[0]==4 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
