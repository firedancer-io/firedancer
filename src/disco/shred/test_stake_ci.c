#include "fd_stake_ci.h"
#define SLOTS_PER_EPOCH 1000 /* Just for testing */

fd_stake_ci_t _info[1];

uchar stake_msg[ FD_STAKE_CI_STAKE_MSG_SZ ];

fd_pubkey_t identity_key[1];

static fd_stake_weight_msg_t *
generate_stake_msg( uchar *      _buf,
                    ulong        epoch,
                    char const * stakers ) {
  fd_stake_weight_msg_t *buf = fd_type_pun( _buf );

  buf->epoch          = epoch;
  buf->start_slot     = epoch * SLOTS_PER_EPOCH;
  buf->slot_cnt       = SLOTS_PER_EPOCH;
  buf->staked_cnt     = strlen(stakers);
  buf->excluded_stake = 0UL;

  ulong i = 0UL;
  for(; *stakers; stakers++, i++ ) {
    memset( buf->weights[i].key.uc, *stakers, sizeof(fd_pubkey_t) );
    buf->weights[i].stake = 1000UL/(i+1UL);
  }
  return fd_type_pun( _buf );
}

static ulong
generate_dest_add( fd_shred_dest_weighted_t * buf,
                   char const               * destinations ) {
  ulong i = 0UL;
  for(; *destinations; destinations++, i++ ) {
    memset( buf+i, *destinations, sizeof(fd_shred_dest_weighted_t) );
    buf[i].stake_lamports = 0xDEADBEEF0BADF00DUL;
  }
  return i;
}

static void
check_destinations( fd_stake_ci_t const * info,
                    ulong                 epoch,
                    char const          * staked_dests,
                    char const          * unstaked_dests ) {
  ulong min_slot =  epoch        * SLOTS_PER_EPOCH;
  ulong max_slot = (epoch + 1UL) * SLOTS_PER_EPOCH - 1UL;
  FD_TEST( fd_stake_ci_get_sdest_for_slot ( info, min_slot ) == fd_stake_ci_get_sdest_for_slot ( info, max_slot ) );
  FD_TEST( fd_stake_ci_get_lsched_for_slot( info, min_slot ) == fd_stake_ci_get_lsched_for_slot( info, max_slot ) );

  if( FD_UNLIKELY( staked_dests==NULL ) ) {
    FD_TEST( !unstaked_dests ); /* If this fails, the test is wrong */
    FD_TEST( !fd_stake_ci_get_sdest_for_slot ( info, min_slot ) );
    FD_TEST( !fd_stake_ci_get_lsched_for_slot( info, min_slot ) );
    return;
  }

  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( info, min_slot );
  FD_TEST( sdest );

#if 0
  char present[28];
  for( ulong j=0UL; j<fd_shred_dest_cnt_staked( sdest ); j++ ) {
    present[ j ] = (char)(fd_shred_dest_idx_to_dest( sdest, (fd_shred_dest_idx_t)j )->pubkey.uc[0]);
  }
  ulong idx = fd_shred_dest_cnt_staked( sdest );
  present[ idx ] = '|';
  for( ulong j=0UL; j<fd_shred_dest_cnt_unstaked( sdest ); j++ ) {
    present[ idx+1UL ] = (char)(fd_shred_dest_idx_to_dest( sdest, (fd_shred_dest_idx_t)idx )->pubkey.uc[0]);
    idx++;
  }
  present[ idx+1UL ] = '\0';

  FD_LOG_NOTICE(( "Found %s, expecting %s|%s", present, staked_dests, unstaked_dests ));
#endif

  FD_TEST( fd_shred_dest_cnt_staked  ( sdest ) == strlen(   staked_dests ) );
  FD_TEST( fd_shred_dest_cnt_unstaked( sdest ) == strlen( unstaked_dests ) );

  ulong        i = 0UL;
  char const * c = staked_dests;
  for(; *c; c++, i++ ) {
    uchar buf[ 32 ];
    memset( buf, *c, 32UL );
    FD_TEST( fd_memeq( buf, fd_shred_dest_idx_to_dest( sdest, (fd_shred_dest_idx_t)i )->pubkey.uc, 32UL ) );
  }
  c = unstaked_dests;
  for(; *c; c++, i++ ) {
    uchar buf[ 32 ];
    memset( buf, *c, 32UL );
    FD_TEST( fd_memeq( buf, fd_shred_dest_idx_to_dest( sdest, (fd_shred_dest_idx_t)i )->pubkey.uc, 32UL ) );
  }

  fd_epoch_leaders_t * lsched = fd_stake_ci_get_lsched_for_slot( info, min_slot );
  FD_TEST( !fd_epoch_leaders_get( lsched, min_slot-1UL ) );
  FD_TEST( !fd_epoch_leaders_get( lsched, max_slot+1UL ) );
  ulong leader_cnt[ 26 ]={ 0UL };
  for( ulong s=min_slot; s<=max_slot; s++ ) {
    ulong c = (ulong)fd_epoch_leaders_get( lsched, s )->uc[ 0 ] - (ulong)'A';
    leader_cnt[ c ]++;
  }

  ulong unaccounted = max_slot-min_slot+1UL;
  for( char const * c=staked_dests; *c; c++ ) {
    /* The stake distribution this test uses is such that given the
       large number of slots per epoch and small number of validators,
       with high probability every staked validator will get at least
       one leader slot.  */
    FD_TEST( leader_cnt[ *c-'A' ] );
    unaccounted -= leader_cnt[ *c-'A' ];
  }
  FD_TEST( unaccounted==0UL );
}

static void
test_staked_only( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABC"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I" );
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "ABCDE" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I" );
  check_destinations( info, 1UL, "ABCDE", "I" );
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 2UL, "ABCF" ) );   fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 2UL, "ABCF",  "I" );
  check_destinations( info, 1UL, "ABCDE", "I" );
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 3UL, "I"    ) );   fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 2UL, "ABCF",  "I" );
  check_destinations( info, 3UL, "I",     ""  );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_unstaked_only( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  /* We need one epoch and one staked node */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "I"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "I", ""       );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABC" ) );
  check_destinations( info, 0UL, "I", "ABC"    );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABCDEF" ) );
  check_destinations( info, 0UL, "I", "ABCDEF" );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABC" ) );
  check_destinations( info, 0UL, "I", "ABC" );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_transitions( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABCD" ) );  fd_stake_ci_stake_msg_fini( info );
  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABCDEFGH" ) );
  check_destinations( info, 0UL, "ABCD", "EFGHI" );

  /* Transition half of unstaked to staked */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "ABCDEF" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABCD",   "EFGHI" );
  check_destinations( info, 1UL, "ABCDEF",   "GHI" );

  /* Transition them back */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 2UL, "AB" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 1UL, "ABCDEF",   "GHI" );
  check_destinations( info, 2UL, "AB",   "CDEFGHI" );

  /* Completely swap */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 3UL, "GI" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 2UL, "AB",   "CDEFGHI" );
  check_destinations( info, 3UL, "GI",   "ABCDEFH" );

  /* Delete a bunch of the unstaked ones */
  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "" ) );
  check_destinations( info, 2UL, "AB",  "I" );
  check_destinations( info, 3UL, "GI",  ""  );

  /* Add new unstaked */
  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "KL" ) );
  check_destinations( info, 2UL, "AB",  "IKL" );
  check_destinations( info, 3UL, "GI",   "KL" );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_startup( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  /* Before it has any information, no epoch should be known */
  check_destinations( info, 0UL, NULL, NULL );
  check_destinations( info, 1UL, NULL, NULL );

  /* We need one epoch and one staked node */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "I"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "I", ""       );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "A"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 1UL, "A", "I"      );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );

  /* Start over and make just A staked, which means I is unstaked */
  info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "A"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "A", "I"      );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_skip_ahead( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABC"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I");
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "ABCDE" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I");
  check_destinations( info, 1UL, "ABCDE", "I");
  /* Pretend something happens and we skip a few epochs */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 6UL, "ABCF" ) );   fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 6UL, "ABCF",  "I");
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 9UL, "GH"    ) );   fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 9UL, "GH",    "I");

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_cancel( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABC"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I");
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "ABCDE" ) );  /* Don't fini */
  check_destinations( info, 0UL, "ABC",   "I");
  check_destinations( info, 1UL, NULL,  NULL );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "EFG" ) );
  check_destinations( info, 0UL, "ABC", "EFGI");
  check_destinations( info, 1UL, NULL,   NULL );
  generate_dest_add( fd_stake_ci_dest_add_init( info ), "EFGHIJ" ); /* Don't fini */
  check_destinations( info, 0UL, "ABC", "EFGI");
  check_destinations( info, 1UL, NULL,   NULL );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_ordering( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABC"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I" );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "BCA"   ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABC",   "I" );
  check_destinations( info, 1UL, "BCA",   "I" );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "EFG" ) );
  check_destinations( info, 0UL, "ABC", "EFGI" );
  check_destinations( info, 1UL, "BCA", "EFGI" );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "LKJ" ) );
  check_destinations( info, 0UL, "ABC", "IJKL" );
  check_destinations( info, 1UL, "BCA", "IJKL" );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_destaking( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABCDEF" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABCDEF",   "I" );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABCH" ) );
  check_destinations( info, 0UL, "ABCDEF",  "HI" );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "DCAF" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "ABCDEF",  "HI" );
  check_destinations( info, 1UL, "DCAF",   "BHI" );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 2UL, "H" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 1UL, "DCAF",   "BHI" );
  check_destinations( info, 2UL, "H",     "ABCI" );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 3UL, "A" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 2UL, "H",     "ABCI" );
  check_destinations( info, 3UL, "A",     "BCHI" );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_changing_contact_info( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "A" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 0UL, "A",   "I" );

  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "AB" ) );
  check_destinations( info, 0UL, "A",  "BI" );

  fd_shred_dest_weighted_t * destinations = fd_stake_ci_dest_add_init( info );
  generate_dest_add( destinations, "AB" );
  destinations[ 0 ].ip4  = 0x11111111U;
  destinations[ 0 ].port = 0x2222;
  destinations[ 1 ].ip4  = 0x33333333U;
  destinations[ 1 ].port = 0x5555;

  fd_stake_ci_dest_add_fini( info, 2UL );

  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( info, 0UL );
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, 0 )->ip4  == 0x11111111U );
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, 0 )->port == 0x2222      );
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, 1 )->ip4  == 0x33333333U );
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, 1 )->port == 0x5555      );

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_limits( void ) {
  /* Cluster info cannot include more than 40,199 validators.  Any
     beyond that get truncated.

     Stake weights cannot include more than 40,200 public keys.  Any
     beyond that get truncated and counted as excluded stake.  more than
     40,200. */
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  for( ulong stake_weight_cnt=40198UL; stake_weight_cnt<=40201UL; stake_weight_cnt++ ) {
    fd_stake_weight_msg_t * buf = fd_type_pun( stake_msg );
    buf->epoch                  = stake_weight_cnt;
    buf->start_slot             = stake_weight_cnt * SLOTS_PER_EPOCH;
    buf->slot_cnt               = SLOTS_PER_EPOCH;
    buf->staked_cnt             = 0UL;
    buf->excluded_stake         = 0UL;

    for( ulong i=0UL; i<stake_weight_cnt; i++ ) {
      ulong stake = 2000000000UL/(i+1UL);
      if( FD_LIKELY( i<40200UL ) ) {
        memset( buf->weights[i].key.uc, 127-((int)i%96), sizeof(fd_pubkey_t) );
        if( FD_LIKELY( 127UL-i!=(ulong)'I' ) ) FD_STORE( ulong, buf->weights[i].key.uc, fd_ulong_bswap( i ) );
        buf->weights[i].stake = stake;
        buf->staked_cnt++;
      } else {
        buf->excluded_stake += stake;
      }
    }
    fd_stake_ci_stake_msg_init( info, buf );
    fd_stake_ci_stake_msg_fini( info );

    for( ulong cluster_info_cnt=40198UL; cluster_info_cnt<=40201UL; cluster_info_cnt++ ) {
      fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( info );
      for( ulong j=0UL; j<cluster_info_cnt; j++ ) {
        if( FD_LIKELY( j<40199UL ) ) {
          memset( dests[j].pubkey.uc, 127-((int)j%96), sizeof(fd_pubkey_t) );
          FD_STORE( ulong, dests[j].pubkey.uc, fd_ulong_bswap( j ) );
        }
      }
      fd_stake_ci_dest_add_fini( info, fd_ulong_min( cluster_info_cnt, 40199UL ) );

      FD_TEST( fd_stake_ci_get_sdest_for_slot ( info, stake_weight_cnt*SLOTS_PER_EPOCH ) );
      FD_TEST( fd_stake_ci_get_lsched_for_slot( info, stake_weight_cnt*SLOTS_PER_EPOCH ) );
    }
  }

  fd_stake_ci_delete( fd_stake_ci_leave( info ) );
}

static void
test_set_identity( void ) {
  fd_stake_ci_t * info = fd_stake_ci_join( fd_stake_ci_new( _info, identity_key ) );

  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 0UL, "ABCDEF" ) );  fd_stake_ci_stake_msg_fini( info );
  fd_stake_ci_dest_add_fini( info, generate_dest_add( fd_stake_ci_dest_add_init( info ), "ABCHJZ" ) );
  /* ABCDEF staked, HIJZ unstaked */

  fd_pubkey_t new[1];
  fd_memset( new, 'N', sizeof(fd_pubkey_t) );
  /* Test unstaked -> unstaked migration */
  fd_stake_ci_set_identity( info, new );
  check_destinations( info, 0UL, "ABCDEF",  "HIJNZ" );

  /* Make N staked */
  fd_stake_ci_stake_msg_init( info, generate_stake_msg( stake_msg, 1UL, "ABCDN" ) );  fd_stake_ci_stake_msg_fini( info );
  check_destinations( info, 1UL, "ABCDN",  "HIJZ" );

  /* staked->unstaked */
  fd_memset( new, 'H', sizeof(fd_pubkey_t) );
  fd_stake_ci_set_identity( info, new );
  check_destinations( info, 1UL, "ABCDN",  "HIJZ" );

  /* unstaked->staked */
  fd_memset( new, 'A', sizeof(fd_pubkey_t) );
  fd_stake_ci_set_identity( info, new );
  check_destinations( info, 1UL, "ABCDN",  "HIJZ" );

  /* staked->staked */
  fd_memset( new, 'B', sizeof(fd_pubkey_t) );
  fd_stake_ci_set_identity( info, new );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max = 0UL;
  for( ulong staked=1UL; staked<MAX_SHRED_DESTS; staked++ ) {
    max = fd_ulong_max( max, fd_shred_dest_footprint( staked, MAX_SHRED_DESTS-staked ) );
  }

  if( FD_UNLIKELY( MAX_SHRED_DEST_FOOTPRINT != max ) )
    FD_LOG_ERR(( "MAX_SHRED_DEST_FOOTPRINT should be %lu = sizeof(fd_shred_dest_t) + %lu", max, max-sizeof(fd_shred_dest_t) ));

  memset( identity_key, 'I', sizeof(fd_pubkey_t) );

  test_staked_only();
  test_unstaked_only();
  test_transitions();
  test_startup();
  test_skip_ahead();
  test_cancel();
  test_ordering();
  test_destaking();
  test_changing_contact_info();
  test_limits();
  test_set_identity();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
