#include "fd_bundle_crank.h"
#include "../pack/fd_chkdup.h"
#include "../../ballet/base64/fd_base64.h"

#include <stddef.h>
#include <stdio.h>


static const uchar fd_bundle_crank_3_vals[] = { FD_BUNDLE_CRANK_3_VALS };
static const uchar fd_bundle_crank_3_mask[] = { FD_BUNDLE_CRANK_3_MASK };
static const uchar fd_bundle_crank_2_vals[] = { FD_BUNDLE_CRANK_2_VALS };
static const uchar fd_bundle_crank_2_mask[] = { FD_BUNDLE_CRANK_2_MASK };

/* crank2:  */
FD_IMPORT_BINARY( payload_2ni,
    "src/disco/bundle/fixtures/2niAy2BYpfqTuBM7pZtTkHFnWM2x7bFcFL1oyR1ixqGRcG5uydjZiG5AR8PRYHAaQ3JqA8JYyCRoc3VCwohQVwYP.bin" );

FD_STATIC_ASSERT( sizeof(fd_bundle_crank_2_t)==FD_BUNDLE_CRANK_2_SZ, crank );
FD_STATIC_ASSERT( sizeof(fd_bundle_crank_3_t)==FD_BUNDLE_CRANK_3_SZ, crank );

FD_STATIC_ASSERT( offsetof(fd_bundle_crank_2_t, authorized_voter         )==FD_BUNDLE_CRANK_SIGNER_OFFSET,           crank );
FD_STATIC_ASSERT( offsetof(fd_bundle_crank_3_t, authorized_voter         )==FD_BUNDLE_CRANK_SIGNER_OFFSET,           crank );
FD_STATIC_ASSERT( offsetof(fd_bundle_crank_2_t, tip_payment_program      )==FD_BUNDLE_CRANK_TIP_PAYMENT_OFFSET,      crank );
FD_STATIC_ASSERT( offsetof(fd_bundle_crank_3_t, tip_payment_program      )==FD_BUNDLE_CRANK_TIP_PAYMENT_OFFSET,      crank );
FD_STATIC_ASSERT( offsetof(fd_bundle_crank_3_t, tip_distribution_program )==FD_BUNDLE_CRANK_TIP_DISTRIBUTION_OFFSET, crank );

fd_acct_addr_t _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD[1] = {{ .b={
            0x28,0x52,0x15,0xd0,0x34,0x59,0xfa,0xc3,0xaf,0xa0,0xa5,0x52,0xcf,0x8c,0xbb,0x79,
            0xe4,0xaa,0xb1,0x8c,0x04,0x4e,0x6d,0x0c,0x72,0x1f,0x03,0xda,0x2d,0xf9,0x03,0x6a } }};
fd_acct_addr_t _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7[1] = {{ .b={
            0x32,0xbc,0x07,0xc7,0xfd,0xe5,0x3f,0x2c,0x9f,0x45,0x8a,0xe8,0x51,0xf2,0x58,0x2a,
            0x9e,0xc4,0xfb,0x00,0x0a,0x87,0xd6,0x67,0xc4,0x77,0x0f,0x16,0xd1,0xd1,0xfc,0x9c } }};
fd_acct_addr_t _96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5[1] = {{ .b={
            0x78,0x52,0x1c,0xb1,0x79,0xce,0xbb,0x85,0x89,0xb5,0x56,0xa2,0xd5,0xec,0x94,0xd2,
            0x49,0x86,0x82,0xfd,0xf9,0xbb,0x2a,0xf5,0xad,0x64,0xe4,0x91,0xcc,0x41,0x53,0xda } }};
fd_acct_addr_t _DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf[1] = {{ .b={
            0xb7,0xcd,0xbb,0x03,0x1e,0x27,0xa7,0xcc,0xb0,0x1b,0xc0,0x7e,0x1c,0x5a,0x30,0x9b,
            0x18,0x61,0x2a,0x16,0xe8,0x10,0x00,0xb8,0x91,0xee,0x8d,0x46,0x0d,0x33,0x67,0x00 } }};
fd_acct_addr_t _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY[1] = {{ .b={
            0x09,0xe6,0xa5,0xb0,0xd0,0xb4,0xc7,0x53,0x14,0x33,0x60,0x33,0x1f,0x86,0x1a,0x39,
            0x2c,0xe7,0x46,0x08,0x74,0xbe,0x2f,0x8d,0x75,0x97,0xce,0x6b,0xa6,0xe3,0x8a,0xa9 } }};
fd_acct_addr_t _G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw[1] = {{ .b={
            0xe0,0xc6,0x27,0x22,0x1b,0xa1,0x94,0xab,0xf8,0x0b,0x2e,0xb3,0x18,0x2b,0x9d,0xcd,
            0x93,0x0d,0x59,0xc5,0xeb,0x75,0x59,0xf8,0x40,0x76,0x93,0x35,0xb2,0x6d,0xc6,0x16 } }};
fd_acct_addr_t _GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh[1] = {{ .b={
            0xe9,0x75,0xeb,0x4d,0xb2,0x71,0x5c,0x24,0x46,0x3c,0xf2,0xf7,0x44,0x84,0xb4,0xd9,
            0x4e,0x3a,0x9d,0x5d,0x6c,0xb9,0xf4,0xe1,0x12,0xef,0xea,0xb6,0x52,0xc0,0x7e,0x9a } }};
fd_acct_addr_t _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji[1] = {{ .b={
            0xec,0xc7,0x12,0xc5,0x2a,0xcf,0xd4,0x8b,0x8a,0x3f,0x01,0xd6,0x6b,0xb8,0x73,0x91,
            0xa5,0x12,0xf8,0x21,0xef,0xa5,0x7b,0xe1,0x1f,0x13,0xa3,0x62,0x24,0x6e,0x7f,0xe1 } }};
fd_acct_addr_t _GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib[1] = {{ .b={
            0xe7,0x3a,0x76,0xdc,0xa8,0x18,0x4f,0xf8,0x7c,0x60,0xf5,0x2c,0xe8,0xc2,0x48,0x1d,
            0xd0,0x64,0x22,0x92,0xe6,0x09,0x9d,0xce,0x9d,0x79,0x76,0xf1,0xa4,0x4b,0x29,0x44 } }};
fd_acct_addr_t _HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe[1] = {{ .b={
            0xf1,0x87,0xec,0x87,0xd1,0xf7,0x45,0xcb,0x3a,0x03,0x38,0x4a,0x26,0xa6,0x9e,0xda,
            0x0c,0xa2,0xd1,0xaa,0x0f,0x41,0xe4,0x24,0x16,0x37,0x7e,0x91,0xff,0x5b,0x5d,0x31 } }};
fd_acct_addr_t _HgzT81VF1xZ3FT9Eq1pHhea7Wcfq2bv4tWTP3VvJ8Y9D[1] = {{ .b={
            0xf7,0xf9,0x9a,0x09,0x42,0xfa,0xc7,0x88,0x05,0x49,0x43,0xab,0xbc,0xf9,0x46,0xb1,
            0xf9,0xb9,0x16,0xcb,0xe1,0x0a,0xed,0xcf,0xa9,0x96,0x76,0x65,0x37,0x1c,0xa2,0x80 } }};
fd_acct_addr_t _T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt[1] = {{ .b={
            0x06,0xaa,0x09,0x54,0x8b,0x50,0x47,0x6a,0xd4,0x62,0xf9,0x1f,0x89,0xa3,0x01,0x50,
            0x33,0x26,0x4f,0xc9,0xab,0xd5,0x27,0x00,0x20,0xa9,0xd1,0x42,0x33,0x47,0x42,0xfb } }};

#define EXPAND_ARR8(arr, i)  arr[(i)], arr[(i)+1], arr[(i)+2], arr[(i)+3], arr[(i)+4], arr[(i)+5], arr[(i)+6], arr[(i)+7],
#define EXPAND_ARR32(arr, i) EXPAND_ARR8(arr, (i)) EXPAND_ARR8(arr, (i)+8) EXPAND_ARR8(arr, (i)+16) EXPAND_ARR8(arr, (i)+24)

ulong
crank_generate_and_test( fd_bundle_crank_gen_t                       * gen,
                         fd_bundle_crank_tip_payment_config_t const  * old_tip_payment_config,
                         fd_acct_addr_t                       const  * new_block_builder,
                         fd_acct_addr_t                       const  * identity,
                         fd_acct_addr_t                       const  * tip_receiver_owner,
                         ulong                                         epoch,
                         ulong                                         block_builder_commission,
                         uchar                                       * out_payload,
                         fd_txn_t                                    * out_txn ) {
  ulong retval = fd_bundle_crank_generate( gen, old_tip_payment_config, new_block_builder, identity, tip_receiver_owner, epoch, block_builder_commission, out_payload, out_txn );
  if( FD_LIKELY( retval==FD_BUNDLE_CRANK_2_SZ ) ) {
    for( ulong i=0UL; i<retval; i++ ) FD_TEST( (out_payload[i]&fd_bundle_crank_2_mask[i])==fd_bundle_crank_2_vals[i] );
  }
  else if( FD_LIKELY( retval==FD_BUNDLE_CRANK_3_SZ ) ) {
    for( ulong i=0UL; i<retval; i++ ) FD_TEST( (out_payload[i]&fd_bundle_crank_3_mask[i])==fd_bundle_crank_3_vals[i] );
  }
  /* Could be 0 or ULONG_MAX */
  return retval;
}

static inline void
test_repro_onchain( void ) {
  fd_bundle_crank_gen_t g[1];

  fd_bundle_crank_gen_init( g, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, _T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt,
                               _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD, _GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib,
                               "NONE",
                               0UL );
  fd_acct_addr_t tip_payment_config[1];
  fd_acct_addr_t tip_receiver      [1];

  fd_bundle_crank_get_addresses( g, 740UL, tip_payment_config, tip_receiver );
  FD_TEST( fd_memeq( tip_payment_config, _HgzT81VF1xZ3FT9Eq1pHhea7Wcfq2bv4tWTP3VvJ8Y9D, 32UL ) );
  FD_TEST( fd_memeq( tip_receiver,       _G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw, 32UL ) );

  fd_bundle_crank_tip_payment_config_t old_tip_payment_config[1] = {{
    .discriminator = 0x82ccfa1ee0aa0c9bUL,
    .tip_receiver  = {{{ EXPAND_ARR32( _GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh->b, 0UL ) }}},
    .block_builder = {{{ EXPAND_ARR32( _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY->b, 0UL )  }}},
    .commission_pct = 5UL,
    .bumps = { 254, 255, 254, 255, 255, 252, 255, 252, 255 }
  }};

  uchar payload[ FD_TXN_MTU ];
  uchar _txn[ FD_TXN_MAX_SZ ];
  fd_txn_t * txn = (fd_txn_t *)_txn;
  uchar _txn_2ni[ FD_TXN_MAX_SZ ];
  fd_txn_t * txn_2ni = (fd_txn_t *)_txn_2ni;

  ulong sz = crank_generate_and_test( g, old_tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn );
  FD_TEST( sz==sizeof(fd_bundle_crank_2_t) );
  /* The transactions are not necessarily byte-for-byte identical,
     but they should be effectively identical */

  ulong txn_2ni_sz = fd_txn_parse( payload_2ni, payload_2ni_sz, _txn_2ni, NULL );
  FD_TEST( txn_2ni_sz );

  FD_TEST( txn->instr_cnt==txn_2ni->instr_cnt+2UL );
  fd_acct_addr_t const * addr = fd_txn_get_acct_addrs( txn, payload );
  fd_acct_addr_t const * addr_2ni = fd_txn_get_acct_addrs( txn_2ni, payload_2ni );
#define ASSERT_PUBKEY_EQ( idx1, idx2 ) FD_TEST( fd_memeq( addr+(idx1), addr_2ni+(idx2), 32UL ) ); \
                                       FD_TEST( fd_txn_is_writable( txn, idx1 )==fd_txn_is_writable( txn_2ni, idx2 ) ); \
                                       FD_TEST( fd_txn_is_signer  ( txn, idx1 )==fd_txn_is_signer  ( txn_2ni, idx2 ) );
  for( ulong i=0UL; i<txn_2ni->instr_cnt; i++ ) {
    FD_TEST( fd_memeq( addr + txn->instr[i+1UL].program_id, addr_2ni + txn_2ni->instr[i].program_id, 32UL ) );
    ASSERT_PUBKEY_EQ( txn->instr[i+1UL].program_id, txn_2ni->instr[i].program_id );
    FD_TEST( txn->instr[i+1UL].acct_cnt == txn_2ni->instr[i].acct_cnt );
    FD_TEST( txn->instr[i+1UL].data_sz  == txn_2ni->instr[i].data_sz  );
    for( ulong j=0UL; j<txn->instr[i+1UL].acct_cnt; j++ ) {
      ASSERT_PUBKEY_EQ( payload[ txn->instr[i+1UL].acct_off+j ], payload_2ni[ txn_2ni->instr[i].acct_off+j ] );
    }
    FD_TEST( fd_memeq( payload + txn->instr[i+1UL].data_off, payload_2ni + txn_2ni->instr[i].data_off, txn->instr[i].data_sz ) );
  }

  do {
    uchar _txn2[ FD_TXN_MAX_SZ ];
    ulong txn_sz = fd_txn_parse( payload, sz, _txn2, NULL );
    FD_TEST( txn_sz );
    FD_TEST( fd_memeq( _txn2, _txn, txn_sz ) );
  } while( 0 );

  do {
    char base64[ FD_BASE64_ENC_SZ( 1232 ) ];
    base64[ fd_base64_encode( base64, payload, sz ) ] = '\0';
    FD_LOG_NOTICE(( "Sample transaction: %s", base64 ));
  } while( 0 );
}

static inline int
check_duplicates( fd_bundle_crank_gen_t * g,
                  fd_rng_t              * rng,
                  fd_acct_addr_t const  * old_tip_receiver,
                  fd_acct_addr_t const  * old_block_builder ) {

  fd_bundle_crank_tip_payment_config_t old_tip_payment_config[1] = {{
    .discriminator = 0x82ccfa1ee0aa0c9bUL,
    .tip_receiver  = {{{ EXPAND_ARR32( old_tip_receiver->b,  0UL ) }}},
    .block_builder = {{{ EXPAND_ARR32( old_block_builder->b, 0UL ) }}},
    .commission_pct = 6UL,
    .bumps = { 254, 255, 254, 255, 255, 252, 255, 252, 255 }
  }};

  uchar payload[ FD_TXN_MTU ];
  uchar _txn[ FD_TXN_MAX_SZ ];
  fd_txn_t * txn = (fd_txn_t *)_txn;

  ulong sz = crank_generate_and_test( g, old_tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn );

  FD_TEST( sz==sizeof(fd_bundle_crank_2_t) );

  fd_acct_addr_t const * addr = fd_txn_get_acct_addrs( txn, payload );

  if( FD_UNLIKELY( !fd_memeq( addr[ payload[ txn->instr[1].acct_off + 1UL ] ].b, old_tip_receiver,  32UL ) ) ) return 0;
  if( FD_UNLIKELY( !fd_memeq( addr[ payload[ txn->instr[1].acct_off + 3UL ] ].b, old_block_builder, 32UL ) ) ) return 0;
  if( FD_UNLIKELY( !fd_memeq( addr[ payload[ txn->instr[2].acct_off + 2UL ] ].b, old_block_builder, 32UL ) ) ) return 0;

  /* Ensure they are writable. We know there are no readonly signers. */
  if( FD_UNLIKELY( payload[ txn->instr[1].acct_off + 1UL ]>=fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE ) ) ) return 0;
  if( FD_UNLIKELY( payload[ txn->instr[1].acct_off + 3UL ]>=fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE ) ) ) return 0;
  if( FD_UNLIKELY( payload[ txn->instr[2].acct_off + 2UL ]>=fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE ) ) ) return 0;

  fd_chkdup_t chkdup[1];
  fd_chkdup_join( fd_chkdup_new( chkdup, rng ) );

  return !fd_chkdup_check( chkdup, addr, fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALL ), NULL, 0UL );
}

static inline void
test_no_duplicates( void ) {
  fd_bundle_crank_gen_t g[1];

  fd_rng_t _rng[1];
  fd_rng_t * rng;
  rng = fd_rng_join( fd_rng_new( _rng, 1U, 3UL ) );

  fd_bundle_crank_gen_init( g, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, _T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt,
                               _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD, _GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib,
                               "NONE",
                               0UL );

  /* first byte one larger than DNVZ */
  fd_acct_addr_t _DSPxzwZjK7VqwGBKhy82uHXrdfc9XdAFpp9mSzL3NKR1[1] = {{ .b={
            0xb8,0xcd,0xbb,0x03,0x1e,0x27,0xa7,0xcc,0xb0,0x1b,0xc0,0x7e,0x1c,0x5a,0x30,0x9b,
            0x18,0x61,0x2a,0x16,0xe8,0x10,0x00,0xb8,0x91,0xee,0x8d,0x46,0x0d,0x33,0x67,0x00 } }};
  fd_acct_addr_t _1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE[1] = {{ .b={
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f } }};

  FD_TEST( check_duplicates( g, rng, _GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY  ) );
  FD_TEST( check_duplicates( g, rng, _GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh, _DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf ) );
  FD_TEST( check_duplicates( g, rng, _DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf, _DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf ) );
  FD_TEST( check_duplicates( g, rng, _96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5, _HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe ) );
  FD_TEST( check_duplicates( g, rng, _G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY  ) );
  FD_TEST( check_duplicates( g, rng, _DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf, _DSPxzwZjK7VqwGBKhy82uHXrdfc9XdAFpp9mSzL3NKR1 ) );
  FD_TEST( check_duplicates( g, rng, _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD, _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD ) );
  FD_TEST( check_duplicates( g, rng, _1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE,   _1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE   ) );

  fd_rng_delete( fd_rng_leave( rng ) );

}

static inline void
test_crank_cnt( void ) {
  fd_bundle_crank_gen_t g[1];

  fd_bundle_crank_gen_init( g, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, _T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt,
                               _3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD, _GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib,
                               "NONE",
                               1UL );

  fd_bundle_crank_tip_payment_config_t tip_payment_config[1] = {{
    .discriminator = 0x82ccfa1ee0aa0c9bUL,
    .tip_receiver  = {{{ EXPAND_ARR32( _G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw->b, 0UL ) }}},
    .block_builder = {{{ EXPAND_ARR32( _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY->b,  0UL ) }}},
    .commission_pct = 5UL,
    .bumps = { 254, 255, 254, 255, 255, 252, 255, 252, 255 }
  }};

  uchar payload[ FD_TXN_MTU ];
  uchar _txn[ FD_TXN_MAX_SZ ];
  fd_txn_t * txn = (fd_txn_t *)_txn;

  fd_acct_addr_t uncreated[1] = {{{ 0 }}};
  FD_TEST( sizeof(fd_bundle_crank_3_t)==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, uncreated, 740UL, 5UL, payload, txn ) );
  FD_TEST( 0UL==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn ) );

  tip_payment_config->commission_pct++;
  FD_TEST( sizeof(fd_bundle_crank_2_t)==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn ) );
  tip_payment_config->commission_pct--;

  tip_payment_config->tip_receiver->b[1]++;
  FD_TEST( sizeof(fd_bundle_crank_2_t)==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn ) );
  tip_payment_config->tip_receiver->b[1]--;

  tip_payment_config->block_builder->b[2]++;
  FD_TEST( sizeof(fd_bundle_crank_2_t)==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn ) );
  tip_payment_config->block_builder->b[2]--;

  FD_TEST( 0UL==crank_generate_and_test( g, tip_payment_config, _feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY,
      _GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji, _4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7, 740UL, 5UL, payload, txn ) );
}

static void
test_masks( void ) {
#define MEMO_PROGRAM_ID 0x05U,0x4aU,0x53U,0x5aU,0x99U,0x29U,0x21U,0x06U,0x4dU,0x24U,0xe8U,0x71U,0x60U,0xdaU,0x38U,0x7cU, \
                        0x7cU,0x35U,0xb5U,0xddU,0xbcU,0x92U,0xbbU,0x81U,0xe4U,0x1fU,0xa8U,0x40U,0x41U,0x05U,0x44U,0x8dU
#define FULL_MASK       0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, \
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
  static const union {
    fd_bundle_crank_3_t m;
    uchar b[sizeof(fd_bundle_crank_3_t)];
  } vals3 = { .m = {
    .sig_cnt         =  1,
    ._sig_cnt        =  1,
    .ro_signed_cnt   =  0,
    .ro_unsigned_cnt =  5,
    .acct_addr_cnt   = 21,

    .system_program         = { SYS_PROG_ID            },
    .compute_budget_program = { COMPUTE_BUDGET_PROG_ID },
    .memo_program           = { MEMO_PROGRAM_ID        },

    .instr_cnt = 5,
    .compute_budget_instruction = {
        .prog_id = 16,
        .acct_cnt = 0,
        .data_sz = 5,
        .set_cu_limit = 2,
        .cus = 130000U
    },

    .init_tip_distribution_acct = {
        .prog_id = 20,
        .acct_cnt = 5,
        .acct_idx = { 9, 13, 15, 0, 19 },
        .data_sz = 43,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_INIT_TIP_DISTR },
    },

    .change_tip_receiver = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 0, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0 },
        .data_sz = 8,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV }
    },

    .change_block_builder = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 13, 0, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0},
        .data_sz = 16,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD },
    },

    .memo = {
      .prog_id = 18,
      .acct_cnt = 0,
      .data_sz  = 3
    },
  }};
  static const union {
    fd_bundle_crank_3_t m;
    uchar b[sizeof(fd_bundle_crank_3_t)];
  } mask3 = { .m = {
    .sig_cnt         = 0xFF,
    ._sig_cnt        = 0xFF,
    .ro_signed_cnt   = 0xFF,
    .ro_unsigned_cnt = 0xFF,
    .acct_addr_cnt   = 0xFF,

    .system_program         = { FULL_MASK },
    .compute_budget_program = { FULL_MASK },
    .memo_program           = { FULL_MASK },

    .instr_cnt = 0xFF,
    .compute_budget_instruction = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .data_sz = 0xFF,
        .set_cu_limit = 0xFF,
        .cus = 0xFFFFFFFFU
    },

    .init_tip_distribution_acct = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .acct_idx = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .data_sz = 0xFF,
        .ix_discriminator = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    },

    .change_tip_receiver = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .acct_idx = { 0xFF, 0, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .data_sz = 0xFF,
        .ix_discriminator = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    },

    .change_block_builder = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .acct_idx = { 0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .data_sz = 0xFF,
        .ix_discriminator = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    },

    .memo = {
      .prog_id = 0xFF,
      .acct_cnt = 0xFF,
      .data_sz  = 0xFF
    },
  }};

  static const union {
    fd_bundle_crank_2_t m;
    uchar b[sizeof(fd_bundle_crank_2_t)];
  } vals2 = { .m = {
    .sig_cnt         =  1,
    ._sig_cnt        =  1,
    .ro_signed_cnt   =  0,
    .ro_unsigned_cnt =  3,
    .acct_addr_cnt   = 19,

    .compute_budget_program = { COMPUTE_BUDGET_PROG_ID },
    .memo_program           = { MEMO_PROGRAM_ID        },

    .instr_cnt = 4,
    .compute_budget_instruction = {
        .prog_id = 16,
        .acct_cnt = 0,
        .data_sz = 5,
        .set_cu_limit = 2,
        .cus = 83000U
    },

    .change_tip_receiver = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 0, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0 },
        .data_sz = 8,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_TIP_RCV }
    },

    .change_block_builder = {
        .prog_id = 17,
        .acct_cnt = 13,
        .acct_idx = { 10, 13, 0, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0},
        .data_sz = 16,
        .ix_discriminator = { FD_BUNDLE_CRANK_DISC_CHANGE_BLK_BLD },
    },

    .memo = {
      .prog_id = 18,
      .acct_cnt = 0,
      .data_sz = 3
    }
  }};
  static const union {
    fd_bundle_crank_2_t m;
    uchar b[sizeof(fd_bundle_crank_2_t)];
  } mask2 = { .m = {
    .sig_cnt         = 0xFF,
    ._sig_cnt        = 0xFF,
    .ro_signed_cnt   = 0xFF,
    .ro_unsigned_cnt = 0xFF,
    .acct_addr_cnt   = 0xFF,

    .compute_budget_program = { FULL_MASK },
    .memo_program           = { FULL_MASK },

    .instr_cnt = 0xFF,
    .compute_budget_instruction = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .data_sz = 0xFF,
        .set_cu_limit = 0xFF,
        .cus = 0xFFFFFFFFU
    },
    .change_tip_receiver = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .acct_idx = { 0xFF, 0, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .data_sz = 0xFF,
        .ix_discriminator = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    },

    .change_block_builder = {
        .prog_id = 0xFF,
        .acct_cnt = 0xFF,
        .acct_idx = { 0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .data_sz = 0xFF,
        .ix_discriminator = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    },

    .memo = {
      .prog_id = 0xFF,
      .acct_cnt = 0xFF,
      .data_sz = 0xFF
    }
  }};

  if( FD_UNLIKELY( sizeof(fd_bundle_crank_3_t)!=sizeof(fd_bundle_crank_3_vals) ||
                   sizeof(fd_bundle_crank_3_t)!=sizeof(fd_bundle_crank_3_mask) ||
                   sizeof(fd_bundle_crank_2_t)!=sizeof(fd_bundle_crank_2_vals) ||
                   sizeof(fd_bundle_crank_2_t)!=sizeof(fd_bundle_crank_2_mask) ||
                   !fd_memeq( vals3.b, fd_bundle_crank_3_vals, sizeof(fd_bundle_crank_3_t) ) ||
                   !fd_memeq( mask3.b, fd_bundle_crank_3_mask, sizeof(fd_bundle_crank_3_t) ) ||
                   !fd_memeq( vals2.b, fd_bundle_crank_2_vals, sizeof(fd_bundle_crank_2_t) ) ||
                   !fd_memeq( mask2.b, fd_bundle_crank_2_mask, sizeof(fd_bundle_crank_2_t) ) ) ) {

    printf("#define FD_BUNDLE_CRANK_3_VALS ");
    for( ulong i=0UL; i<sizeof(fd_bundle_crank_3_t); i++ ) {
      FD_TEST( mask3.b[i]==0xFF || vals3.b[i]==0 );
      printf( "0x%02hhx, ", vals3.b[i] );
      if( i%16UL==15UL ) printf("\\\n                               ");
    }
    printf("\n#define FD_BUNDLE_CRANK_3_MASK ");
    for( ulong i=0UL; i<sizeof(fd_bundle_crank_3_t); i++ ) {
      printf( "0x%02hhx, ", mask3.b[i] );
      if( i%16UL==15UL ) printf("\\\n                               ");
    }
    printf("\n");

    printf("#define FD_BUNDLE_CRANK_2_VALS ");
    for( ulong i=0UL; i<sizeof(fd_bundle_crank_2_t); i++ ) {
      FD_TEST( mask2.b[i]==0xFF || vals2.b[i]==0 );
      printf( "0x%02hhx, ", vals2.b[i] );
      if( i%16UL==15UL ) printf("\\\n                               ");
    }
    printf("\n#define FD_BUNDLE_CRANK_2_MASK ");
    for( ulong i=0UL; i<sizeof(fd_bundle_crank_2_t); i++ ) {
      printf( "0x%02hhx, ", mask2.b[i] );
      if( i%16UL==15UL ) printf("\\\n                               ");
    }
    printf("\n");
  }
  FD_TEST( sizeof(fd_bundle_crank_3_t)==sizeof(fd_bundle_crank_3_vals) );
  FD_TEST( sizeof(fd_bundle_crank_3_t)==sizeof(fd_bundle_crank_3_mask) );
  FD_TEST( sizeof(fd_bundle_crank_2_t)==sizeof(fd_bundle_crank_2_vals) );
  FD_TEST( sizeof(fd_bundle_crank_2_t)==sizeof(fd_bundle_crank_2_mask) );
  FD_TEST( fd_memeq( vals3.b, fd_bundle_crank_3_vals, sizeof(fd_bundle_crank_3_t) ) );
  FD_TEST( fd_memeq( mask3.b, fd_bundle_crank_3_mask, sizeof(fd_bundle_crank_3_t) ) );
  FD_TEST( fd_memeq( vals2.b, fd_bundle_crank_2_vals, sizeof(fd_bundle_crank_2_t) ) );
  FD_TEST( fd_memeq( mask2.b, fd_bundle_crank_2_mask, sizeof(fd_bundle_crank_2_t) ) );
}


int
main( int argc,
    char ** argv ) {
  fd_boot( &argc, &argv );

  test_repro_onchain();
  test_no_duplicates();
  test_crank_cnt();
  test_masks();


  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
