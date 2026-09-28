#include "fd_pack_offer.h"
#include "fd_compute_budget_program.h"
#include "../../ballet/base58/fd_base58.h"

/* A minimal transaction serializer.  All counts in these tests are
   below 128, so every compact-u16 is a single byte. */

#define MAX_KEYS  (16UL)
#define MAX_IX    (8UL)
#define MAX_LUT   (2UL)

typedef struct {
  uchar key[ 32 ];
} key_t;

typedef struct {
  uchar prog_idx;
  uchar acct_cnt;
  uchar acct[ 16 ];
  uchar data_sz;
  uchar data[ 64 ];
} ix_t;

typedef struct {
  int   v0;
  uchar sig_seed;
  uchar blockhash_seed;
  uchar ro_signed;
  uchar ro_unsigned;
  ulong key_cnt;
  key_t keys[ MAX_KEYS ];
  ulong ix_cnt;
  ix_t  ix[ MAX_IX ];
  ulong lut_cnt;
  struct {
    uchar key[ 32 ];
    uchar w_cnt;
    uchar w[ 4 ];
    uchar r_cnt;
    uchar r[ 4 ];
  } lut[ MAX_LUT ];
} spec_t;

static ulong
serialize( spec_t const * s,
           uchar *        out ) {
  uchar * p = out;
  *p++ = 1; /* one signature */
  memset( p, s->sig_seed, 64UL ); p += 64UL;
  if( s->v0 ) *p++ = 0x80;
  *p++ = 1; /* num required signatures */
  *p++ = s->ro_signed;
  *p++ = s->ro_unsigned;
  *p++ = (uchar)s->key_cnt;
  for( ulong i=0UL; i<s->key_cnt; i++ ) { memcpy( p, s->keys[ i ].key, 32UL ); p += 32UL; }
  memset( p, s->blockhash_seed, 32UL ); p += 32UL;
  *p++ = (uchar)s->ix_cnt;
  for( ulong i=0UL; i<s->ix_cnt; i++ ) {
    ix_t const * ix = s->ix+i;
    *p++ = ix->prog_idx;
    *p++ = ix->acct_cnt;
    memcpy( p, ix->acct, ix->acct_cnt ); p += ix->acct_cnt;
    *p++ = ix->data_sz;
    memcpy( p, ix->data, ix->data_sz ); p += ix->data_sz;
  }
  if( s->v0 ) {
    *p++ = (uchar)s->lut_cnt;
    for( ulong i=0UL; i<s->lut_cnt; i++ ) {
      memcpy( p, s->lut[ i ].key, 32UL ); p += 32UL;
      *p++ = s->lut[ i ].w_cnt; memcpy( p, s->lut[ i ].w, s->lut[ i ].w_cnt ); p += s->lut[ i ].w_cnt;
      *p++ = s->lut[ i ].r_cnt; memcpy( p, s->lut[ i ].r, s->lut[ i ].r_cnt ); p += s->lut[ i ].r_cnt;
    }
  }
  return (ulong)(p-out);
}

static uchar payload_buf[ FD_TPU_MTU ];
static uchar txn_buf    [ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));

static fd_pack_offer_t
offer( spec_t const *         s,
       fd_acct_addr_t const * alt ) {
  ulong sz = serialize( s, payload_buf );
  FD_TEST( fd_txn_parse( payload_buf, sz, txn_buf, NULL ) );
  fd_pack_offer_t out[1];
  FD_TEST( fd_pack_offer_compute( (fd_txn_t const *)txn_buf, payload_buf, alt, out )==out );
  return *out;
}

static void
set_key( key_t * k,
         char    c ) {
  memset( k->key, c, 32UL );
}

static void
set_key_b58( key_t *      k,
             char const * b58 ) {
  FD_TEST( fd_base58_decode_32( b58, k->key ) );
}

/* Key layout of the base transaction:
     0 payer (writable signer)
     1 pool  (writable)
     2 tip account (writable)
     3 compute budget program
     4 system program
     5 swap program */
#define K_PAYER 0
#define K_POOL  1
#define K_TIP   2
#define K_CB    3
#define K_SYS   4
#define K_SWAP  5

static void
add_cb_limit( spec_t * s,
              uchar    cb_idx,
              uint     limit ) {
  ix_t * ix = s->ix + s->ix_cnt++;
  ix->prog_idx = cb_idx; ix->acct_cnt = 0; ix->data_sz = 5;
  ix->data[0] = 2; memcpy( ix->data+1, &limit, 4UL );
}

static void
add_cb_price( spec_t * s,
              uchar    cb_idx,
              ulong    micro_lamports ) {
  ix_t * ix = s->ix + s->ix_cnt++;
  ix->prog_idx = cb_idx; ix->acct_cnt = 0; ix->data_sz = 9;
  ix->data[0] = 3; memcpy( ix->data+1, &micro_lamports, 8UL );
}

static void
add_transfer( spec_t * s,
              uchar    sys_idx,
              uchar    from,
              uchar    to,
              ulong    lamports ) {
  ix_t * ix = s->ix + s->ix_cnt++;
  ix->prog_idx = sys_idx; ix->acct_cnt = 2; ix->acct[0] = from; ix->acct[1] = to; ix->data_sz = 12;
  uint disc = 2U; memcpy( ix->data, &disc, 4UL ); memcpy( ix->data+4, &lamports, 8UL );
}

static void
add_swap( spec_t *     s,
          uchar        swap_idx,
          uchar        a0,
          uchar        a1,
          char const * data ) {
  ix_t * ix = s->ix + s->ix_cnt++;
  ix->prog_idx = swap_idx; ix->acct_cnt = 2; ix->acct[0] = a0; ix->acct[1] = a1;
  ix->data_sz = (uchar)strlen( data ); memcpy( ix->data, data, ix->data_sz );
}

static void
base_keys( spec_t * s ) {
  memset( s, 0, sizeof(spec_t) );
  s->key_cnt = 6UL;
  set_key    ( s->keys+K_PAYER, 'P' );
  set_key    ( s->keys+K_POOL,  'L' );
  set_key_b58( s->keys+K_TIP,   "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5" );
  memcpy     ( s->keys[ K_CB ].key, FD_COMPUTE_BUDGET_PROGRAM_ID, 32UL );
  memset     ( s->keys[ K_SYS ].key, 0, 32UL );
  set_key    ( s->keys+K_SWAP,  'S' );
  s->ro_unsigned = 3; /* cb, sys, swap */
}

/* The bundle variant: price + limit, a tip transfer, and the swap. */
static void
bundle_variant( spec_t * s ) {
  base_keys( s );
  s->sig_seed = 1; s->blockhash_seed = 1;
  add_cb_limit( s, K_CB, 200000U );
  add_cb_price( s, K_CB, 1000UL );
  add_swap    ( s, K_SWAP, K_POOL, K_PAYER, "swap 100 for 99" );
  add_transfer( s, K_SYS, K_PAYER, K_TIP, 12345UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  spec_t s[1];

  /* Price, limit, a swap and a tip transfer */
  bundle_variant( s );
  fd_pack_offer_t o = offer( s, NULL );
  FD_TEST( o.static_tip==12345UL );
  FD_TEST( o.priority_fee==200UL ); /* 1000 micro-lamports/CU * 200k CU */

  /* Several tip transfers add up; no compute budget means no priority fee */
  base_keys( s );
  add_transfer( s, K_SYS, K_PAYER, K_TIP, 777UL );
  add_transfer( s, K_SYS, K_PAYER, K_TIP, 223UL );
  o = offer( s, NULL );
  FD_TEST( o.static_tip==1000UL );
  FD_TEST( o.priority_fee==0UL );

  /* A transfer to a non-tip account is not a tip */
  base_keys( s );
  add_cb_price( s, K_CB, 10UL );
  add_transfer( s, K_SYS, K_PAYER, K_POOL, 777UL );
  FD_TEST( offer( s, NULL ).static_tip==0UL );

  /* Other System instructions and malformed transfers are ignored */
  base_keys( s );
  add_transfer( s, K_SYS, K_PAYER, K_TIP, 5UL );
  s->ix[ 0 ].data[ 0 ] = 3; /* not a Transfer */
  FD_TEST( offer( s, NULL ).static_tip==0UL );
  base_keys( s );
  add_transfer( s, K_SYS, K_PAYER, K_TIP, 5UL );
  s->ix[ 0 ].data_sz = 11;
  FD_TEST( offer( s, NULL ).static_tip==0UL );

  /* A transfer by another program to a tip account is not a static tip */
  base_keys( s );
  add_transfer( s, K_SWAP, K_PAYER, K_TIP, 5UL );
  FD_TEST( offer( s, NULL ).static_tip==0UL );

  /* A tip transfer whose destination comes from a lookup table */
  memset( s, 0, sizeof(spec_t) );
  s->v0 = 1; s->sig_seed = 5;
  s->key_cnt = 2UL;
  set_key( s->keys+0, 'P' );
  memset ( s->keys[ 1 ].key, 0, 32UL );
  s->ro_unsigned = 1;
  s->lut_cnt = 1UL;
  memset( s->lut[ 0 ].key, 'T', 32UL );
  s->lut[ 0 ].w_cnt = 1; s->lut[ 0 ].w[ 0 ] = 3;
  add_transfer( s, 1, 0, 2, 42UL );
  fd_acct_addr_t alt[1];
  FD_TEST( fd_base58_decode_32( "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe", alt->b ) );
  FD_TEST( offer( s, alt ).static_tip==42UL );
  /* ...and with an unrelated lookup table address, or none, it isn't */
  memset( alt->b, 'M', 32UL );
  FD_TEST( offer( s, alt ).static_tip==0UL );
  FD_TEST( offer( s, NULL ).static_tip==0UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
