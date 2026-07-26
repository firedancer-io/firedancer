#include "fd_txn.h"
#include "../../util/sanitize/fd_sanitize.h"

/* This transaction is from the flood pcap. It never landed on chain. */
FD_IMPORT_BINARY( transaction1, "src/ballet/txn/fixtures/transaction1.bin" );

/* This transaction landed on mainnet. The base58 encoded signature is
   4gxceixEGkug6Da4KgTjZ9EVjEyEDWSk5QzokfucQE4d767yyxjwgv46u5y3hntprtVMGWGz1cNzWeC6DtJhUcuz */
FD_IMPORT_BINARY( transaction2, "src/ballet/txn/fixtures/transaction2.bin" );

/* When parsed, this transaction takes up the maximum amount of space */
FD_IMPORT_BINARY( transaction3, "src/ballet/txn/fixtures/transaction3.bin" );

/* This transaction has no instructions and only one account address */
FD_IMPORT_BINARY( transaction4, "src/ballet/txn/fixtures/transaction4.bin" );

/* Hand-crafted invalid instruction that would trigger an out-of-bounds
   write in a previous version. It is not a valid transaction. */
FD_IMPORT_BINARY( transaction5, "src/ballet/txn/fixtures/transaction5.bin" );

/* The program ID is a signer on this transaction.  That's valid. */
FD_IMPORT_BINARY( transaction6, "src/ballet/txn/fixtures/transaction6.bin" );

#define RED_ZONE_SZ (8UL)
#define RED_ZONE_VAL ((uchar)0xCC)

uchar out_buf[ FD_TXN_MAX_SZ+RED_ZONE_SZ ];
uchar test_buf[ FD_TXN_MAX_SZ ];

uchar payload_c[ FD_TXN_MTU ];
uchar min_okay[  FD_TXN_MTU ];
uchar max_okay[  FD_TXN_MTU ];

void txn1_correctness( void ) {
  fd_txn_parse_counters_t  counters = {0};
  static uchar const first_sig_byte [  4 ] = {   97, 189,  11, 108 };
  static uchar const first_acct_byte[ 23 ] = {  220, 255,  85,  89, 201, 170, 194, 48, 228, 123, 151, 133, 6, 6, 203, 6,
                                                 11,   6,   0, 140,   3,   5, 168 };
  static uchar const ix0_data       [  5 ] = { 0x00,0xE0,0x93,0x04,0x00 };
  fd_txn_t * parsed = (fd_txn_t *)out_buf;
  ulong out_sz = fd_txn_parse( transaction1, transaction1_sz, out_buf, &counters );
  FD_TEST( out_sz );
  FD_TEST( counters.success_cnt==1UL );
  FD_TEST( counters.failure_cnt==0UL );
  FD_TEST( parsed->transaction_version == FD_TXN_VLEGACY );
  FD_TEST( parsed->signature_cnt == 4UL );
  fd_ed25519_sig_t const * sigs = fd_txn_get_signatures( parsed, transaction1 );
  for( ulong j=0UL; j<parsed->signature_cnt; j++ ) {
    FD_TEST( transaction1[ parsed->signature_off + j*FD_TXN_SIGNATURE_SZ ]==first_sig_byte[ j ] );
    FD_TEST( sigs[ j ][ 0 ]                                               ==first_sig_byte[ j ] );
  }
  FD_TEST( parsed->message_off == parsed->signature_off + parsed->signature_cnt*FD_TXN_SIGNATURE_SZ );
  FD_TEST( parsed->readonly_signed_cnt   ==  1UL );
  FD_TEST( parsed->readonly_unsigned_cnt == 11UL );
  FD_TEST( parsed->acct_addr_cnt         == 23UL );
  for( ulong j=0UL; j<parsed->acct_addr_cnt; j++ )
    FD_TEST( transaction1[ parsed->acct_addr_off + j*FD_TXN_ACCT_ADDR_SZ ]==first_acct_byte[ j ] );
  FD_TEST( transaction1[ parsed->recent_blockhash_off ] == 155UL );
  FD_TEST( parsed->addr_table_lookup_cnt        == 0UL );
  FD_TEST( parsed->addr_table_adtl_writable_cnt == 0UL );
  FD_TEST( parsed->addr_table_adtl_cnt          == 0UL );
  FD_TEST( parsed->instr_cnt == 7UL );
  fd_txn_instr_t * ix = parsed->instr;
  FD_TEST( ix[ 0 ].program_id == 20UL );
  FD_TEST( ix[ 0 ].acct_cnt   ==  0UL );
  FD_TEST( ix[ 0 ].data_sz    ==  5UL );
  FD_TEST( !memcmp( &transaction1[ ix[ 0 ].data_off ], ix0_data, 5UL ) );

  FD_TEST( ix[ 1 ].program_id == 18UL );
  FD_TEST( ix[ 1 ].acct_cnt   ==  2UL );
  FD_TEST( ix[ 1 ].data_sz    == 12UL );
  FD_TEST( transaction1[ ix[ 1 ].acct_off ] == 0UL );
  FD_TEST( transaction1[ ix[ 1 ].data_off ] == 2UL );

  FD_TEST( ix[ 6 ].program_id == 22UL );
  FD_TEST( ix[ 6 ].acct_cnt   == 21UL );
  FD_TEST( ix[ 6 ].data_sz    == 12UL );
  FD_TEST( transaction1[ ix[ 6 ].acct_off ] ==  14UL );
  FD_TEST( transaction1[ ix[ 6 ].data_off ] == 211UL );
}
void txn2_correctness( void ) {
  fd_txn_parse_counters_t counters = {0};
  static uchar const first_sig_byte    [ 1 ] = { 184 };
  static uchar const first_acct_byte   [ 6 ] = { 216, 176,   9, 213, 3, 4 };
  static uchar const first_lut_writable[ 4 ] = { 142, 141, 143, 144 };
  fd_txn_t * parsed = (fd_txn_t *)out_buf;
  ulong out_sz = fd_txn_parse( transaction2, transaction2_sz, out_buf, &counters );
  FD_TEST( out_sz );
  FD_TEST( counters.success_cnt==1UL );
  FD_TEST( counters.failure_cnt==0UL );
  FD_TEST( parsed->transaction_version == FD_TXN_V0 );
  FD_TEST( parsed->signature_cnt == 1UL );
  fd_ed25519_sig_t const * sigs = fd_txn_get_signatures( parsed, transaction2 );
  for( ulong j=0UL; j<parsed->signature_cnt; j++ ) {
    FD_TEST( transaction2[ parsed->signature_off + j*FD_TXN_SIGNATURE_SZ ]==first_sig_byte[ j ] );
    FD_TEST( sigs[ j ][ 0 ]                                               ==first_sig_byte[ j ] );
  }
  FD_TEST( parsed->message_off == parsed->signature_off + parsed->signature_cnt*FD_TXN_SIGNATURE_SZ );
  FD_TEST( parsed->readonly_signed_cnt   == 0UL );
  FD_TEST( parsed->readonly_unsigned_cnt == 2UL );
  FD_TEST( parsed->acct_addr_cnt         == 6UL );
  for( ulong j=0UL; j<parsed->acct_addr_cnt; j++ )
    FD_TEST( transaction2[ parsed->acct_addr_off + j*FD_TXN_ACCT_ADDR_SZ ]==first_acct_byte[ j ] );
  FD_TEST( transaction2[ parsed->recent_blockhash_off ] == 148UL );
  FD_TEST( parsed->addr_table_lookup_cnt        == 3UL );
  FD_TEST( parsed->addr_table_adtl_writable_cnt == 12UL );
  FD_TEST( parsed->addr_table_adtl_cnt          == 21UL );
  FD_TEST( parsed->instr_cnt == 2UL );
  fd_txn_instr_t * ix = parsed->instr;
  FD_TEST( ix[ 0 ].program_id == 4UL );
  FD_TEST( ix[ 0 ].acct_cnt   == 0UL );
  FD_TEST( ix[ 0 ].data_sz    == 5UL );

  FD_TEST( ix[ 1 ].program_id ==  5UL );
  FD_TEST( ix[ 1 ].acct_cnt   == 39UL );
  FD_TEST( ix[ 1 ].data_sz    == 38UL );
  FD_TEST( transaction2[ ix[ 1 ].acct_off ] ==  18UL );
  FD_TEST( transaction2[ ix[ 1 ].data_off ] == 229UL );

  fd_txn_acct_addr_lut_t const * luts = fd_txn_get_address_tables_const( parsed );
  FD_TEST( transaction2[ luts[ 0 ].addr_off ] == 54UL );
  FD_TEST( luts[ 0 ].writable_cnt == 4UL );
  FD_TEST( luts[ 0 ].readonly_cnt == 4UL );
  FD_TEST( !memcmp( &transaction2[ luts[ 0 ].writable_off ], first_lut_writable, 4UL ) );
  FD_TEST( transaction2[ luts[ 0 ].readonly_off + 1 ] == 117UL );

  FD_TEST( transaction2[ luts[ 1 ].addr_off ] == 34UL );
  FD_TEST( luts[ 1 ].writable_cnt == 4UL );
  FD_TEST( luts[ 1 ].readonly_cnt == 4UL );
  FD_TEST( transaction2[ luts[ 1 ].writable_off ] == 196UL );
  FD_TEST( transaction2[ luts[ 1 ].readonly_off ] == 194UL );

  FD_TEST( transaction2[ luts[ 2 ].addr_off ] == 212UL );
  FD_TEST( luts[ 2 ].writable_cnt == 4UL );
  FD_TEST( luts[ 2 ].readonly_cnt == 1UL );
  FD_TEST( transaction2[ luts[ 2 ].writable_off ] == 91UL );
  FD_TEST( transaction2[ luts[ 2 ].readonly_off ] == 97UL );

}

void test_mutate( uchar const * payload,
    ulong len ) {
  fd_txn_parse_counters_t counters = {0};

  fd_memcpy( payload_c, payload, len );

  fd_txn_t * parsed = (fd_txn_t *)out_buf;
  ulong out_sz = fd_txn_parse( payload_c, len, out_buf, NULL );
  FD_TEST( out_sz );

  ulong footprint = fd_txn_footprint( parsed->instr_cnt, parsed->addr_table_lookup_cnt );
  FD_TEST( out_sz==footprint );
  fd_txn_acct_addr_lut_t const * tables = fd_txn_get_address_tables_const( parsed );

  /* The transaction should be valid if for each byte payload[ i ],
      min_okay[ i ] <= payload[ i ] <= max_okay[ i ]
   */
  fd_memcpy( min_okay, payload_c, len );
  fd_memcpy( max_okay, payload_c, len );

#define MUT_OKAY( start, len ) do { for( ulong _=(start); _<(start)+(len); _++ ) { min_okay[ _ ] = 0; max_okay[ _ ] = 0xFFUL; } } while( 0 )
  MUT_OKAY( parsed->signature_off,        parsed->signature_cnt*FD_TXN_SIGNATURE_SZ );
  MUT_OKAY( parsed->acct_addr_off,        parsed->acct_addr_cnt*FD_TXN_ACCT_ADDR_SZ );
  MUT_OKAY( parsed->recent_blockhash_off,                       FD_TXN_BLOCKHASH_SZ );
  ulong signed_ro_idx = parsed->message_off + (parsed->transaction_version==FD_TXN_V0 ? 2UL : 1UL );
  min_okay[ signed_ro_idx   ] = 0;
  max_okay[ signed_ro_idx   ] = (uchar)(parsed->signature_cnt-1);
  min_okay[ signed_ro_idx+1 ] = 0;
  max_okay[ signed_ro_idx+1 ] = (uchar)(parsed->acct_addr_cnt - parsed->signature_cnt);
  for( ulong j=0; j<parsed->instr_cnt; j++ ) {
    min_okay[ parsed->instr[ j ].acct_off-2 ] = 1;
    max_okay[ parsed->instr[ j ].acct_off-2 ] = (uchar)(parsed->acct_addr_cnt - 1);
    MUT_OKAY( parsed->instr[ j ].data_off, parsed->instr[ j ].data_sz  );
    for( ulong k=0; k<parsed->instr[ j ].data_sz; k++ ) {
      /* Modify contents of instruction data to make it unlikely that reading
         these bytes as some other field can give a valid transaction. */
      payload_c[ parsed->instr[ j ].data_off+k ] = (uchar)0xDA;
    }
    ulong total_accts = (ulong)parsed->acct_addr_cnt + (ulong)parsed->addr_table_adtl_cnt;
    for( ulong k=0; k<parsed->instr[ j ].acct_cnt; k++ ) {
      min_okay[ parsed->instr[ j ].acct_off+k ] = 0;
      max_okay[ parsed->instr[ j ].acct_off+k ] = (uchar)(parsed->acct_addr_cnt + parsed->addr_table_adtl_cnt - 1);
      /* Modify contents of which accounts the instruction references to make
         it unlikely that reading these bytes as some other field can give a
         valid transaction. */
      payload_c[ parsed->instr[ j ].acct_off+k ] = (uchar)((total_accts-1UL-k)%total_accts);
    }
  }
  for( ulong j=0; j<parsed->addr_table_lookup_cnt; j++ ) {
    MUT_OKAY( tables[ j ].addr_off,     FD_TXN_ACCT_ADDR_SZ );
    MUT_OKAY( tables[ j ].writable_off, tables[ j ].writable_cnt );
    MUT_OKAY( tables[ j ].readonly_off, tables[ j ].readonly_cnt );
  }
  FD_TEST( fd_txn_parse( payload_c, len, test_buf, NULL ) );
  FD_TEST( !memcmp( out_buf, test_buf, footprint ) );

#undef MUT_OKAY
  for( ulong i=0; i<len; i++ ) {
    /* Test truncated version */
    FD_TEST( !fd_txn_parse( payload_c, i, test_buf, &counters ) );
    uchar orig = payload_c[ i ];
    for( ulong off=1; off<256; off++ ) {
      payload_c[ i ] = (uchar)(orig+off);
      ulong mut_parsed_footprint = fd_txn_parse( payload_c, len, test_buf, &counters );
      fd_txn_t * mut_parsed = (fd_txn_t *)test_buf;
      if( min_okay[ i ]==0 && max_okay[ i ]==255 ) {
        FD_TEST( footprint == mut_parsed_footprint );
        FD_TEST( !memcmp( parsed, mut_parsed, footprint ) );
      } else if ( payload_c[ i ]<min_okay[ i ] || payload_c[ i ]>max_okay[ i ] ) {
        FD_TEST( !mut_parsed_footprint );
      } else {
        FD_TEST( mut_parsed_footprint );
      }
    }
    payload_c[ i ] = orig;
  }
  FD_TEST( counters.success_cnt );
  FD_TEST( counters.failure_cnt );
  FD_TEST( (counters.success_cnt+counters.failure_cnt) == 256*len );
  for( ulong i=0UL; i<FD_TXN_PARSE_COUNTERS_RING_SZ; i++ ) FD_TEST( counters.failure_ring[ i ] );
}


/* V1 transaction (SIMD-0385) test helpers.

   build_v1 assembles a V1 transaction into buf from the given parameters
   and returns its serialized size.  Layout mirrors Agave
   transaction-view try_new_as_v1:
     VersionByte | LegacyHeader(3) | ConfigMask(u32 LE) | Blockhash(32) |
     NumInstr | NumAddr | Addresses | ConfigValues | InstrHeaders |
     InstrPayloads | Signatures (at the end) */

struct v1_instr {
  uchar  program_id;
  uchar  acct_cnt;
  ushort data_sz;
  uchar  accts[ 8 ]; /* up to 8 account indices for tests */
};
typedef struct v1_instr v1_instr_t;

static ulong
build_v1( uchar       * buf,
          uchar         num_req_sig,
          uchar         ro_signed,
          uchar         ro_unsigned,
          uint          config_mask,
          uchar         num_addr,
          v1_instr_t const * instrs,
          uchar         instr_cnt ) {
  ulong o = 0UL;
  buf[ o++ ] = (uchar)0x81;          /* version byte: MESSAGE_VERSION_PREFIX | 1 */
  buf[ o++ ] = num_req_sig;
  buf[ o++ ] = ro_signed;
  buf[ o++ ] = ro_unsigned;
  /* config mask u32 LE */
  buf[ o++ ] = (uchar)( config_mask        & 0xFF );
  buf[ o++ ] = (uchar)((config_mask >>  8) & 0xFF );
  buf[ o++ ] = (uchar)((config_mask >> 16) & 0xFF );
  buf[ o++ ] = (uchar)((config_mask >> 24) & 0xFF );
  for( ulong j=0UL; j<32UL; j++ ) buf[ o++ ] = (uchar)(0xB0+j); /* blockhash */
  buf[ o++ ] = instr_cnt;
  buf[ o++ ] = num_addr;
  /* addresses */
  for( ulong a=0UL; a<num_addr; a++ )
    for( ulong j=0UL; j<32UL; j++ ) buf[ o++ ] = (uchar)(a*32UL+j);
  /* config values: one 4-byte word per set bit */
  ulong nvals = (ulong)fd_uint_popcnt( config_mask );
  for( ulong v=0UL; v<nvals; v++ ) { buf[o++]=0; buf[o++]=0x04; buf[o++]=0; buf[o++]=0; } /* arbitrary */
  /* instruction headers */
  for( ulong j=0UL; j<instr_cnt; j++ ) {
    buf[ o++ ] = instrs[j].program_id;
    buf[ o++ ] = instrs[j].acct_cnt;
    buf[ o++ ] = (uchar)( instrs[j].data_sz       & 0xFF );
    buf[ o++ ] = (uchar)((instrs[j].data_sz >> 8) & 0xFF );
  }
  /* instruction payloads (account indices then data) */
  for( ulong j=0UL; j<instr_cnt; j++ ) {
    for( ulong k=0UL; k<instrs[j].acct_cnt; k++ ) buf[ o++ ] = instrs[j].accts[k];
    for( ulong k=0UL; k<instrs[j].data_sz;  k++ ) buf[ o++ ] = (uchar)k;
  }
  /* signatures */
  for( ulong s=0UL; s<num_req_sig; s++ )
    for( ulong j=0UL; j<64UL; j++ ) buf[ o++ ] = (uchar)(0x40+s);
  return o;
}

static uchar v1_buf[ FD_TXN_MTU ];

void txn_v1_correctness( void ) {
  fd_txn_parse_counters_t counters = {0};
  fd_txn_t * parsed = (fd_txn_t *)out_buf;

  /* --- Minimal valid V1: 1 sig, 2 addrs, 1 instr (program=1, 1 acct, no data), no config --- */
  {
    v1_instr_t ix[1] = { { .program_id=1, .acct_cnt=1, .data_sz=0, .accts={0} } };
    ulong sz = build_v1( v1_buf, /*num_req_sig*/1, /*ro_signed*/0, /*ro_unsigned*/1,
                         /*config_mask*/0u, /*num_addr*/2, ix, /*instr_cnt*/1 );
    counters = (fd_txn_parse_counters_t){0};
    ulong out_sz = fd_txn_parse( v1_buf, sz, out_buf, &counters );
    FD_TEST( out_sz );
    FD_TEST( counters.success_cnt==1UL );
    FD_TEST( parsed->transaction_version          == FD_TXN_V1 );
    FD_TEST( parsed->signature_cnt                == 1 );
    FD_TEST( parsed->message_off                  == 0 ); /* message starts at byte 0 in V1 */
    FD_TEST( parsed->readonly_signed_cnt          == 0 );
    FD_TEST( parsed->readonly_unsigned_cnt        == 1 );
    FD_TEST( parsed->acct_addr_cnt                == 2 );
    FD_TEST( parsed->addr_table_lookup_cnt        == 0 ); /* no ALTs in V1 */
    FD_TEST( parsed->addr_table_adtl_cnt          == 0 );
    FD_TEST( parsed->v1_txn_config_mask           == 0 );
    FD_TEST( parsed->instr_cnt                    == 1 );
    FD_TEST( parsed->instr[0].program_id          == 1 );
    FD_TEST( parsed->instr[0].acct_cnt            == 1 );
    FD_TEST( parsed->instr[0].data_sz             == 0 );
    /* signatures are at the very end */
    FD_TEST( parsed->signature_off                == sz - 64UL );
    /* blockhash sits right after the 4-byte config mask + 3-byte header + version */
    FD_TEST( parsed->recent_blockhash_off         == 8 );
    FD_TEST( v1_buf[ parsed->recent_blockhash_off ] == 0xB0 );
  }

  /* --- Valid V1 with full config mask (priority fee + CU + loaded + heap) --- */
  {
    v1_instr_t ix[1] = { { .program_id=1, .acct_cnt=0, .data_sz=3, .accts={0} } };
    ulong sz = build_v1( v1_buf, 1, 0, 1, /*mask*/0x1Fu, 2, ix, 1 );
    counters = (fd_txn_parse_counters_t){0};
    ulong out_sz = fd_txn_parse( v1_buf, sz, out_buf, &counters );
    FD_TEST( out_sz );
    FD_TEST( parsed->v1_txn_config_mask == 0x1F );
    /* config values region = 5 words * 4 bytes, located after the addresses */
    FD_TEST( parsed->v1_txn_config_values_off == 8UL+32UL+1UL+1UL+2UL*32UL );
  }

  /* --- Rejection cases --- */
  v1_instr_t ix1[1] = { { .program_id=1, .acct_cnt=1, .data_sz=0, .accts={0} } };

  /* truncation: a valid transaction parsed with too few bytes must fail
     (CHECK_LEFT catches the missing trailing signature bytes) */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz-1UL, out_buf, &counters ) );
    FD_TEST( counters.failure_cnt==1UL );
  }

  /* bad version byte (0x82 = version 2) */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix1, 1 );
    v1_buf[0] = (uchar)0x82;
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* reserved config mask bit set (bit 5) */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0x20u, 2, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* priority-fee bit pairing violated (bit 0 set, bit 1 clear) */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0x01u, 2, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* program id is the fee payer (index 0) */
  {
    v1_instr_t ix[1] = { { .program_id=0, .acct_cnt=1, .data_sz=0, .accts={0} } };
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* program id out of range (>= num_addr) */
  {
    v1_instr_t ix[1] = { { .program_id=2, .acct_cnt=1, .data_sz=0, .accts={0} } };
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* account index out of range (>= num_addr) */
  {
    v1_instr_t ix[1] = { { .program_id=1, .acct_cnt=1, .data_sz=0, .accts={2} } };
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* num_addr exceeds FD_TXN_ACCT_ADDR_MAX (64) */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 65, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* readonly_signed >= num_req_sig (fee payer not writable) */
  {
    ulong sz = build_v1( v1_buf, 1, 1, 0, 0u, 2, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz, out_buf, &counters ) );
  }

  /* trailing-byte rejection when payload_sz_opt is NULL */
  {
    ulong sz = build_v1( v1_buf, 1, 0, 1, 0u, 2, ix1, 1 );
    counters = (fd_txn_parse_counters_t){0};
    FD_TEST( 0UL == fd_txn_parse( v1_buf, sz+1UL, out_buf, &counters ) );
  }

  FD_LOG_NOTICE(( "v1 parse tests pass" ));
}

void test_performance( uchar const * payload,
                       ulong sz ) {
  const ulong test_count = 10000000UL;
  long start = fd_log_wallclock( );
  for( ulong i = 0; i < test_count; i++ ) {
    FD_TEST( fd_txn_parse( payload, sz, out_buf, NULL ) );
  }
  long end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "Average time per parse: %f ns", (double)(end-start)/(double)test_count ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  txn1_correctness( );
  txn2_correctness( );
  txn_v1_correctness( );

  test_performance( transaction1, transaction1_sz );
  test_performance( transaction2, transaction2_sz );

  test_mutate( transaction1, transaction1_sz );
  test_mutate( transaction2, transaction2_sz );

  fd_memset( out_buf+FD_TXN_MAX_SZ, RED_ZONE_VAL, RED_ZONE_SZ );
  fd_asan_poison( out_buf+FD_TXN_MAX_SZ, RED_ZONE_SZ );

  FD_TEST( FD_TXN_MAX_SZ                == fd_txn_parse( transaction3, transaction3_sz, out_buf, NULL ) );

  FD_TEST( sizeof(fd_txn_t)             == fd_txn_parse( transaction4, transaction4_sz, out_buf, NULL ) );

  FD_TEST( 0UL                          == fd_txn_parse( transaction5, transaction5_sz, out_buf, NULL ) );

  FD_TEST( fd_txn_footprint( 1UL, 0UL ) == fd_txn_parse( transaction6, transaction6_sz, out_buf, NULL ) );

  fd_asan_unpoison( out_buf+FD_TXN_MAX_SZ, RED_ZONE_SZ );
  for( ulong i=0UL; i<RED_ZONE_SZ; i++ ) FD_TEST( out_buf[ FD_TXN_MAX_SZ+i ] == RED_ZONE_VAL );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

