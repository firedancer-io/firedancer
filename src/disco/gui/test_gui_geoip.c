#include "../../util/fd_util.h"

#include <stdio.h>
#include <stdlib.h>

/* Manual benchmark: old bit-trie geoip vs new disjoint-segment binary
   search.  Usage:

     test_gui_geoip <old-format.bin> <new-format.bin>

   where the files are DECOMPRESSED old (10-byte CIDR records) and new
   (columnar segments) dbip images.  Checks that every lookup agrees
   and reports build + lookup timings. */

/* ---- old format: bit trie (copied from the deleted implementation) */

struct geoip_node {
  uchar has_prefix;
  uchar country_code_idx;
  uint  city_name_idx;
  struct geoip_node * left;
  struct geoip_node * right;
};
typedef struct geoip_node geoip_node_t;

#define MAX_NODES (1UL<<24UL)

static geoip_node_t * trie_nodes;
static ulong          trie_node_cnt;

static void
trie_insert( uint ip_addr, uchar prefix_len, uchar country_idx, uint city_idx ) {
  geoip_node_t * node = &trie_nodes[ 0 ];
  for( uchar bit_pos=0; bit_pos<prefix_len; bit_pos++ ) {
    uchar bit = (ip_addr >> (31 - bit_pos)) & 1;
    geoip_node_t ** slot = bit ? &node->right : &node->left;
    if( FD_LIKELY( !*slot ) ) {
      FD_TEST( trie_node_cnt<MAX_NODES );
      geoip_node_t * child = &trie_nodes[ trie_node_cnt++ ];
      child->left = NULL; child->right = NULL; child->has_prefix = 0;
      *slot = child;
    }
    node = *slot;
  }
  node->has_prefix       = 1;
  node->country_code_idx = country_idx;
  node->city_name_idx    = city_idx;
}

static geoip_node_t const *
trie_lookup( uint ip_host ) {
  geoip_node_t const * ret  = NULL;
  geoip_node_t const * node = &trie_nodes[ 0 ];
  for( uchar bit_pos=0; bit_pos<32; bit_pos++ ) {
    if( FD_UNLIKELY( node->has_prefix ) ) ret = node;
    uchar bit = (ip_host >> (31 - bit_pos)) & 1;
    geoip_node_t const * child = bit ? node->right : node->left;
    if( FD_UNLIKELY( !child ) ) break;
    node = child;
  }
  if( FD_UNLIKELY( node->has_prefix ) ) ret = node;
  return ret;
}

/* ---- new format: segment binary search */

static ulong         seg_cnt;
static uint const *  seg_start;
static uchar const * seg_country;
static uint const *  seg_city;

static ulong
seg_lookup( uint ip_host ) {
  ulong lo = 0UL;
  ulong hi = seg_cnt;
  while( hi-lo>1UL ) {
    ulong mid = (lo+hi)>>1;
    if( seg_start[ mid ]<=ip_host ) lo = mid;
    else                            hi = mid;
  }
  return lo;
}

/* ---- shared parsing */

static uchar *
read_file( char const * path, ulong * out_sz ) {
  FILE * fp = fopen( path, "rb" );
  FD_TEST( fp );
  FD_TEST( !fseek( fp, 0, SEEK_END ) );
  long sz = ftell( fp );
  FD_TEST( sz>0 );
  rewind( fp );
  uchar * buf = aligned_alloc( 16UL, fd_ulong_align_up( (ulong)sz, 16UL ) );
  FD_TEST( buf );
  FD_TEST( fread( buf, 1, (ulong)sz, fp )==(ulong)sz );
  fclose( fp );
  *out_sz = (ulong)sz;
  return buf;
}

static uchar const *
skip_strtabs( uchar const * p ) {
  ulong cc_cnt = FD_LOAD( ulong, p ); p += sizeof(ulong)+2UL*cc_cnt;
  ulong city_cnt = FD_LOAD( ulong, p ); p += sizeof(ulong);
  for( ulong i=0UL; i<city_cnt; i++ ) { while( *p ) p++; p++; }
  return p;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( argc==3 );

  ulong old_sz; uchar * old_img = read_file( argv[1], &old_sz );
  ulong new_sz; uchar * new_img = read_file( argv[2], &new_sz );

  /* Parse + build old trie (timed) */
  trie_nodes = aligned_alloc( 16UL, sizeof(geoip_node_t)*MAX_NODES );
  FD_TEST( trie_nodes );
  trie_nodes[ 0 ] = (geoip_node_t){0};
  trie_node_cnt = 1UL;

  uchar const * rec = skip_strtabs( old_img );
  ulong rec_cnt = FD_LOAD( ulong, rec ); rec += sizeof(ulong);

  long t0 = fd_log_wallclock();
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    uint  ip          = fd_uint_bswap( FD_LOAD( uint, rec+10UL*i ) );
    uchar prefix_len  = rec[ 10UL*i+4UL ];
    uchar country_idx = rec[ 10UL*i+5UL ];
    uint  city_idx    = FD_LOAD( uint, rec+10UL*i+6UL );
    trie_insert( ip, prefix_len, country_idx, city_idx );
  }
  long trie_build_ns = fd_log_wallclock()-t0;

  /* Parse new segments (build cost is just the pointer setup) */
  uchar const * p = skip_strtabs( new_img );
  p = new_img + fd_ulong_align_up( (ulong)(p-new_img), 4UL );
  seg_cnt = FD_LOAD( ulong, p ); p += sizeof(ulong);
  seg_start = fd_type_pun_const( p ); p += seg_cnt*sizeof(uint);
  seg_country = p;                    p += fd_ulong_align_up( seg_cnt, 4UL );
  seg_city = fd_type_pun_const( p );  p += seg_cnt*sizeof(uint);
  FD_TEST( (ulong)(p-new_img)==new_sz );

  FD_LOG_NOTICE(( "old: %lu records, trie build %ld ms (%lu nodes)", rec_cnt, trie_build_ns/1000000L, trie_node_cnt ));
  FD_LOG_NOTICE(( "new: %lu segments", seg_cnt ));

  /* Correctness: every lookup must agree, over random IPs and all
     segment boundaries +/-1 */
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 42U, 0UL ) );
  ulong checked = 0UL;
  for( ulong i=0UL; i<3UL*seg_cnt; i++ ) {
    uint ip;
    if(      i<seg_cnt )     ip = seg_start[ i ];
    else if( i<2UL*seg_cnt ) ip = seg_start[ i-seg_cnt ]-1U;
    else                     ip = fd_rng_uint( rng );

    geoip_node_t const * t = trie_lookup( ip );
    ulong                s = seg_lookup( ip );
    uchar t_country = t ? t->country_code_idx : (uchar)UCHAR_MAX;
    uint  t_city    = t ? t->city_name_idx    : (uint)UINT_MAX;
    if( FD_UNLIKELY( t_country!=seg_country[ s ] || t_city!=seg_city[ s ] ) )
      FD_LOG_ERR(( "MISMATCH ip=%08x trie=(%u,%u) seg=(%u,%u)", ip, t_country, t_city, (uint)seg_country[ s ], seg_city[ s ] ));
    checked++;
  }
  FD_LOG_NOTICE(( "agreement: %lu lookups match", checked ));

  /* Lookup throughput, same random sequence for both */
# define LOOKUP_CNT (10000000UL)
  ulong sink = 0UL;

  fd_rng_seq_set( rng, 0UL ); fd_rng_idx_set( rng, 0UL );
  t0 = fd_log_wallclock();
  for( ulong i=0UL; i<LOOKUP_CNT; i++ ) {
    geoip_node_t const * t = trie_lookup( fd_rng_uint( rng ) );
    sink += t ? t->country_code_idx : 0UL;
  }
  long trie_lookup_ns = fd_log_wallclock()-t0;

  fd_rng_seq_set( rng, 0UL ); fd_rng_idx_set( rng, 0UL );
  t0 = fd_log_wallclock();
  for( ulong i=0UL; i<LOOKUP_CNT; i++ ) {
    sink += seg_country[ seg_lookup( fd_rng_uint( rng ) ) ];
  }
  long seg_lookup_ns = fd_log_wallclock()-t0;

  FD_LOG_NOTICE(( "trie lookup: %.1f ns/op", (double)trie_lookup_ns/(double)LOOKUP_CNT ));
  FD_LOG_NOTICE(( "seg  lookup: %.1f ns/op", (double)seg_lookup_ns /(double)LOOKUP_CNT ));
  FD_LOG_NOTICE(( "sink %lu", sink ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
