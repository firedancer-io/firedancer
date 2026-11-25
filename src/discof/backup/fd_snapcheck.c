/* fd_snapcheck verifies a snapshot offline (development tool).

   Full snapshot: recomputes the accounts lthash over every account and
   compares it with the manifest's.  --dups also checks that no account
   appears twice.

     zstd -dc snapshot-*.tar.zst | fd_snapcheck [--dups]

   Incremental (--incr): its manifest lthash covers all accounts, i.e.
   the base full snapshot's lthash, minus the base versions of the
   accounts in the incremental, plus their incremental versions.  Stream
   the incremental, then its base:

     ( zstd -dc incr.tar.zst; zstd -dc full.tar.zst ) | fd_snapcheck --incr

   Both also report whether the status cache came before the accounts. */

#include "../restore/utils/fd_ssparse.h"
#include "../restore/utils/fd_ssmanifest_parser.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF_SZ (64UL<<20)

#define MAP_NAME     dup_map
#define MAP_T        dup_ele_t
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_NULL ((fd_pubkey_t){0})
#define MAP_KEY_INVAL(k) (!memcmp((k).uc,MAP_KEY_NULL.uc,32))
#define MAP_KEY_EQUAL(a,b) (!memcmp((a).uc,(b).uc,32))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(k,s) ((uint)(fd_ulong_load_8((k).uc)^(s)))
#define MAP_MEMOIZE 0
typedef struct { fd_pubkey_t key; } dup_ele_t;
#include "../../util/tmpl/fd_map_dynamic.c"

/* One snapshot stream: parse until the tar EOF, calling acc_fn per
   account and filling *manifest.  Reads from fd 0, leaving any bytes
   past the stream end in the buffer for the next stream. */

typedef void (*acc_fn_t)( void * ctx, fd_pubkey_t const * pk, fd_pubkey_t const * owner,
                          ulong lamports, int exec, uchar const * data, ulong data_len );

static uchar * g_buf;
static ulong   g_have, g_off;

static void
stream( fd_snapshot_manifest_t * manifest,
        int *                    status_first,
        acc_fn_t                 fn,
        void *                   ctx ) {
  fd_ssparse_t ssparse[1]; fd_ssparse_init( ssparse );
  static uchar mp_mem[ 1<<20 ] __attribute__((aligned(128)));
  FD_TEST( fd_ssmanifest_parser_footprint()<=sizeof(mp_mem) );
  fd_ssmanifest_parser_t * mp = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( mp_mem ) );
  fd_ssmanifest_parser_init( mp, manifest );
  static uchar acc[ FD_RUNTIME_ACC_SZ_MAX ];
  fd_pubkey_t pk, owner; ulong lamports=0UL, data_len=0UL, got=0UL; int exec=0;
  int manifest_done=0, done=0, status_seen=0;
  *status_first = 1;
  while( !done ) {
    if( g_off==g_have ) {
      long n = read( 0, g_buf, BUF_SZ );
      if( n<0 ) FD_LOG_ERR(( "read failed" ));
      if( n==0 ) break;
      g_have = (ulong)n; g_off = 0UL;
    }
    fd_ssparse_advance_result_t r[1];
    int res = fd_ssparse_advance( ssparse, g_buf+g_off, g_have-g_off, r );
    switch( res ) {
    case FD_SSPARSE_ADVANCE_ERROR: FD_LOG_ERR(( "snapshot parse error" ));
    case FD_SSPARSE_ADVANCE_AGAIN: break;
    case FD_SSPARSE_ADVANCE_APPENDVEC: fd_ssparse_appendvec_parse( ssparse ); break;
    case FD_SSPARSE_ADVANCE_MANIFEST:
    case FD_SSPARSE_ADVANCE_MANIFEST_DONE:
      FD_TEST( fd_ssmanifest_parser_consume( mp, r->manifest.data, r->manifest.data_sz )!=FD_SSMANIFEST_PARSER_ADVANCE_ERROR );
      if( res==FD_SSPARSE_ADVANCE_MANIFEST_DONE ) { FD_TEST( fd_ssmanifest_parser_fini( mp )==FD_SSMANIFEST_PARSER_ADVANCE_DONE ); manifest_done=1; }
      break;
    case FD_SSPARSE_ADVANCE_STATUS_CACHE: status_seen=1; break;
    case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
      if( !status_seen ) *status_first = 0;
      memcpy( pk.uc, r->account_header.pubkey, 32 ); memcpy( owner.uc, r->account_header.owner, 32 );
      lamports = r->account_header.lamports; data_len = r->account_header.data_len; exec = r->account_header.executable; got = 0UL;
      if( !data_len ) fn( ctx, &pk, &owner, lamports, exec, acc, 0UL );
      break;
    case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
      memcpy( acc+got, r->account_data.data, r->account_data.data_sz ); got += r->account_data.data_sz;
      if( got==data_len ) fn( ctx, &pk, &owner, lamports, exec, acc, data_len );
      break;
    case FD_SSPARSE_ADVANCE_DONE: done=1; break;
    default: FD_LOG_ERR(( "unexpected ssparse result %d", res ));
    }
    g_off += r->bytes_consumed;
  }
  FD_TEST( done );
  FD_TEST( manifest_done );
  FD_TEST( manifest->has_accounts_lthash );
  /* skip tar zero padding up to the next stream's first header byte */
  for(;;) {
    while( g_off<g_have && !g_buf[ g_off ] ) g_off++;
    if( g_off<g_have ) break;
    long n = read( 0, g_buf, BUF_SZ );
    if( n<=0 ) break;
    g_have = (ulong)n; g_off = 0UL;
  }
}

struct chk {
  fd_lthash_value_t sum[1];      /* over the first stream's accounts */
  ulong             acc_cnt;
  ulong             tomb_cnt;
  ulong             dup_cnt;
  dup_ele_t *       seen;        /* pubkeys of the first stream */
  int               base_pass;   /* incr: streaming the base */
  fd_lthash_value_t base_sub[1]; /* incr: base versions it replaces */
  ulong             base_hit;
};

static void
acc_cb( void * _c, fd_pubkey_t const * pk, fd_pubkey_t const * owner,
        ulong lamports, int exec, uchar const * data, ulong data_len ) {
  struct chk * c = _c;
  fd_lthash_value_t h[1];
  if( c->base_pass ) { /* only the accounts the incremental replaced */
    if( !dup_map_query( c->seen, *pk, NULL ) ) return;
    fd_hashes_account_lthash_simple( pk->uc, owner->uc, lamports, exec, data, data_len, h );
    fd_lthash_add( c->base_sub, h );
    c->base_hit++;
    return;
  }
  fd_hashes_account_lthash_simple( pk->uc, owner->uc, lamports, exec, data, data_len, h );
  fd_lthash_add( c->sum, h );
  c->acc_cnt++; c->tomb_cnt += !lamports;
  if( c->seen ) {
    if( dup_map_query( c->seen, *pk, NULL ) ) c->dup_cnt++;
    else FD_TEST( dup_map_insert( c->seen, *pk ) );
  }
}

static void
print_cmp( char const * what, fd_lthash_value_t const * got, uchar const * want ) {
  uchar h1[32], h2[32];
  fd_blake3_hash( got->bytes, sizeof(fd_lthash_value_t), h1 );
  fd_blake3_hash( want,       sizeof(fd_lthash_value_t), h2 );
  FD_BASE58_ENCODE_32_BYTES( h1, h1_b58 ); FD_BASE58_ENCODE_32_BYTES( h2, h2_b58 );
  printf( "%s computed blake3(lthash)=%s\n%s manifest blake3(lthash)=%s\n", what, h1_b58, what, h2_b58 );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  int   check_dups = fd_env_strip_cmdline_contains( &argc, &argv, "--dups" );
  int   incr       = fd_env_strip_cmdline_contains( &argc, &argv, "--incr" );
  ulong lg_slot    = fd_env_strip_cmdline_ulong( &argc, &argv, "--dup-lg", NULL, 32UL );

  g_buf = aligned_alloc( 64UL, BUF_SZ );
  static struct chk c[1];
  fd_lthash_zero( c->sum ); fd_lthash_zero( c->base_sub );
  if( check_dups || incr ) {
    c->seen = dup_map_join( dup_map_new( aligned_alloc( dup_map_align(), dup_map_footprint( (int)lg_slot ) ), (int)lg_slot, 0UL ) );
    FD_TEST( c->seen );
  }
  fd_snapshot_manifest_t * m0 = aligned_alloc( 64UL, sizeof(fd_snapshot_manifest_t) );
  int status_first;
  stream( m0, &status_first, acc_cb, c );
  printf( "slot=%lu accounts=%lu tombstones=%lu dups=%lu status_cache_before_accounts=%d\n",
          m0->slot, c->acc_cnt, c->tomb_cnt, c->dup_cnt, status_first );

  int ok;
  if( !incr ) {
    print_cmp( "full", c->sum, m0->accounts_lthash );
    ok = !memcmp( c->sum->bytes, m0->accounts_lthash, sizeof(fd_lthash_value_t) );
  } else {
    fd_snapshot_manifest_t * m1 = aligned_alloc( 64UL, sizeof(fd_snapshot_manifest_t) );
    c->base_pass = 1;
    int sf1;
    stream( m1, &sf1, acc_cb, c );
    printf( "base slot=%lu replaced_in_base=%lu\n", m1->slot, c->base_hit );
    /* incremental lthash = base - replaced base versions + incremental versions */
    fd_lthash_value_t want[1];
    fd_memcpy( want->bytes, m1->accounts_lthash, sizeof(fd_lthash_value_t) );
    fd_lthash_sub( want, c->base_sub );
    fd_lthash_add( want, c->sum );
    print_cmp( "incr", want, m0->accounts_lthash );
    ok = !memcmp( want->bytes, m0->accounts_lthash, sizeof(fd_lthash_value_t) );
  }
  printf( "%s\n", ok ? "LTHASH MATCH" : "LTHASH MISMATCH" );
  fd_halt();
  return ok ? 0 : 1;
}
