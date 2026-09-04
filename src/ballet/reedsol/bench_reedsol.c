#include "fd_reedsol.h"

#include <string.h>

#define BENCH_SHRED_CNT (32UL)
#define BENCH_SHRED_MAX (2048UL)

static uchar data_mem  [ BENCH_SHRED_CNT*BENCH_SHRED_MAX ] __attribute__((aligned(FD_REEDSOL_ALIGN)));
static uchar parity_mem[ BENCH_SHRED_CNT*BENCH_SHRED_MAX ] __attribute__((aligned(FD_REEDSOL_ALIGN)));
static uchar data_ref  [ BENCH_SHRED_CNT*BENCH_SHRED_MAX ] __attribute__((aligned(FD_REEDSOL_ALIGN)));
static uchar parity_ref[ BENCH_SHRED_CNT*BENCH_SHRED_MAX ] __attribute__((aligned(FD_REEDSOL_ALIGN)));
static uchar rs_mem[ FD_REEDSOL_FOOTPRINT ]                 __attribute__((aligned(FD_REEDSOL_ALIGN)));

enum bench_mode {
  BENCH_ENCODE,
  BENCH_RECOVER_NONE,
  BENCH_RECOVER_FIRST,
  BENCH_RECOVER_PARITY,
  BENCH_RECOVER_DATA,
  BENCH_RECOVER_EVEN
};

static inline void
encode_once( uchar * const data  [ static BENCH_SHRED_CNT ],
             uchar * const parity[ static BENCH_SHRED_CNT ],
             ulong         shred_sz ) {
  fd_reedsol_t * rs = fd_reedsol_encode_init( rs_mem, shred_sz );
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) fd_reedsol_encode_add_data_shred  ( rs, data  [ i ] );
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) fd_reedsol_encode_add_parity_shred( rs, parity[ i ] );
  fd_reedsol_encode_fini( rs );
}

static inline int
recover_once( uchar * const data  [ static BENCH_SHRED_CNT ],
              uchar * const parity[ static BENCH_SHRED_CNT ],
              ulong         shred_sz,
              enum bench_mode mode ) {
  fd_reedsol_t * rs = fd_reedsol_recover_init( rs_mem, shred_sz );
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) {
    int erased = (mode==BENCH_RECOVER_DATA) | ((mode==BENCH_RECOVER_EVEN) & !(i&1UL));
    if( erased ) fd_reedsol_recover_add_erased_shred( rs, 1, data[ i ] );
    else         fd_reedsol_recover_add_rcvd_shred  ( rs, 1, data[ i ] );
  }
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) {
    int erased = (mode==BENCH_RECOVER_PARITY) | (((mode==BENCH_RECOVER_FIRST) | (mode==BENCH_RECOVER_EVEN)) & !(i&1UL));
    if( erased ) fd_reedsol_recover_add_erased_shred( rs, 0, parity[ i ] );
    else         fd_reedsol_recover_add_rcvd_shred  ( rs, 0, parity[ i ] );
  }
  return fd_reedsol_recover_fini( rs );
}

static enum bench_mode
parse_mode( char const * mode ) {
  if( !strcmp( mode, "encode"         ) ) return BENCH_ENCODE;
  if( !strcmp( mode, "recover-none"   ) ) return BENCH_RECOVER_NONE;
  if( !strcmp( mode, "recover-first"  ) ) return BENCH_RECOVER_FIRST;
  if( !strcmp( mode, "recover-parity" ) ) return BENCH_RECOVER_PARITY;
  if( !strcmp( mode, "recover-data"   ) ) return BENCH_RECOVER_DATA;
  if( !strcmp( mode, "recover-even"   ) ) return BENCH_RECOVER_EVEN;
  FD_LOG_ERR(( "unknown --mode %s", mode ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * mode_cstr = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mode",     NULL, "encode" );
  ulong        iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt", NULL, 100000UL );
  ulong        shred_sz  = fd_env_strip_cmdline_ulong( &argc, &argv, "--shred-sz", NULL, 1024UL );
  if( FD_UNLIKELY( !iter_cnt ) ) FD_LOG_ERR(( "--iter-cnt must be positive" ));
  if( FD_UNLIKELY( (shred_sz<32UL) | (shred_sz>BENCH_SHRED_MAX) ) )
    FD_LOG_ERR(( "--shred-sz must be in [32,%lu]", BENCH_SHRED_MAX ));
  enum bench_mode mode = parse_mode( mode_cstr );

  uchar * data  [ BENCH_SHRED_CNT ];
  uchar * parity[ BENCH_SHRED_CNT ];
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) {
    data  [ i ] = data_mem   + i*shred_sz;
    parity[ i ] = parity_mem + i*shred_sz;
  }

  fd_rng_t rng[ 1 ];
  fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  for( ulong i=0UL; i<BENCH_SHRED_CNT*shred_sz; i++ ) data_mem[ i ] = fd_rng_uchar( rng );
  encode_once( data, parity, shred_sz );
  fd_memcpy( data_ref,   data_mem,   BENCH_SHRED_CNT*shred_sz );
  fd_memcpy( parity_ref, parity_mem, BENCH_SHRED_CNT*shred_sz );

  if( mode!=BENCH_ENCODE ) {
    if( mode==BENCH_RECOVER_DATA   ) fd_memset( data_mem,   0, BENCH_SHRED_CNT*shred_sz );
    if( mode==BENCH_RECOVER_PARITY ) fd_memset( parity_mem, 0, BENCH_SHRED_CNT*shred_sz );
    if( (mode==BENCH_RECOVER_FIRST) | (mode==BENCH_RECOVER_EVEN) ) for( ulong i=0UL; i<BENCH_SHRED_CNT; i+=2UL ) {
      if( mode==BENCH_RECOVER_EVEN ) fd_memset( data[ i ], 0, shred_sz );
      fd_memset( parity[ i ], 0, shred_sz );
    }
    FD_TEST( recover_once( data, parity, shred_sz, mode )==FD_REEDSOL_SUCCESS );
    FD_TEST( !memcmp( data_mem,   data_ref,   BENCH_SHRED_CNT*shred_sz ) );
    FD_TEST( !memcmp( parity_mem, parity_ref, BENCH_SHRED_CNT*shred_sz ) );
    if( (mode==BENCH_RECOVER_NONE) | (mode==BENCH_RECOVER_FIRST) ) {
      ulong corrupt_idx = fd_ulong_if( mode==BENCH_RECOVER_FIRST, 1UL, 0UL );
      parity[ corrupt_idx ][ 0 ] ^= 1U;
      FD_TEST( recover_once( data, parity, shred_sz, mode )==FD_REEDSOL_ERR_CORRUPT );
      parity[ corrupt_idx ][ 0 ] ^= 1U;
    }
  }

  ulong warmup_cnt = fd_ulong_min( iter_cnt, 10000UL );
  for( ulong i=0UL; i<warmup_cnt; i++ ) {
    if( mode==BENCH_ENCODE ) encode_once( data, parity, shred_sz );
    else FD_TEST( recover_once( data, parity, shred_sz, mode )==FD_REEDSOL_SUCCESS );
  }

  long then = fd_log_wallclock();
  for( ulong i=0UL; i<iter_cnt; i++ ) {
    if( mode==BENCH_ENCODE ) encode_once( data, parity, shred_sz );
    else FD_TEST( recover_once( data, parity, shred_sz, mode )==FD_REEDSOL_SUCCESS );
  }
  long elapsed = fd_log_wallclock() - then;

  volatile uchar checksum = 0U;
  for( ulong i=0UL; i<BENCH_SHRED_CNT; i++ ) checksum ^= data[ i ][ 0 ] ^ parity[ i ][ 0 ];
  FD_LOG_NOTICE(( "mode %s shred_sz %lu iter_cnt %lu: %.3f ns/call, %.3f GiB/s input, checksum %u",
                  mode_cstr, shred_sz, iter_cnt,
                  (double)elapsed/(double)iter_cnt,
                  (double)(iter_cnt*BENCH_SHRED_CNT*shred_sz)/((double)elapsed*1.073741824),
                  (uint)checksum ));

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
