#include "../fd_ballet.h"
#include "fd_murmur3.h"

struct fd_murmur3_32_test_vector {
  uint         hash;
  char const * msg;
  ulong        sz;
  uint         seed;
};

typedef struct fd_murmur3_32_test_vector fd_murmur3_32_test_vector_t;

static fd_murmur3_32_test_vector_t const fd_murmur3_32_test_vector[] = {
  { 0xb6fc1a11U, "abort",                                  5UL, 0 },
  { 0x686093bbU, "sol_panic_",                            10UL, 0 },
  { 0x207559bdU, "sol_log_",                               8UL, 0 },
  { 0x5c2a3178U, "sol_log_64_",                           11UL, 0 },
  { 0x52ba5096U, "sol_log_compute_units_",                22UL, 0 },
  { 0x7ef088caU, "sol_log_pubkey",                        14UL, 0 },
  { 0x9377323cU, "sol_create_program_address",            26UL, 0 },
  { 0x48504a38U, "sol_try_find_program_address",          28UL, 0 },
  { 0x11f49d86U, "sol_sha256",                            10UL, 0 },
  { 0xd7793abbU, "sol_keccak256",                         13UL, 0 },
  { 0x17e40350U, "sol_secp256k1_recover",                 21UL, 0 },
  { 0x174c5122U, "sol_blake3",                            10UL, 0 },
  { 0xaa2607caU, "sol_curve_validate_point",              24UL, 0 },
  { 0xdd1c41a6U, "sol_curve_group_op",                    18UL, 0 },
  { 0xd56b5fe9U, "sol_get_clock_sysvar",                  20UL, 0 },
  { 0x23a29a61U, "sol_get_epoch_schedule_sysvar",         29UL, 0 },
  { 0x3b97b73cU, "sol_get_fees_sysvar",                   19UL, 0 },
  { 0xbf7188f6U, "sol_get_rent_sysvar",                   19UL, 0 },
  { 0x717cc4a3U, "sol_memcpy_",                           11UL, 0 },
  { 0x434371f8U, "sol_memmove_",                          12UL, 0 },
  { 0x5fdcde31U, "sol_memcmp_",                           11UL, 0 },
  { 0x3770fb22U, "sol_memset_",                           11UL, 0 },
  { 0xa22b9c85U, "sol_invoke_signed_c",                   19UL, 0 },
  { 0xd7449092U, "sol_invoke_signed_rust",                22UL, 0 },
  { 0x83f00e8fU, "sol_alloc_free_",                       15UL, 0 },
  { 0xa226d3ebU, "sol_set_return_data",                   19UL, 0 },
  { 0x5d2245e4U, "sol_get_return_data",                   19UL, 0 },
  { 0x7317b434U, "sol_log_data",                          12UL, 0 },
  { 0xadb8efc8U, "sol_get_processed_sibling_instruction", 37UL, 0 },
  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( fd_murmur3_32_test_vector_t const * vec = fd_murmur3_32_test_vector; vec->msg; vec++ ) {
    char const *  msg      = vec->msg;
    ulong         sz       = vec->sz;
    uint          seed     = vec->seed;
    uint          expected = vec->hash;

    uint hash = fd_murmur3_32( msg, sz, seed );
    if( FD_UNLIKELY( hash!=expected ) )
      FD_LOG_ERR(( "FAIL (sz %lu)"
                   "\n\tGot      %08x"
                   "\n\tExpected %08x"
                   "\n\t\t", sz, hash, expected ));
  }

  for( uint i=0U; i<10U<<17; i++ ) {
    ulong pc = i;
    uint  hash = fd_murmur3_32( &pc, 8UL, 0U );
    FD_TEST( fd_pchash( i )==hash );
    FD_TEST( fd_pchash_inverse( hash )==i );
  }

  FD_LOG_NOTICE(( "Benchmarking small inputs" ));

  do {
    /* warmup */
    uint hash = 42U;
    for( ulong i=0UL; i<100000UL; i++ ) {
      uint x[2] = { (uint)i, hash };
      hash = fd_murmur3_32( &x, 8UL, 0 );
    }

    /* for real */
    ulong bench_cnt = 100000000UL;
    long dt = -fd_log_wallclock();
    for( ulong i=0UL; i<bench_cnt; i++ ) {
      uint x[2] = { (uint)i, hash };
      hash = fd_murmur3_32( &x, 8UL, 0 );
    }
   FD_COMPILER_UNPREDICTABLE( hash );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%.3f ns/hash (sz 8)", (double)((float)dt / (float)bench_cnt) ));
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking hashrate (generic)" ));

  do {
    uchar msg[ 1024UL ];
    ulong sz = 1024UL;
    for( ulong i=0UL; i<sz; i+=8UL )
      FD_STORE( ulong, msg+i, fd_rng_ulong( rng ) );

    /* warmup */
    for( ulong i=0UL; i<10000UL; i++ ) {
      uint hash = fd_murmur3_32( &msg, sz, 0U );
      FD_COMPILER_FORGET( hash );
    }

    /* for real */
    ulong bench_cnt = 1000000UL;
    long dt = -fd_log_wallclock();
    for( ulong i=0UL; i<bench_cnt; i++ ) {
      uint hash = fd_murmur3_32( &msg, sz, 0U );
      __asm__( "" : "=m" (*msg) : "r" (hash) : "cc" );
    }
    dt += fd_log_wallclock();
    double gbps = ((double)(8*bench_cnt*sz)) / ((double)dt);
    FD_LOG_NOTICE(( "~%6.3f GiB/s (sz %4lu)", gbps, sz ));
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking hashrate (pchash)" ));

  do {
    /* warmup */
    uint hash = 42U;
    for( ulong i=0UL; i<100000UL; i++ )
      hash = fd_pchash( hash );

    /* for real */
    ulong bench_cnt = 100000000UL;
    long dt = -fd_log_wallclock();
    for( ulong i=0UL; i<bench_cnt; i++ )
      hash = fd_pchash( hash );
    FD_COMPILER_UNPREDICTABLE( hash );

    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%.3f ns/pchash", (double)((float)dt / (float)bench_cnt) ));
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking hashrate (pchash_inverse)" ));

  do {
    /* warmup */
    uint hash = 42U;
    for( ulong i=0UL; i<100000UL; i++ )
      hash = fd_pchash_inverse( hash );

    /* for real */
    ulong bench_cnt = 100000000UL;
    long dt = -fd_log_wallclock();
    for( ulong i=0UL; i<bench_cnt; i++ )
      hash = fd_pchash_inverse( hash );
    FD_COMPILER_UNPREDICTABLE( hash );

    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%.3f ns/pchash", (double)((float)dt / (float)bench_cnt) ));
  } while(0);

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

