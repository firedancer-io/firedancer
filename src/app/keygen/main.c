#include "../../util/fd_util.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"

#include <stdlib.h>
#include <sys/random.h>

static uchar *
fd_rng_b256( fd_rng_t * rng,
             uchar      r[static 32] ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng );
  u[1] = fd_rng_ulong( rng ); 
  u[2] = fd_rng_ulong( rng ); 
  u[3] = fd_rng_ulong( rng );
  return r;
}

struct fd_keygen_task_args {
  fd_rng_t rng[1];
  uchar prefix[32];
  ulong prefix_len;
  ulong rounds;
};
typedef struct fd_keygen_task_args fd_keygen_task_args_t;

static void 
fd_keygen_task( void * tpool,
                ulong  t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                void * args FD_PARAM_UNUSED,
                void * reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                ulong  l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                ulong  m0, ulong m1 FD_PARAM_UNUSED,
                ulong  n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_keygen_task_args_t * arg = (fd_keygen_task_args_t *)tpool + m0;

  for( ulong i = 0; i < arg->rounds; i++ ) {
    uchar private_key[32];
    uchar public_key[32];

    fd_rng_b256( arg->rng, private_key );

    fd_sha512_t _sha[1];
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

    fd_ed25519_public_from_private( public_key, private_key, sha );

    if( FD_UNLIKELY( memcmp( public_key, arg->prefix, arg->prefix_len ) == 0 ) ) {
      char pub[FD_BASE58_ENCODED_32_SZ];
      char priv[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32(public_key, NULL, pub);
      fd_base58_encode_32(private_key, NULL, priv);

      FD_LOG_NOTICE(("found key - public: %s, private: %s", pub, priv ));
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  // char const * wkspname     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",         NULL, NULL      );
  // ulong        pages        = fd_env_strip_cmdline_ulong( &argc, &argv, "--pages",        NULL,         5 );
  char const * prefix_b58   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--prefix",       NULL, NULL   );
  ulong        prefix_len   = fd_env_strip_cmdline_ulong( &argc, &argv, "--prefix-len",   NULL, 0      );
  ulong        rounds       = fd_env_strip_cmdline_ulong( &argc, &argv, "--rounds",       NULL, 1024   );

  FD_LOG_INFO(("rounds: %lu", rounds));
  // fd_wksp_t * wksp;
  // if(wkspname == NULL) {
  //   FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
  //   wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, pages, 0, "wksp", 0UL );
  // } else {
  //   fd_shmem_info_t shmem_info[1];
  //   if( FD_UNLIKELY( fd_shmem_info( wkspname, 0UL, shmem_info ) ) ) {
  //     FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wkspname ));
  //   }
  //   wksp = fd_wksp_attach( wkspname );
  // }

  ulong tcnt = fd_tile_cnt();
  uchar tpool_mem[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));
  fd_tpool_t * tpool = fd_tpool_init( tpool_mem, tcnt );
 
  if( tpool == NULL ) {
    FD_LOG_ERR(("failed to create thread pool"));
  }

  for( ulong i = 1; i <= tcnt-1; ++i ) {
    if( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL ) {
      FD_LOG_ERR(( "failed to launch worker" ));
    }
  }

  uchar prefix[32];
  fd_base58_decode_32(prefix_b58, prefix);

  uint seed;
  FD_TEST( getrandom( &seed, sizeof(uint), 0) == sizeof(uint) );

  fd_keygen_task_args_t task_args[tcnt];
  for( uint i = 0; i < tcnt; ++i ) {
    fd_keygen_task_args_t * task_arg = &task_args[i];
    fd_memcpy( task_arg->prefix, prefix, 32);
    task_arg->prefix_len = prefix_len;
    fd_rng_join( fd_rng_new( task_arg->rng, seed+i, 0UL ) );
    task_arg->rounds = rounds;
  }

  long timer = -fd_log_wallclock();
  fd_tpool_exec_all_taskq( tpool, 0, tcnt, fd_keygen_task, task_args, NULL, NULL, 1, 0, tcnt );
  timer += fd_log_wallclock();

  double secs_elapsed = ((double)timer) / 1000000000.0;
  double mega_keys_per_sec = ((double)rounds * (double)tcnt) / 1000000.0 / secs_elapsed;
  FD_LOG_NOTICE(("finished - secs: %6.3f, rate: %6.3f Mkeys / sec", secs_elapsed, mega_keys_per_sec ));

  fd_tpool_fini( tpool );
  fd_halt();
  return 0;
}
