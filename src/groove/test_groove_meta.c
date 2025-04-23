#include "fd_groove.h"

#define SHMEM_MAX (1UL<<20)

static FD_TL uchar shmem[ SHMEM_MAX ];
static FD_TL ulong shmem_cnt = 0UL;

static void *
shmem_alloc( ulong a,
             ulong s ) {
  uchar * m  = (uchar *)fd_ulong_align_up( (ulong)(shmem + shmem_cnt), a );
  shmem_cnt = (ulong)((m + s) - shmem);
  FD_TEST( shmem_cnt <= SHMEM_MAX );
  return (void *)m;
}

static fd_groove_meta_map_t * tile_map;
static ulong                  tile_iter_cnt;
static ulong                  tile_go;

static int
tile_main( int     argc,
           char ** argv ) {

  /* Init local tile context */

  fd_groove_meta_map_t * map      = tile_map;
  ulong                  iter_cnt = tile_iter_cnt;
  ulong                  tile_idx = (ulong)(uint)argc;
  ulong                  tile_cnt = (ulong)argv;

  fd_groove_meta_t * ele0    = (fd_groove_meta_t *)fd_groove_meta_map_shele( map );
  ulong              ele_max = fd_groove_meta_map_ele_max( map );
  ulong              seed    = fd_groove_meta_map_seed( map );

  fd_groove_meta_t sentinel[1];

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  ulong global_prefix = 0x0123456789abcdefUL;
  ulong local_key     = 0U;

  ulong             save    = shmem_cnt;
  fd_groove_key_t * map_key = shmem_alloc( alignof(fd_groove_key_t), ele_max*sizeof(fd_groove_key_t) );
  ulong             map_cnt = 0UL;

  ulong lock_max = fd_groove_meta_map_lock_max();
  ulong lock_cnt = fd_groove_meta_map_lock_cnt( map );

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Hammer the map with all manners of concurrent operations */

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (local map_cnt %lu)", iter_idx, iter_cnt, map_cnt ));
      if( tile_cnt==1UL ) FD_TEST( !fd_groove_meta_map_verify( map ) );
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r = fd_rng_ulong( rng );

    int op       = (int)(r & 15UL);           r >>= 4;
    int flags    = (int)r;                    r >>= 32;
    int blocking = !!(flags & FD_MAP_FLAG_BLOCKING);
    int use_hint = !!(flags & FD_MAP_FLAG_USE_HINT);
    int rdonly   = !!(flags & FD_MAP_FLAG_RDONLY);

    fd_groove_meta_map_query_t query[1];

    switch( op ) {

    case 0: { /* blocking read / bad insert (i.e. key already in map) */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong             idx  = fd_rng_ulong_roll( rng, map_cnt );
      fd_groove_key_t * key  = map_key + idx;
      ulong             memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                err = fd_groove_meta_map_prepare( map, key, sentinel, query, flags );
      fd_groove_meta_t * ele = fd_groove_meta_map_query_ele( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max                   );
        FD_TEST( fd_groove_key_eq( &ele->key, key )          );
        FD_TEST( fd_groove_meta_bits_used( ele->bits )       );
        FD_TEST( ele->val_off==(key->ul[0] ^ (ele->bits>>1)) );

        fd_groove_meta_map_cancel( query );
      }

      break;
    }

    case 1: { /* good insert (i.e. key not already in map) */
      fd_groove_key_t key[1]; fd_groove_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_groove_meta_map_key_hash( key, seed );
      ulong           mod  = 0UL;

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                err = fd_groove_meta_map_prepare( map, key, sentinel, query, flags );
      fd_groove_meta_t * ele = fd_groove_meta_map_query_ele( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max              );
        FD_TEST( !fd_groove_meta_bits_used( ele->bits ) );

        ele->key     = *key;
        ele->val_off = key->ul[0] ^ mod;
        ele->bits    = 1UL | (mod<<1);

        fd_groove_meta_map_publish( query );

        map_key[ map_cnt++ ] = *key;
        local_key++;
      }

      break;
    }

    case 2: { /* bad remove (i.e. key not already in map) */
      fd_groove_key_t key[1]; fd_groove_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int err = fd_groove_meta_map_remove( map, key, query, flags );

      if( FD_LIKELY( err ) ) {
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_KEY );
      }

      break;
    }

    case 3: { /* good remove (i.e. key already in map) */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong             idx  = fd_rng_ulong_roll( rng, map_cnt );
      fd_groove_key_t * key  = map_key + idx;
      ulong             memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int err = fd_groove_meta_map_remove( map, key, query, flags );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        map_key[ idx ] = map_key[ --map_cnt ];
      }

      break;
    }

    case 4: { /* bad modify (i.e. key not already in map) */
      fd_groove_key_t key[1]; fd_groove_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                err = fd_groove_meta_map_prepare( map, key, sentinel, query, flags );
      fd_groove_meta_t * ele = fd_groove_meta_map_query_ele( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max              );
        FD_TEST( !fd_groove_meta_bits_used( ele->bits ) );

        fd_groove_meta_map_cancel( query );
      }

      break;
    }

    case 5: { /* good modify (i.e. key already in map) */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong             idx  = fd_rng_ulong_roll( rng, map_cnt );
      fd_groove_key_t * key  = map_key + idx;
      ulong             memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                err = fd_groove_meta_map_prepare( map, key, sentinel, query, flags );
      fd_groove_meta_t * ele = fd_groove_meta_map_query_ele( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );
        ulong mod = ele->bits >> 1;
        FD_TEST( fd_groove_key_eq( &ele->key, key )    );
        FD_TEST( ele->val_off==(key->ul[0] ^ mod)      );
        FD_TEST( fd_groove_meta_bits_used( ele->bits ) );

        mod++;

        ele->val_off = key->ul[0] ^ mod;
        ele->bits    = 1UL | (mod<<1);

        fd_groove_meta_map_publish( query );
      }

      break;
    }

    case 6: { /* bad query (i.e. key not already in map) */
      fd_groove_key_t key[1]; fd_groove_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                      err = fd_groove_meta_map_query_try( map, key, sentinel, query, flags );
      fd_groove_meta_t const * ele = fd_groove_meta_map_query_ele_const( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
      else                        FD_TEST( err==FD_MAP_ERR_KEY );

      break;
    }

    case 7: { /* good query */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong             idx  = fd_rng_ulong_roll( rng, map_cnt );
      fd_groove_key_t * key  = map_key + idx;
      ulong             memo = fd_groove_meta_map_key_hash( key, seed );

      if( use_hint ) {
        fd_groove_meta_map_hint( map, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );
      }

      int                      err = fd_groove_meta_map_query_try( map, key, sentinel, query, flags );
      fd_groove_meta_t const * ele = fd_groove_meta_map_query_ele_const( query );
      FD_TEST( memo==fd_groove_meta_map_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );

        fd_groove_key_t spec_key = ele->key;
        ulong           spec_mod = ele->bits >> 1;
        ulong           spec_val = ele->val_off;

        err = fd_groove_meta_map_query_test( query );

        if( FD_UNLIKELY( err ) ) {
          FD_TEST( err==FD_MAP_ERR_AGAIN );
          FD_TEST( tile_cnt>1UL          );
        } else {
          FD_TEST( fd_groove_key_eq( &spec_key, key ) );
          FD_TEST( spec_val==(key->ul[0] ^ spec_mod)  );
        }
      }

      break;
    }

    case 8: { /* parallel iteration */
      ushort version[ lock_max ];

      ulong range_start = fd_rng_ulong_roll( rng, lock_cnt );
      ulong range_cnt   = fd_ulong_min( fd_rng_coin_tosses( rng ), lock_cnt );

      int err = fd_groove_meta_map_lock_range( map, range_start, range_cnt, flags, version );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong lock_idx = range_start;
        for( ulong lock_rem=range_cnt; lock_rem; lock_rem-- ) {
          ulong e0 = fd_groove_meta_map_lock_ele0( map, lock_idx );
          ulong e1 = fd_groove_meta_map_lock_ele1( map, lock_idx );

          FD_TEST( e0< e1      );
          FD_TEST( e1<=ele_max );

          for( ulong ele_idx=e0; ele_idx<e1; ele_idx++ ) {
            fd_groove_meta_t * ele = ele0 + ele_idx;
            if( !fd_groove_meta_bits_used( ele->bits ) ) continue;

            ulong mod = ele->bits >> 1;

            FD_TEST( ele->val_off==(ele->key.ul[0] ^ mod) );

            if( !rdonly ) {
              mod++;
              ele->bits    = 1UL | (mod<<1);
              ele->val_off = ele->key.ul[0] ^ mod;
            }
          }

          lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
        }

        fd_groove_meta_map_unlock_range( map, range_start, range_cnt, version );

      }

      break;
    }

    case 9: { /* parallel memo iteration */
      ulong memo;
      ulong iter_min;
      if( FD_UNLIKELY( !map_cnt ) ) { /* pick a memo not likely in map */
        memo     = fd_rng_ulong( rng );
        iter_min = 0UL;
      } else { /* pick a memo in map at least once */
        ulong             idx = fd_rng_ulong_roll( rng, map_cnt );
        fd_groove_key_t * key = map_key + idx;
        memo     = fd_groove_meta_map_key_hash( key, seed );
        iter_min = 1UL;
      }

      fd_groove_meta_map_iter_t iter[1];
      int err = fd_groove_meta_map_iter_init( map, memo, flags, iter );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong iter_cnt = 0UL;
        while( !fd_groove_meta_map_iter_done( iter ) ) {
          fd_groove_meta_t * ele = fd_groove_meta_map_iter_ele( iter );

          FD_TEST( (ulong)(ele-ele0)<ele_max );

          ulong mod = ele->bits >> 1;

          FD_TEST( fd_groove_meta_map_key_hash( &ele->key, seed )==memo );
          FD_TEST( fd_groove_meta_bits_used( ele->bits )                );
          FD_TEST( ele->val_off==(ele->key.ul[0] ^ mod)                 );

          if( !rdonly ) {
            mod++;
            ele->bits    = 1UL | (mod<<1);
            ele->val_off = ele->key.ul[0] ^ mod;
          }

          iter_cnt++;

          FD_TEST( fd_groove_meta_map_iter_next( iter )==iter );
        }

        FD_TEST( fd_groove_meta_map_iter_fini( iter )==iter );

        FD_TEST( iter_cnt>=iter_min );
      }

      break;
    }

    default:
      break;
    }
  }

  /* Clean up for the next text battery */

  for( ulong map_idx=0UL; map_idx<map_cnt; map_idx++ )
    FD_TEST( !fd_groove_meta_map_remove( map, map_key + map_idx, NULL, FD_MAP_FLAG_BLOCKING ) );

  shmem_cnt = save;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",   NULL, 4096UL                                      );
  ulong lock_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--lock-cnt",  NULL, fd_groove_meta_map_lock_cnt_est ( ele_max ) );
  ulong probe_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--probe-max", NULL, fd_groove_meta_map_probe_max_est( ele_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL, 1234UL                                      );
  ulong iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt",  NULL, 10000000UL                                  );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --lock-cnt %lu --probe-max %lu --seed %lu --iter-cnt %lu)",
                  ele_max, lock_cnt, probe_max, seed, iter_cnt ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  for( ulong rem=100000000UL; rem; rem-- ) {
    ulong r = fd_rng_ulong( rng );

    int   used    = fd_groove_meta_bits_used   ( r ); FD_TEST( (0<=used) & (used<=1) );
    int   cold    = fd_groove_meta_bits_cold   ( r ); FD_TEST( (0<=cold) & (cold<=1) );
    int   hot     = fd_groove_meta_bits_hot    ( r ); FD_TEST( (0<=hot ) & (hot <=1) );
    ulong val_sz  = fd_groove_meta_bits_val_sz ( r ); FD_TEST( val_sz <(1UL<<24)     );
    ulong val_max = fd_groove_meta_bits_val_max( r ); FD_TEST( val_max<(1UL<<24)     );

    int s = (int)((r>>3) & 31UL);

    ulong bits = fd_groove_meta_bits( used<<s, cold<<s, hot<<s, val_sz, val_max );

    FD_TEST( fd_groove_meta_bits_used   ( bits )==used    );
    FD_TEST( fd_groove_meta_bits_cold   ( bits )==cold    );
    FD_TEST( fd_groove_meta_bits_hot    ( bits )==hot     );
    FD_TEST( fd_groove_meta_bits_val_sz ( bits )==val_sz  );
    FD_TEST( fd_groove_meta_bits_val_max( bits )==val_max );
  }

  FD_LOG_NOTICE(( "Creating groove meta store" ));

  void * shele = shmem_alloc( alignof(fd_groove_meta_t), ele_max*sizeof(fd_groove_meta_t) );
  memset( shele, 0, ele_max*sizeof(fd_groove_meta_t) );

  FD_LOG_NOTICE(( "Creating groove meta map" ));

  ulong  align     = fd_groove_meta_map_align();
  ulong  footprint = fd_groove_meta_map_footprint( ele_max, lock_cnt, probe_max );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Unsupported --ele-max / --lock-cnt / --probe-max" ));
  void * shmap = shmem_alloc( align, footprint );

  FD_TEST( fd_groove_meta_map_new( shmap, ele_max, lock_cnt, probe_max, seed )==shmap );

  FD_LOG_NOTICE(( "Joining groove meta map" ));

  fd_groove_meta_map_t map[1]; fd_groove_meta_map_join( map, shmap, shele );

  tile_map      = map;
  tile_iter_cnt = iter_cnt;

  ulong tile_max = fd_tile_cnt();
  for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

    FD_LOG_NOTICE(( "Testing concurrent operation on %lu tiles", tile_cnt ));

    /* FIXME: use tpool here */

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 0;
    FD_COMPILER_MFENCE();

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
      fd_tile_exec_new( tile_idx, tile_main, (int)(uint)tile_idx, (char **)tile_cnt );

    fd_log_sleep( (long)0.1e9 );

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 1;
    FD_COMPILER_MFENCE();

    tile_main( 0, (char **)tile_cnt );

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

    FD_TEST( !fd_groove_meta_map_verify( map ) );
  }

  FD_LOG_NOTICE(( "Leave groove meta map" ));

  FD_TEST( fd_groove_meta_map_leave( map )==map );

  FD_LOG_NOTICE(( "Destroying groove meta map" ));

  FD_TEST( fd_groove_meta_map_delete( shmap )==shmap );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
