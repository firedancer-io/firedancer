#include "../fd_vinyl.h"

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

static fd_vinyl_meta_t * tile_meta;
static ulong             tile_iter_cnt;
static ulong             tile_go;

static int
tile_main( int     argc,
           char ** argv ) {

  /* Init local tile context */

  fd_vinyl_meta_t * meta     = tile_meta;
  ulong             iter_cnt = tile_iter_cnt;
  ulong             tile_idx = (ulong)(uint)argc;
  ulong             tile_cnt = (ulong)argv;

  fd_vinyl_meta_ele_t * ele0    = (fd_vinyl_meta_ele_t *)fd_vinyl_meta_shele( meta );
  ulong                 ele_max = fd_vinyl_meta_ele_max( meta );
  ulong                 seed    = fd_vinyl_meta_seed( meta );

  fd_vinyl_meta_ele_t sentinel[1];

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  ulong global_prefix = 0x0123456789abcdefUL;
  ulong local_key     = 0U;

  ulong            save     = shmem_cnt;
  fd_vinyl_key_t * meta_key = shmem_alloc( alignof(fd_vinyl_key_t), ele_max*sizeof(fd_vinyl_key_t) );
  ulong            meta_cnt = 0UL;

  ulong lock_max = fd_vinyl_meta_lock_max();
  ulong lock_cnt = fd_vinyl_meta_lock_cnt( meta );

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Hammer the meta with all manners of concurrent operations */

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (local meta_cnt %lu)", iter_idx, iter_cnt, meta_cnt ));
      if( tile_cnt==1UL ) FD_TEST( !fd_vinyl_meta_verify( meta ) );
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r = fd_rng_ulong( rng );

    int op       = (int)(r & 15UL);           r >>= 4;
    int flags    = (int)r;                    r >>= 32;
    int blocking = !!(flags & FD_MAP_FLAG_BLOCKING);
    int use_hint = !!(flags & FD_MAP_FLAG_USE_HINT);
    int rdonly   = !!(flags & FD_MAP_FLAG_RDONLY);

    fd_vinyl_meta_query_t query[1];

    switch( op ) {

    case 0: { /* blocking read / bad insert (i.e. key already in meta) */
      if( FD_UNLIKELY( !meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, meta_cnt );
      fd_vinyl_key_t * key  = meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                   err = fd_vinyl_meta_prepare( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max              );
        FD_TEST( ele->memo==memo                        );
        FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );
        FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );

        ulong mod = ele->phdr.info.ul[0];

        FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
        FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
        FD_TEST( ele->line_idx        == ULONG_MAX          );

        fd_vinyl_meta_cancel( query );
      }

      break;
    }

    case 1: { /* good insert (i.e. key not already in meta) */
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong          memo = fd_vinyl_key_memo( seed, key );
      ulong          mod  = 0UL;

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                   err = fd_vinyl_meta_prepare( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max        );
        FD_TEST( !fd_vinyl_meta_ele_in_use( ele ) );

        ele->memo            = memo;
        ele->phdr.ctl        = 1UL;
        ele->phdr.key        = *key;
        ele->phdr.info.ul[0] = mod;
        ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
        ele->seq             = (key->ul[0] ^ mod);
        ele->line_idx        = ULONG_MAX;

        fd_vinyl_meta_publish( query );

        meta_key[ meta_cnt++ ] = *key;
        local_key++;
      }

      break;
    }

    case 2: { /* bad remove (i.e. key not already in meta) */
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int err = fd_vinyl_meta_remove( meta, key, query, flags );

      if( FD_LIKELY( err ) ) {
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_KEY );
      }

      break;
    }

    case 3: { /* good remove (i.e. key already in meta) */
      if( FD_UNLIKELY( !meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, meta_cnt );
      fd_vinyl_key_t * key  = meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int err = fd_vinyl_meta_remove( meta, key, query, flags );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        meta_key[ idx ] = meta_key[ --meta_cnt ];
      }

      break;
    }

    case 4: { /* bad modify (i.e. key not already in meta) */
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                   err = fd_vinyl_meta_prepare( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                          FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max        );
        FD_TEST( !fd_vinyl_meta_ele_in_use( ele ) );

        fd_vinyl_meta_cancel( query );
      }

      break;
    }

    case 5: { /* good modify (i.e. key already in meta) */
      if( FD_UNLIKELY( !meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, meta_cnt );
      fd_vinyl_key_t * key  = meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                   err = fd_vinyl_meta_prepare( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );
        ulong mod = ele->seq;
        FD_TEST( ele->memo==memo                        );
        FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );
        FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );
        FD_TEST( ele->line_idx==ULONG_MAX               );

        mod++;

        ele->phdr.info.ul[0] = mod;
        ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
        ele->seq             = (key->ul[0] ^ mod);
        ele->line_idx        = ULONG_MAX;

        fd_vinyl_meta_publish( query );
      }

      break;
    }

    case 6: { /* bad query (i.e. key not already in meta) */
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong           memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                         err = fd_vinyl_meta_query_try( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t const * ele = fd_vinyl_meta_query_ele_const( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
      else                        FD_TEST( err==FD_MAP_ERR_KEY );

      break;
    }

    case 7: { /* good query */
      if( FD_UNLIKELY( !meta_cnt ) ) break;
      ulong             idx  = fd_rng_ulong_roll( rng, meta_cnt );
      fd_vinyl_key_t * key   = meta_key + idx;
      ulong             memo = fd_vinyl_key_memo( seed, key );

      if( use_hint ) {
        fd_vinyl_meta_hint( meta, key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );
      }

      int                         err = fd_vinyl_meta_query_try( meta, key, sentinel, query, flags );
      fd_vinyl_meta_ele_t const * ele = fd_vinyl_meta_query_ele_const( query );
      FD_TEST( memo==fd_vinyl_meta_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );

        ulong mod = ele->phdr.info.ul[0];

        int spec_good = ( ele->memo==memo                            )
                      & ( fd_vinyl_meta_ele_in_use( ele )            )
                      & ( fd_vinyl_key_eq( &ele->phdr.key, key )     )
                      & ( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) )
                      & ( ele->seq             == (key->ul[0] ^ mod) )
                      & ( ele->line_idx        == ULONG_MAX          );

        err = fd_vinyl_meta_query_test( query );

        if( FD_UNLIKELY( err ) ) {
          FD_TEST( err==FD_MAP_ERR_AGAIN );
          FD_TEST( tile_cnt>1UL          );
        } else {
          FD_TEST( spec_good             );
        }
      }

      break;
    }

    case 8: { /* parallel iteration */
      ulong version[ lock_max ];

      ulong range_start = fd_rng_ulong_roll( rng, lock_cnt );
      ulong range_cnt   = fd_ulong_min( fd_rng_coin_tosses( rng ), lock_cnt );

      int err = fd_vinyl_meta_lock_range( meta, range_start, range_cnt, flags, version );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong lock_idx = range_start;
        for( ulong lock_rem=range_cnt; lock_rem; lock_rem-- ) {
          ulong e0 = fd_vinyl_meta_lock_ele0( meta, lock_idx );
          ulong e1 = fd_vinyl_meta_lock_ele1( meta, lock_idx );

          FD_TEST( e0< e1      );
          FD_TEST( e1<=ele_max );

          for( ulong ele_idx=e0; ele_idx<e1; ele_idx++ ) {
            fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;
            if( !fd_vinyl_meta_ele_in_use( ele ) ) continue;

            fd_vinyl_key_t const * key = &ele->phdr.key;
            ulong                  mod = ele->phdr.info.ul[0];

            FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
            FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
            FD_TEST( ele->line_idx        == ULONG_MAX          );

            if( !rdonly ) {
              mod++;

              ele->phdr.info.ul[0] = mod;
              ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
              ele->seq             = (key->ul[0] ^ mod);
              ele->line_idx        = ULONG_MAX;

            }
          }

          lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
        }

        fd_vinyl_meta_unlock_range( meta, range_start, range_cnt, version );

      }

      break;
    }

    case 9: { /* parallel memo iteration */
      ulong memo;
      ulong iter_min;
      if( FD_UNLIKELY( !meta_cnt ) ) { /* pick a memo not likely in meta */
        memo     = fd_rng_ulong( rng );
        iter_min = 0UL;
      } else { /* pick a memo in meta at least once */
        ulong            idx = fd_rng_ulong_roll( rng, meta_cnt );
        fd_vinyl_key_t * key = meta_key + idx;
        memo     = fd_vinyl_key_memo( seed, key );
        iter_min = 1UL;
      }

      fd_vinyl_meta_iter_t iter[1];
      int err = fd_vinyl_meta_iter_init( meta, memo, flags, iter );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong iter_cnt = 0UL;
        while( !fd_vinyl_meta_iter_done( iter ) ) {
          fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_iter_ele( iter );

          FD_TEST( (ulong)(ele-ele0)<ele_max );

          FD_TEST( fd_vinyl_key_memo( seed, &ele->phdr.key )==memo );
          FD_TEST( fd_vinyl_meta_ele_in_use( ele )                 );

          fd_vinyl_key_t const * key = &ele->phdr.key;
          ulong                  mod = ele->phdr.info.ul[0];

          FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
          FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
          FD_TEST( ele->line_idx        == ULONG_MAX          );

          if( !rdonly ) {
            mod++;

            ele->phdr.info.ul[0] = mod;
            ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
            ele->seq             = (key->ul[0] ^ mod);
            ele->line_idx        = ULONG_MAX;
          }

          iter_cnt++;

          FD_TEST( fd_vinyl_meta_iter_next( iter )==iter );
        }

        FD_TEST( fd_vinyl_meta_iter_fini( iter )==iter );

        FD_TEST( iter_cnt>=iter_min );
      }

      break;
    }

    default:
      break;
    }
  }

  /* Clean up for the next text battery */

  for( ulong meta_idx=0UL; meta_idx<meta_cnt; meta_idx++ )
    FD_TEST( !fd_vinyl_meta_remove( meta, meta_key + meta_idx, NULL, FD_MAP_FLAG_BLOCKING ) );

  shmem_cnt = save;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

static fd_vinyl_key_t * _meta_key = NULL;
static ulong            _meta_cnt = 0UL;

static int
writer_main( int     argc,
             char ** argv ) {

  /* Init local tile context */

  fd_vinyl_meta_t * meta     = tile_meta;
  ulong             iter_cnt = tile_iter_cnt;
  ulong             tile_idx = (ulong)(uint)argc;
  ulong             tile_cnt = (ulong)argv;

  fd_vinyl_meta_ele_t * ele0       = (fd_vinyl_meta_ele_t *)fd_vinyl_meta_shele( meta );
  ulong                 ele_max    = fd_vinyl_meta_ele_max( meta );
  ulong                 seed       = fd_vinyl_meta_seed( meta );
  ulong *               lock       = meta->lock;
  int                   lock_shift = meta->lock_shift;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  ulong global_prefix = 0x0123456789abcdefUL;
  ulong local_key     = 0U;

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Hammer the meta with all manners of writer side operations */

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (shared meta_cnt %lu)", iter_idx, iter_cnt, _meta_cnt ));
      if( tile_cnt==1UL ) FD_TEST( !fd_vinyl_meta_verify( meta ) );
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r = fd_rng_ulong( rng );

    int op = (int)(r & 7UL); r >>= 4;

    switch( op ) {

    case 0: { /* single writer good query (i.e. key already in meta) */
      if( FD_UNLIKELY( !_meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, _meta_cnt );
      fd_vinyl_key_t * key  = _meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      ulong ele_idx;
      FD_TEST( !fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx ) );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( ele->memo==memo                        );
      FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );
      FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );

      ulong mod = ele->phdr.info.ul[0];

      FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
      FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
      FD_TEST( ele->line_idx        == ULONG_MAX          );

      break;
    }

    case 1: { /* single writer bad query (i.e. key not in meta) */
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong          memo = fd_vinyl_key_memo( seed, key );

      ulong ele_idx;
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx );
      FD_TEST( err==FD_VINYL_ERR_KEY );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( !fd_vinyl_meta_ele_in_use( ele ) );
      break;
    }

    case 2: { /* single writer insert (i.e. room and key not already in meta) */
      if( FD_UNLIKELY( _meta_cnt>=(ele_max-1UL) ) ) break;
      fd_vinyl_key_t key[1]; fd_vinyl_key_init_ulong( key, global_prefix, tile_cnt, tile_idx, local_key );
      ulong          memo = fd_vinyl_key_memo( seed, key );
      ulong          mod  = 0UL;

      ulong ele_idx;
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx );
      FD_TEST( err==FD_VINYL_ERR_KEY );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( !fd_vinyl_meta_ele_in_use( ele ) );

      ele->memo            = memo;
      ele->phdr.key        = *key;
      ele->phdr.info.ul[0] = mod;
      ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
      ele->seq             = (key->ul[0] ^ mod);
      ele->line_idx        = ULONG_MAX;

      FD_COMPILER_MFENCE();
      ele->phdr.ctl = 1UL;
      FD_COMPILER_MFENCE();

      _meta_key[ _meta_cnt++ ] = *key;
      local_key++;
      break;
    }

    case 3: { /* single writer remove (i.e. key already in meta) */
      if( FD_UNLIKELY( !_meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, _meta_cnt );
      fd_vinyl_key_t * key  = _meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      ulong ele_idx;
      FD_TEST( !fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx ) );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( ele->memo==memo                        );
      FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );
      FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );

      ulong mod = ele->phdr.info.ul[0];

      FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
      FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
      FD_TEST( ele->line_idx        == ULONG_MAX          );

      fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, NULL, 0UL, ele_idx );

      _meta_key[ idx ] = _meta_key[ --_meta_cnt ];
      break;
    }

    case 4: { /* good modify (i.e. key already in meta) */
      if( FD_UNLIKELY( !_meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, _meta_cnt );
      fd_vinyl_key_t * key  = _meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      ulong ele_idx;
      FD_TEST( !fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx ) );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( ele->memo==memo                        );
      FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );
      FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );

      ulong mod = ele->phdr.info.ul[0];

      FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
      FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
      FD_TEST( ele->line_idx        == ULONG_MAX          );

      fd_vinyl_meta_prepare_fast( lock, lock_shift, ele_idx );

      mod++;

      ele->phdr.info.ul[0] = mod;
      ele->phdr.info.ul[1] = (key->ul[1] ^ mod);
      ele->seq             = (key->ul[0] ^ mod);
      ele->line_idx        = ULONG_MAX;

      fd_vinyl_meta_publish_fast( lock, lock_shift, ele_idx );
      break;
    }

    case 5: { /* bad modify (i.e. key already in meta) */
      if( FD_UNLIKELY( !_meta_cnt ) ) break;
      ulong            idx  = fd_rng_ulong_roll( rng, _meta_cnt );
      fd_vinyl_key_t * key  = _meta_key + idx;
      ulong            memo = fd_vinyl_key_memo( seed, key );

      ulong ele_idx;
      FD_TEST( !fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx ) );
      FD_TEST( ele_idx<ele_max );

      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;

      FD_TEST( ele->memo==memo                        );
      FD_TEST( fd_vinyl_meta_ele_in_use( ele )        );
      FD_TEST( fd_vinyl_key_eq( &ele->phdr.key, key ) );

      ulong mod = ele->phdr.info.ul[0];

      FD_TEST( ele->phdr.info.ul[1] == (key->ul[1] ^ mod) );
      FD_TEST( ele->seq             == (key->ul[0] ^ mod) );
      FD_TEST( ele->line_idx        == ULONG_MAX          );

      fd_vinyl_meta_prepare_fast( lock, lock_shift, ele_idx );

      mod++;

      fd_vinyl_meta_cancel_fast( lock, lock_shift, ele_idx );
      break;
    }

    default:
      break;
    }
  }

  /* Clean up for the next text battery */

  for( ulong meta_idx=0UL; meta_idx<_meta_cnt; meta_idx++ ) {
    fd_vinyl_key_t * key  = _meta_key + meta_idx;
    ulong            memo = fd_vinyl_key_memo( seed, key );
    ulong            ele_idx;
    FD_TEST( !fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &ele_idx ) );
    fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, NULL, 0UL, ele_idx );
  }

  FD_COMPILER_MFENCE();
  tile_go = 2;
  FD_COMPILER_MFENCE();

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

static int
reader_main( int     argc,
             char ** argv ) {
  (void)argc; (void)argv;

  /* Init local tile context */

  fd_vinyl_meta_t * meta     = tile_meta;
  ulong             tile_idx = (ulong)(uint)argc;
  ulong             tile_cnt = (ulong)argv;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Run while the writer is running */

  for(;;) {

    /* Pick a key the writer has recent published.  Since _meta_key is
       allocated to largest possible _meta_cnt, we don't care if we do
       this atomically accurate or not (if we get a botched read, the
       query will fail with ERR_KEY). */

    fd_vinyl_key_t  key[1];
    fd_vinyl_info_t info[1];

    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( tile_go!=1 ) ) break;

    ulong meta_cnt = _meta_cnt;

    if( FD_UNLIKELY( !meta_cnt ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    *key = _meta_key[ fd_rng_ulong_roll( rng, meta_cnt ) ];

    int err = fd_vinyl_meta_query( meta, key, info );
    if( FD_UNLIKELY( err ) ) FD_TEST( err==FD_MAP_ERR_KEY );
    else {
      FD_TEST( !err );

      ulong mod = info->ul[0];

      FD_TEST( info->ul[1] == (key->ul[1] ^ mod) );
    }

    /* And try to query for a key we know isn't in the map */

    key->ul[3] = 1UL;
    FD_TEST( fd_vinyl_meta_query( meta, key, info )==FD_VINYL_ERR_KEY );

  }

  fd_rng_delete( fd_rng_leave( rng ) );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",   NULL, 4096UL                                      );
  ulong lock_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--lock-cnt",  NULL, fd_vinyl_meta_lock_cnt_est ( ele_max ) );
  ulong probe_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--probe-max", NULL, fd_vinyl_meta_probe_max_est( ele_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL, 1234UL                                      );
  ulong iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt",  NULL, 10000000UL                                  );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --lock-cnt %lu --probe-max %lu --seed %lu --iter-cnt %lu)",
                  ele_max, lock_cnt, probe_max, seed, iter_cnt ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Creating vinyl meta element" ));

  void * shele = shmem_alloc( alignof(fd_vinyl_meta_ele_t), ele_max*sizeof(fd_vinyl_meta_ele_t) );
  memset( shele, 0, ele_max*sizeof(fd_vinyl_meta_ele_t) );

  FD_LOG_NOTICE(( "Creating vinyl meta" ));

  ulong  align     = fd_vinyl_meta_align();
  ulong  footprint = fd_vinyl_meta_footprint( ele_max, lock_cnt, probe_max );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Unsupported --ele-max / --lock-cnt / --probe-max" ));
  void * shmeta = shmem_alloc( align, footprint );

  FD_TEST( fd_vinyl_meta_new( shmeta, ele_max, lock_cnt, probe_max, seed )==shmeta );

  FD_LOG_NOTICE(( "Joining vinyl meta" ));

  fd_vinyl_meta_t meta[1]; fd_vinyl_meta_join( meta, shmeta, shele );

  tile_meta     = meta;
  tile_iter_cnt = iter_cnt;

  ulong tile_max = fd_tile_cnt();
  for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

    /* FIXME: use tpool here */

    FD_LOG_NOTICE(( "Testing concurrent operation on %lu tiles", tile_cnt ));

    FD_COMPILER_MFENCE();
    tile_go = 0;
    FD_COMPILER_MFENCE();

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
      fd_tile_exec_new( tile_idx, tile_main, (int)(uint)tile_idx, (char **)tile_cnt );

    fd_log_sleep( (long)0.1e9 );

    FD_COMPILER_MFENCE();
    tile_go = 1;
    FD_COMPILER_MFENCE();

    tile_main( 0, (char **)tile_cnt );

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

    FD_TEST( !fd_vinyl_meta_verify( meta ) );

    FD_LOG_NOTICE(( "Testing single writer / concurrent readers on %lu tiles", tile_cnt ));

    ulong save = shmem_cnt;
    _meta_key = shmem_alloc( alignof(fd_vinyl_key_t), ele_max*sizeof(fd_vinyl_key_t) );
    _meta_cnt = 0UL;

    FD_COMPILER_MFENCE();
    tile_go = 0;
    FD_COMPILER_MFENCE();

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
      fd_tile_exec_new( tile_idx, reader_main, (int)(uint)tile_idx, (char **)tile_cnt );

    fd_log_sleep( (long)0.1e9 );

    FD_COMPILER_MFENCE();
    tile_go = 1;
    FD_COMPILER_MFENCE();

    writer_main( 0, (char **)tile_cnt );

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

    shmem_cnt = save;

    FD_TEST( !fd_vinyl_meta_verify( meta ) );
  }

  FD_LOG_NOTICE(( "Leaving vinyl meta" ));

  FD_TEST( fd_vinyl_meta_leave( meta )==meta );

  FD_LOG_NOTICE(( "Destroying vinyl meta" ));

  FD_TEST( fd_vinyl_meta_delete( shmeta )==shmeta );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
