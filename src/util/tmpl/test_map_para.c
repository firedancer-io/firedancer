#include "../fd_util.h"

struct myele {
  uint  mykey;
  uint  mynext;
  uint  mod;
  uint  val;
  ulong mymemo;
};

typedef struct myele myele_t;

#define POOL_NAME          mypool
#define POOL_ELE_T         myele_t
#define POOL_IDX_T         uint
#define POOL_NEXT          mynext
#define POOL_IMPL_STYLE    0
#include "fd_pool_para.c"

#define MAP_NAME           mymap
#define MAP_ELE_T          myele_t
#define MAP_KEY_T          uint
#define MAP_KEY            mykey
#define MAP_IDX_T          uint
#define MAP_NEXT           mynext
#define MAP_KEY_HASH(k,s)  fd_ulong_hash( ((ulong)*(k)) ^ (s) )
#define MAP_IMPL_STYLE     0
#define MAP_MEMOIZE        1
#define MAP_MEMO           mymemo
#define MAP_KEY_EQ_IS_SLOW 1
#include "fd_map_para.c"

FD_STATIC_ASSERT( FD_MAP_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_AGAIN  ==-2, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_CORRUPT==-3, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_KEY    ==-4, unit_test );

FD_STATIC_ASSERT( FD_MAP_FLAG_BLOCKING==1, unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_ADAPTIVE==2, unit_test );

#define SHMEM_MAX (131072UL)

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

static mypool_t * tile_pool;
static mymap_t  * tile_map;
static ulong      tile_ele_max;
static ulong      tile_iter_cnt;
static ulong      tile_go;

static int
tile_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;

  /* Init local tile context */

  mypool_t * pool     = tile_pool;
  mymap_t *  map      = tile_map;
  ulong      ele_max  = tile_ele_max;
  ulong      iter_cnt = tile_iter_cnt;
  ulong      tile_idx = fd_tile_idx();
  ulong      tile_cnt = fd_tile_cnt();

  /* Need to upgrade this if using more than 256 tiles or ~16.7M iterations */

  FD_TEST( tile_cnt<(1UL<< 8) );
  FD_TEST( iter_cnt<(1UL<<24) );

  uint local_prefix  = (uint)(tile_idx << 24);
  uint local_key     = 0U;
  uint unused_prefix = (uint)(tile_cnt << 24);
  uint unused_mask   = (~0U) >> 8;

  myele_t   sentinel[1];
  myele_t * ele_stop = (myele_t *)mypool_shele( pool ) + ele_max;

  /* Create a distinct rng sequence for this tile and tile set */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  /* Alloc the key local scratch */

  ulong  save    = shmem_cnt;
  uint * map_key = shmem_alloc( alignof(uint), ele_max*sizeof(uint) );
  ulong  map_cnt = 0UL;

  /* Alloc the map txn local scratch */

  ulong txn_key_max     = 7UL;
  ulong txn_key_max_max = mymap_txn_key_max_max();
  FD_TEST( txn_key_max_max >= txn_key_max );

  ulong txn_align = mymap_txn_align();
  FD_TEST( fd_ulong_is_pow2( txn_align ) );

  FD_TEST( !mymap_txn_footprint( txn_key_max_max+1UL ) );
  ulong txn_footprint = mymap_txn_footprint( txn_key_max );
  FD_TEST( fd_ulong_is_aligned( txn_footprint, txn_align ) );

  void * ltxn = shmem_alloc( txn_align, txn_footprint );

  FD_TEST( !mymap_txn_init( NULL,        map,  txn_key_max         ) ); /* NULL       ltxn */
  FD_TEST( !mymap_txn_init( (void *)1UL, map,  txn_key_max         ) ); /* misaligned ltxn */
  FD_TEST( !mymap_txn_init( ltxn,        NULL, txn_key_max         ) ); /* NULL       join */
  FD_TEST( !mymap_txn_init( ltxn,        map,  txn_key_max_max+1UL ) ); /* bad key_max */

  FD_TEST( !mymap_txn_fini( NULL ) ); /* NULL ltxn */

  /* Alloc the map parallel iterator lock scratch */

  ulong   chain_cnt = mymap_chain_cnt( map );
  ulong * lock_seq = (ulong *)shmem_alloc( alignof(ulong), chain_cnt*sizeof(ulong) );
  for( ulong lock_idx=0UL; lock_idx<chain_cnt; lock_idx++ ) lock_seq[ lock_idx ] = lock_idx;

  FD_TEST(  mymap_iter_lock( NULL, lock_seq, 1UL,           0 )==FD_MAP_ERR_INVAL ); /* NULL join */
  FD_TEST(  mymap_iter_lock( map,  NULL,     1UL,           0 )==FD_MAP_ERR_INVAL ); /* NULL lock_seq */
  FD_TEST( !mymap_iter_lock( NULL, NULL,     0UL,           0 )                   ); /* nothing to do */
  FD_TEST( !mymap_iter_lock( NULL, lock_seq, 0UL,           0 )                   ); /* nothing to do */
  FD_TEST( !mymap_iter_lock( map,  NULL,     0UL,           0 )                   ); /* nothing to do */
  FD_TEST(  mymap_iter_lock( map,  lock_seq, chain_cnt+1UL, 0 )==FD_MAP_ERR_INVAL ); /* too many locks */
  /* flags is arbitrary */

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Hammer the map with all manners of concurrent operations */

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (local map_cnt %lu)", iter_idx, iter_cnt, map_cnt ));
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r = fd_rng_ulong( rng );

    int op = (int)(r & 15UL); r >>= 4;

    switch( op ) {

    case 0: { /* bad insert */
      int flags = (int)(r & 3UL); r >>= 2;
      FD_TEST( mymap_insert( map, NULL,     flags )==FD_MAP_ERR_INVAL ); /* not in ele store */
      FD_TEST( mymap_insert( map, sentinel, flags )==FD_MAP_ERR_INVAL ); /* not in ele store */
      FD_TEST( mymap_insert( map, ele_stop, flags )==FD_MAP_ERR_INVAL ); /* not in ele store */
      break;
    }

    case 1: { /* good insert */
      int flags = (int)(r & 3UL); r >>= 2;

      int       acq_err;
      myele_t * ele = mypool_acquire( pool, NULL, 0, &acq_err ); /* non-blocking acquire */
      if( FD_UNLIKELY( !ele ) ) {
        FD_TEST( (acq_err==FD_POOL_ERR_EMPTY) | (acq_err==FD_POOL_ERR_AGAIN) );
        break;
      }
      uint key = (uint)(local_prefix | local_key);
      uint mod = 0U;

      ele->mykey = key;
      ele->mod   = mod;
      ele->val   = (key ^ mod) ^ (uint)mypool_idx( pool, ele );

      int err = mymap_insert( map, ele, flags );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
        FD_TEST( err==FD_MAP_ERR_AGAIN           );
        FD_TEST( !mypool_release( pool, ele, 1 ) ); /* blocking release */
      } else {
        map_key[ map_cnt++ ] = key;
        local_key++;
      }
      break;
    }

    case 2: { /* bad remove */
      int  flags = (int)(r & 3UL); r >>= 2;
      uint key   = unused_prefix | (((uint)r) & unused_mask); r >>= 32;

      mymap_query_t query[1];
      int           err = mymap_remove( map, &key, sentinel, query, flags );
      myele_t *     ele = mymap_query_ele( query );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
      else                        FD_TEST( err==FD_MAP_ERR_KEY             );
      break;
    }

    case 3: { /* good remove */
      int flags = (int)(r & 3UL); r >>= 2;

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx = fd_rng_ulong_roll( rng, map_cnt );
      uint  key = map_key[ idx ];

      mymap_query_t query[1];
      int           err = mymap_remove( map, &key, sentinel, query, flags );
      myele_t *     ele = mymap_query_ele( query );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
        FD_TEST( err==FD_MAP_ERR_AGAIN           );
        FD_TEST( ele==sentinel                   );
      } else {
        FD_TEST( ele->mykey== key                                               );
        FD_TEST( ele->val  ==((key ^ ele->mod) ^ (uint)mypool_idx( pool, ele )) );
        FD_TEST( !mypool_release( pool, ele, 1 ) ); /* blocking release */
        map_key[ idx ] = map_key[ --map_cnt ];
      }
      break;
    }

    case 4: { /* bad modify */
      int  flags = (int)(r & 3UL); r >>= 2;
      uint key   = unused_prefix | (((uint)r) & unused_mask); r >>= 32;

      mymap_query_t query[1];
      int           err = mymap_modify_try( map, &key, sentinel, query, flags );
      myele_t *     ele = mymap_query_ele( query );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
      else                        FD_TEST( err==FD_MAP_ERR_KEY             );
      break;
    }

    case 5: { /* good modify */
      int flags = (int)(r & 3UL); r >>= 2;

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx = fd_rng_ulong_roll( rng, map_cnt );
      uint  key = map_key[ idx ];

      mymap_query_t query[1];
      int           err = mymap_modify_try( map, &key, sentinel, query, flags );
      myele_t *     ele = mymap_query_ele( query );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
        FD_TEST( ele==sentinel                   );
        FD_TEST( err==FD_MAP_ERR_AGAIN           );
      } else {
        ulong ele_idx = mypool_idx( pool, ele );
        uint  mod     = ele->mod;
        FD_TEST( ele_idx<ele_max                           );
        FD_TEST( ele->mykey== key                          );
        FD_TEST( ele->val  ==((key ^ mod) ^ (uint)ele_idx) );
        mod++;
        ele->mod = mod;
        ele->val = (key ^ mod) ^ (uint)ele_idx;
        FD_TEST( !mymap_modify_test( query ) );
      }
      break;
    }

    case 6: { /* bad query */
      uint key = unused_prefix | (((uint)r) & unused_mask); r >>= 32;

      mymap_query_t   query[1];
      int             err = mymap_query_try( map, &key, sentinel, query );
      myele_t const * ele = mymap_query_ele_const( query );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) break;
      FD_TEST( err==FD_MAP_ERR_KEY );
      break;
    }

    case 7: { /* good query */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx = fd_rng_ulong_roll( rng, map_cnt );
      uint  key = map_key[ idx ];

      mymap_query_t   query[1];
      int             err = mymap_query_try( map, &key, sentinel, query );
      myele_t const * ele = mymap_query_ele_const( query );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
      } else {
        ulong ele_idx = mypool_idx( pool, ele );
        FD_TEST( ele_idx<ele_max );

        uint spec_key = ele->mykey;
        uint spec_mod = ele->mod;
        uint spec_val = ele->val;

        err = mymap_query_test( query );

        if( FD_UNLIKELY( err ) ) {
          FD_TEST( err==FD_MAP_ERR_AGAIN );
        } else {
          FD_TEST( spec_key==  key                              );
          FD_TEST( spec_val==((key ^ spec_mod) ^ (uint)ele_idx) );
        }
      }
      break;
    }

    case 8: { /* compound operation */
      int flags = (int)(r & 3UL); r >>= 2;

      /* Test txn_add overflow */

      mymap_txn_t * txn = mymap_txn_init( ltxn, map, 0UL );
      FD_TEST( (void *)txn==ltxn );
      uint dum0 = (uint)r;        r >>= 32;
      int  dum1 = (int)(r & 1UL); r >>=  1;
      FD_TEST( mymap_txn_add( txn, &dum0, dum1 )==FD_MAP_ERR_INVAL );
      FD_TEST( mymap_txn_fini( txn )==ltxn );

      /* Generate a random transaction */

      if( FD_UNLIKELY( !map_cnt ) ) break;

      ulong txn_key_cnt = fd_rng_ulong_roll( rng, txn_key_max+1UL ); /* In [0,txn_key_max] */

      txn = mymap_txn_init( ltxn, map, txn_key_cnt );
      FD_TEST( (void *)txn==ltxn );

      struct { uint key; int key_op; } info[ txn_key_max ];

      for( ulong info_idx=0UL; info_idx<txn_key_cnt; info_idx++ ) {
        int   key_op = (int)(r & 3UL); r >>= 2;
        uint  key    = (key_op==1) ? (local_prefix | (local_key++)) : map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
        int   locked = key_op>0;

        FD_TEST( !mymap_txn_add( txn, &key, locked ) );

        info[ info_idx ].key    = key;
        info[ info_idx ].key_op = key_op;
      }

      /* Try the transaction */

      int err = mymap_txn_try( txn, flags );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
        FD_TEST( err==FD_MAP_ERR_AGAIN           );
      } else {

        /* Do all the operations in the transaction */

        int good   = 1;
        int canary = 0;

        for( ulong info_idx=0UL; info_idx<txn_key_cnt; info_idx++ ) {
          uint key    = info[ info_idx ].key;
          int  key_op = info[ info_idx ].key_op;

          switch( key_op ) {

          case 0: { /* txn query (speculative) */
            mymap_query_t   query[1];
            int             err = mymap_txn_query( map, &key, sentinel, query );
            myele_t const * ele = mymap_query_ele_const( query );

            if( FD_UNLIKELY( err ) ) {
              FD_TEST( ele==sentinel );
              int removed_earlier = 0;
              for( ulong prev_idx=0UL; prev_idx<info_idx; prev_idx++ ) {
                if( FD_UNLIKELY( (info[ prev_idx ].key==key) & (info[ prev_idx ].key_op==2) ) ) {
                  removed_earlier = 1;
                  break;
                }
              }
              if( tile_cnt==1UL ) { /* no conflicts possible */
                FD_TEST( err==FD_MAP_ERR_KEY );
                FD_TEST( removed_earlier );
              } else {
                FD_TEST( (err==FD_MAP_ERR_CORRUPT) | (err==FD_MAP_ERR_KEY) ); /* conflicting concurrent operation */
                canary = (err==FD_MAP_ERR_CORRUPT) | ((err==FD_MAP_ERR_KEY) & (!removed_earlier));
              }
            } else {
              ulong ele_idx = mypool_idx( pool, ele );
              if( FD_UNLIKELY( ele_idx>=ele_max ) ) good = 0;
              else {
                uint spec_key = ele->mykey;
                uint spec_mod = ele->mod;
                uint spec_val = ele->val;
                good &= (spec_key==key) & (spec_val==((key ^ spec_mod) ^ (uint)ele_idx));
              }
            }
            break;
          }

          case 1: { /* txn insert */
            FD_TEST( mymap_txn_insert( map, NULL     )==FD_MAP_ERR_INVAL ); /* not in ele store */
            FD_TEST( mymap_txn_insert( map, sentinel )==FD_MAP_ERR_INVAL ); /* not in ele store */
            FD_TEST( mymap_txn_insert( map, ele_stop )==FD_MAP_ERR_INVAL ); /* not in ele store */

            int       err;
            myele_t * ele = mypool_acquire( pool, NULL, 0, &err ); /* non-blocking acquire */
            if( FD_UNLIKELY( !ele ) ) {
              FD_TEST( (err==FD_POOL_ERR_EMPTY) | (err==FD_POOL_ERR_AGAIN) );
              break;
            }
            uint mod = 0U;

            ele->mykey = key;
            ele->mod   = mod;
            ele->val   = (key ^ mod) ^ (uint)mypool_idx( pool, ele );

            FD_TEST( !mymap_txn_insert( map, ele ) );

            map_key[ map_cnt++ ] = key;
            local_key++;
            break;
          }

          case 2: { /* txn remove */
            mymap_query_t query[1];
            int           err = mymap_txn_remove( map, &key, sentinel, query );
            myele_t *     ele = mymap_query_ele( query );

            if( FD_UNLIKELY( err ) ) {
              FD_TEST( err==FD_MAP_ERR_KEY );
              FD_TEST( ele==sentinel       );
              int removed_earlier = 0;
              for( ulong prev_idx=0UL; prev_idx<info_idx; prev_idx++ ) {
                if( FD_UNLIKELY( (info[ prev_idx ].key==key) & (info[ prev_idx ].key_op==2) ) ) {
                  removed_earlier = 1;
                  break;
                }
              }
              FD_TEST( removed_earlier );
            } else {
              FD_TEST( ele->mykey== key                                               );
              FD_TEST( ele->val  ==((key ^ ele->mod) ^ (uint)mypool_idx( pool, ele )) );
              FD_TEST( !mypool_release( pool, ele, 1 ) ); /* blocking release */
              ulong idx;
              for( idx=0UL; idx<map_cnt; idx++ ) if( map_key[ idx ]==key ) break;
              map_key[ idx ] = map_key[ --map_cnt ];
            }
            break;
          }

          case 3: { /* txn modify */
            int flags = (int)(r & 3UL); r >>= 2;

            mymap_query_t query[1];
            int           err = mymap_txn_modify( map, &key, sentinel, query, flags );
            myele_t *     ele = mymap_query_ele( query );

            if( FD_UNLIKELY( err ) ) {
              FD_TEST( err==FD_MAP_ERR_KEY );
              FD_TEST( ele==sentinel       );
              int removed_earlier = 0;
              for( ulong prev_idx=0UL; prev_idx<info_idx; prev_idx++ ) {
                if( FD_UNLIKELY( (info[ prev_idx ].key==key) & (info[ prev_idx ].key_op==2) ) ) {
                  removed_earlier = 1;
                  break;
                }
              }
              FD_TEST( removed_earlier );
            } else {
              ulong ele_idx = mypool_idx( pool, ele );
              FD_TEST( ele_idx < ele_max );

              uint mod = ele->mod;
              FD_TEST( ele->mykey== key                          );
              FD_TEST( ele->val  ==((key ^ mod) ^ (uint)ele_idx) );

              mod++;
              ele->mod = mod;
              ele->val = (key ^ mod) ^ (uint)ele_idx;
            }
            break;
          }

          default: break;
          }
        }

        /* Test if transaction was successful */

        err = mymap_txn_test( txn );

        if( FD_UNLIKELY( canary | (!!err) ) ) FD_TEST( err==FD_MAP_ERR_AGAIN );
        else                                  FD_TEST( good );

        /* FIXME: test reuse of existing or again failed transaction? */

      }

      FD_TEST( mymap_txn_fini( txn )==ltxn );
      break;
    }

    case 9: { /* parallel iteration */
      int flags = (int)(r & 3UL); r >>= 2;

      /* Pick a random subset of chains in an arbitrary order */

      ulong lock_cnt = fd_ulong_min( fd_rng_coin_tosses( rng ), chain_cnt );
      for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
        ulong swap_idx = lock_idx + fd_rng_ulong_roll( rng, chain_cnt-lock_idx );
        fd_swap( lock_seq[ lock_idx ], lock_seq[ swap_idx ] );
      }

      /* Lock the relevant subset of the map */

      int err = mymap_iter_lock( map, lock_seq, lock_cnt, flags );
      if( FD_UNLIKELY( err ) ) {
        FD_TEST( !(flags & FD_MAP_FLAG_BLOCKING) );
        FD_TEST( err==FD_MAP_ERR_AGAIN           );
        break;
      }

      /* Verify each element in the locked subset, unlocking as we go
         (note that the query can affect keys otherwise managed by other
         tiles and that we could do things like modify and remove keys
         from the subset we locked ... we could also potentially insert
         keys here but we'd have to know that key maps to a chain in our
         locked subset). */

      for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
        ulong chain_idx = lock_seq[ lock_idx ];

        for( mymap_iter_t iter = mymap_iter( map, chain_idx ); !mymap_iter_done( iter ); iter = mymap_iter_next( iter ) ) {
          myele_t const * ele = mymap_iter_ele_const( iter );
          ulong ele_idx = mypool_idx( pool, ele );
          FD_TEST( ele_idx < ele_max );
          FD_TEST( ele->val==((ele->mykey ^ ele->mod) ^ (uint)ele_idx) );
        }

        mymap_iter_unlock( map, lock_seq + lock_idx, 1UL );
      }

      break;
    }

    default:
      break;
    }

  }

  /* Clean up for the next text battery */

  for( ulong map_idx=0UL; map_idx<map_cnt; map_idx++ ) {
    mymap_query_t query[1];
    FD_TEST( !mymap_remove( map, map_key + map_idx, NULL, query, 1 ) );
    FD_TEST( !mypool_release( pool, mymap_query_ele( query ), 1 ) );
  }

  shmem_cnt = save;

  fd_rng_delete( fd_rng_leave( rng ) );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",    NULL, 1024UL                         );
  ulong chain_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--chain-cnt",  NULL, mymap_chain_cnt_est( ele_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",       NULL, 1234UL                         );
  ulong iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt",   NULL, 10000000UL                     );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --chain-cnt %lu --seed %lu --iter-cnt %lu)", ele_max, chain_cnt, seed, iter_cnt ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  /* Create the shared element store */
  void * shele = shmem_alloc( alignof(myele_t), sizeof(myele_t)*ele_max );

  /* Create and join an element pool */
  void * shpool = mypool_new( shmem_alloc( mypool_align(), mypool_footprint() ) );
  mypool_t pool[1]; FD_TEST( mypool_join( pool, shpool, shele, ele_max )==pool );
  mypool_reset( pool, 0UL );

  FD_LOG_NOTICE(( "Testing misc" ));

  ulong ele_max_max = mymap_ele_max_max(); FD_TEST( ele_max_max>0UL               );
  ulong chain_max   = mymap_chain_max();   FD_TEST( fd_ulong_is_pow2( chain_max ) );

  FD_TEST( mymap_chain_cnt_est( 0UL )                                ==mymap_chain_cnt_est( 1UL         ) );
  FD_TEST( mymap_chain_cnt_est( ele_max_max+(ele_max_max<ULONG_MAX) )==mymap_chain_cnt_est( ele_max_max ) );
  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong ele_max_est   = fd_rng_ulong_roll( rng, ele_max_max+1UL ); /* In [0,ele_max_max] */
    ulong chain_cnt_est = mymap_chain_cnt_est( ele_max_est );
    FD_TEST( fd_ulong_is_pow2( chain_cnt_est ) & (chain_cnt_est<=chain_max) );

    uint r  = fd_rng_uint( rng );
    uint k0 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    uint k1 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    int  eq = (k0==k1);
    FD_TEST( mymap_key_eq(&k0,&k0)==1 && mymap_key_eq(&k1,&k0)==eq && mymap_key_eq(&k0,&k1)==eq && mymap_key_eq(&k1,&k1)==1 );

    ulong s = fd_rng_ulong( rng );
    ulong h = mymap_key_hash( &k0, s ); FD_COMPILER_FORGET( h ); /* All values possible and hash quality depends on the user */
  }

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = mymap_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !mymap_footprint( 0UL          ) ); /* Not a power of 2 */
  FD_TEST( !mymap_footprint( chain_max<<1 ) ); /* Too many chains */
  ulong footprint = mymap_footprint( chain_cnt );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shmap = shmem_alloc( align, footprint );
  mymap_t map[1];

  FD_TEST( !mymap_new( NULL,        chain_cnt,    seed )        ); /* NULL shmem */
  FD_TEST( !mymap_new( (void *)1UL, chain_cnt,    seed )        ); /* misaligned shmem */
  FD_TEST( !mymap_new( shmap,       0UL,          seed )        ); /* Not a power of 2 */
  FD_TEST( !mymap_new( shmap,       chain_max<<1, seed )        ); /* Too many chains */
  /* seed arbitrary */
  FD_TEST(  mymap_new( shmap,       chain_cnt,    seed )==shmap );

  FD_TEST( !mymap_join( NULL,        shmap,       shele,       ele_max   )      ); /* NULL       ljoin */
  FD_TEST( !mymap_join( (void *)1UL, shmap,       shele,       ele_max   )      ); /* misaligned ljoin */
  FD_TEST( !mymap_join( map,         NULL,        shele,       ele_max   )      ); /* NULL       shmap */
  FD_TEST( !mymap_join( map,         (void *)1UL, shele,       ele_max   )      ); /* misaligned shmap */
  FD_TEST(  mymap_join( map,         shmap,       NULL,        ele_max   )==(ele_max ? NULL : map) ); /* NULL shele */
  FD_TEST( !mymap_join( map,         shmap,       (void *)1UL, ele_max   )      ); /* misaligned shele */
  FD_TEST(  mymap_join( map,         shmap,       shele,       ele_max   )==map );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST(  mymap_seed     ( map )==seed      );
  FD_TEST(  mymap_chain_cnt( map )==chain_cnt );

  FD_TEST(  mymap_shmap_const( map )==shmap   );
  FD_TEST(  mymap_shele_const( map )==shele   );
  FD_TEST(  mymap_ele_max    ( map )==ele_max );

  FD_TEST(  mymap_shmap( map )==shmap );
  FD_TEST(  mymap_shele( map )==shele );

  /* FIXME: use tpool here */

  tile_pool     = pool;
  tile_map      = map;
  tile_ele_max  = ele_max;
  tile_iter_cnt = iter_cnt;

  ulong tile_max = fd_tile_cnt();
  for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

    FD_LOG_NOTICE(( "Testing concurrent operation on %lu tiles", tile_cnt ));

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 0;
    FD_COMPILER_MFENCE();

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_new( tile_idx, tile_main, argc, argv );

    fd_log_sleep( (long)0.1e9 );

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 1;
    FD_COMPILER_MFENCE();

    tile_main( argc, argv );
    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

    /* FIXME: run these on non-empty maps too */
    FD_TEST( !mymap_verify( map ) );
    mymap_reset( map );
  }

  FD_LOG_NOTICE(( "Testing destruction" ));

  FD_TEST( !mymap_leave( NULL )      ); /* NULL join */
  FD_TEST(  mymap_leave( map  )==map );

  FD_TEST( !mymap_delete( NULL        )        ); /* NULL shmap */
  FD_TEST( !mymap_delete( (void *)1UL )        ); /* misaligned shmap */
  FD_TEST(  mymap_delete( shmap       )==shmap );

  FD_TEST( !mymap_delete( shmap )                    ); /* bad magic */
  FD_TEST( !mymap_join( map, shmap, shele, ele_max ) ); /* bad magic */

  FD_LOG_NOTICE(( "bad error code     (%i-%s)", 1,                  mymap_strerror( 1                  ) ));
  FD_LOG_NOTICE(( "FD_MAP_SUCCESS     (%i-%s)", FD_MAP_SUCCESS,     mymap_strerror( FD_MAP_SUCCESS     ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_INVAL   (%i-%s)", FD_MAP_ERR_INVAL,   mymap_strerror( FD_MAP_ERR_INVAL   ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_AGAIN   (%i-%s)", FD_MAP_ERR_AGAIN,   mymap_strerror( FD_MAP_ERR_AGAIN   ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_CORRUPT (%i-%s)", FD_MAP_ERR_CORRUPT, mymap_strerror( FD_MAP_ERR_CORRUPT ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_KEY     (%i-%s)", FD_MAP_ERR_KEY,     mymap_strerror( FD_MAP_ERR_KEY     ) ));

  mypool_leave( pool );
  mypool_delete( shpool );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
