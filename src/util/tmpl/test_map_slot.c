#include "../fd_util.h"

#define HAS_MEMO 0

struct myele {
  uint  mykey;
  int   used;
  uint  val;
  uint  mod;
# if HAS_MEMO
  ulong mymemo;
# endif
};

typedef struct myele myele_t;

/* Note: macros are deliberately written sloppy (generator should be
   robust against this) */

#undef  FD_TMPL_USE_HANDHOLDING
#define FD_TMPL_USE_HANDHOLDING 0

#define MAP_NAME             mymap
#define MAP_ELE_T            myele_t
#define MAP_KEY_T            uint
#define MAP_KEY              mykey
#define MAP_KEY_HASH(k,s)    fd_ulong_hash( s ^ (ulong)*k )
#define MAP_KEY_EQ(k0,k1)    *k0==*k1
#define MAP_MEMOIZE          HAS_MEMO
#define MAP_MEMO             mymemo
#define MAP_KEY_EQ_IS_SLOW   0
#define MAP_ELE_IS_FREE(e)   (!e->used)
#define MAP_ELE_FREE(c,e)    FD_TEST( *(ulong *)c==0x0123456789abcdefUL ); e->used = 0
#define MAP_ELE_MOVE(c,d,s)  FD_TEST( *(ulong *)c==0x0123456789abcdefUL ); *d = *s; s->used = 0
#define MAP_PREFETCH(s,h)    FD_VOLATILE_CONST( (s)->mykey )
#define MAP_IMPL_STYLE       0
#include "fd_map_slot.c"

#define ELE_MAX (4096UL)

static myele_t shmem[ ELE_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",   NULL,                        ELE_MAX );
  ulong probe_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--probe-max", NULL, mymap_probe_max_est( ele_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL,                         1234UL );
  ulong iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt",  NULL,                     10000000UL );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --probe-max %lu --seed %lu --iter-cnt %lu)",
                  ele_max, probe_max, seed, iter_cnt ));

  if( FD_UNLIKELY( ele_max>ELE_MAX ) ) FD_LOG_ERR(( "Increase ELE_MAX to support this --ele-max" ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  /* Create the shared element store and initialize it to free */

  FD_LOG_NOTICE(( "Testing misc" ));

  for( ulong rem=1000000UL; rem; rem-- ) {
    uint  r  = fd_rng_uint( rng );
    ulong em = 1UL << (r&31U);                     r >>= 5;
    uint  k0 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    uint  k1 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;

    FD_TEST( mymap_probe_max_est( em )==em );

    int eq = (k0==k1);
    FD_TEST( mymap_key_eq(&k0,&k0)==1 && mymap_key_eq(&k1,&k0)==eq && mymap_key_eq(&k0,&k1)==eq && mymap_key_eq(&k1,&k1)==1 );

    ulong s = fd_rng_ulong( rng );
    ulong h = mymap_key_hash( &k0, s ); FD_COMPILER_FORGET( h ); /* All values possible and hash quality depends on the user */
  }

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = mymap_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !mymap_footprint( 0UL     ) ); /* ele_max not a power of 2 */
  FD_TEST( !mymap_footprint( 1UL<<63 ) ); /* ele_max  too large */

  ulong footprint = mymap_footprint( ele_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  FD_TEST( !mymap_new( NULL,        ele_max, 0 ) ); /* NULL       shmem */
  FD_TEST( !mymap_new( (void *)1UL, ele_max, 0 ) ); /* misaligned shmem */
  FD_TEST( !mymap_new( shmem,       0UL,     0 ) ); /* ele_max not a power of 2 */
  FD_TEST( !mymap_new( shmem,       1UL<<63, 0 ) ); /* ele_max too large */

  FD_TEST( mymap_new( shmem, ele_max, 1 )==shmem );

  mymap_t map[1];

  FD_TEST( !mymap_join( NULL,        shmem,       ele_max, probe_max,   seed ) ); /* NULL       lmem */
  FD_TEST( !mymap_join( (void *)1UL, shmem,       ele_max, probe_max,   seed ) ); /* misaligned lmem */
  FD_TEST( !mymap_join( map,         NULL,        ele_max, probe_max,   seed ) ); /* NULL       ele0 */
  FD_TEST( !mymap_join( map,         (void *)1UL, ele_max, probe_max,   seed ) ); /* misaligned ele0 */
  FD_TEST( !mymap_join( map,         shmem,       0UL,     probe_max,   seed ) ); /* ele_max not a power of 2 */
  FD_TEST( !mymap_join( map,         shmem,       1UL<<63, probe_max,   seed ) ); /* ele_max too large */
  FD_TEST( !mymap_join( map,         shmem,       ele_max, 0UL,         seed ) ); /* probe_max too small */
  FD_TEST( !mymap_join( map,         shmem,       ele_max, ele_max+1UL, seed ) ); /* probe_max too large */
  /* seed arbitrary */

  FD_TEST( mymap_join( map, shmem, ele_max, probe_max, seed )==map );

  FD_LOG_NOTICE(( "Initializing context" ));

  FD_TEST( mymap_ctx_max( map )>=8UL );
  ulong * ctx = (ulong *)mymap_ctx( map );
  FD_TEST( ctx );
  FD_TEST( fd_ulong_is_aligned( (ulong)ctx, alignof(ulong) ) );

  ctx[0] = 0x0123456789abcdefUL;

  FD_TEST( ctx==(ulong *)mymap_ctx_const( map ) );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( mymap_ele0      ( map )==shmem     );
  FD_TEST( mymap_ele0_const( map )==shmem     );
  FD_TEST( mymap_ele_max   ( map )==ele_max   );
  FD_TEST( mymap_probe_max ( map )==probe_max );
  FD_TEST( mymap_seed      ( map )==seed      );

  FD_LOG_NOTICE(( "Testing operations" ));

  uint  map_key[ ELE_MAX ];
  ulong map_cnt = 0UL;

  myele_t sentinel[ 1 ]; memset( sentinel, 0, sizeof(myele_t) );

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "Iteration %lu of %lu (local map_cnt %lu)", iter_idx, iter_cnt, map_cnt ));
      FD_TEST( !mymap_verify( map ) );
      diag_rem = 1000000UL;
    }
    diag_rem--;
    uint r = fd_rng_uint( rng );

    int op = (int)(r & 31UL); r >>= 5;

    switch( op ) {

    case 0: { /* basic query (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      myele_t const * ele = mymap_query( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( ele->used                                 );
      FD_TEST( ele->val==(key ^ ele->mod)                );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      break;
    }

    case 1: { /* basic query (key not in map) */

      uint key = fd_rng_uint( rng ) | 1U;
      FD_TEST( !mymap_query( map, &key ) );

      break;
    }

    case 2: { /* basic update (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      myele_t * ele = mymap_update( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( ele->used                                 );
      FD_TEST( ele->val==(key ^ ele->mod)                );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->val = key ^ (++ele->mod);

      break;
    }

    case 3: { /* basic update (key not in map) */

      uint key = fd_rng_uint( rng ) | 1U;
      FD_TEST( !mymap_update( map, &key ) );

      break;
    }

    case 4: { /* basic insert (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      FD_TEST( !mymap_insert( map, &key ) );

      break;
    }

    case 5: { /* basic insert (key not in map) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      myele_t * ele = mymap_insert( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( !ele->used                                );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;
      ele->used = 1;

      map_key[ map_cnt++ ] = key;

      break;
    }

    case 6: { /* basic insert (key not in map, cancelled) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      myele_t * ele = mymap_insert( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( !ele->used                                );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;

      break;
    }

    case 7: { /* basic upsert (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      myele_t * ele = mymap_upsert( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( ele->used                                 );
      FD_TEST( ele->val==(key ^ ele->mod)                );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->val = key ^ (++ele->mod);

      break;
    }

    case 8: { /* basic upsert (key not in map) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      myele_t * ele = mymap_upsert( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( !ele->used                                );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;
      ele->used = 1;

      map_key[ map_cnt++ ] = key;

      break;
    }

    case 9: { /* basic upsert (key not in map, cancelled) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      myele_t * ele = mymap_upsert( map, &key );

      FD_TEST( ele                                       );
      FD_TEST( ele->mykey==key                           );
      FD_TEST( !ele->used                                );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;

      break;
    }

    case 10: { /* advanced query (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint  key  = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t const * ele = mymap_query_fast( map, &key, memo, sentinel );

      FD_TEST( ele                        );
      FD_TEST( ele!=sentinel              );
      FD_TEST( ele->mykey==key            );
      FD_TEST( ele->used                  );
      FD_TEST( ele->val==(key ^ ele->mod) );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo          );
#     endif

      break;
    }

    case 11: { /* advanced query (key not in map) */

      uint key = fd_rng_uint( rng ) | 1U;
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      FD_TEST( mymap_query_fast( map, &key, memo, sentinel )==sentinel );

      break;
    }

    case 12: { /* advanced update (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_update_fast( map, &key, memo, sentinel );

      FD_TEST( ele                        );
      FD_TEST( ele!=sentinel              );
      FD_TEST( ele->mykey==key            );
      FD_TEST( ele->used                  );
      FD_TEST( ele->val==(key ^ ele->mod) );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo          );
#     endif

      ele->val = key ^ (++ele->mod);

      break;
    }

    case 13: { /* advanced update (key not in map) */

      uint key = fd_rng_uint( rng ) | 1U;
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      FD_TEST( mymap_update_fast( map, &key, memo, sentinel )==sentinel );

      break;
    }

    case 14: { /* advanced insert (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      FD_TEST( mymap_insert_fast( map, &key, memo, sentinel )==sentinel );

      break;
    }

    case 15: { /* advanced insert (key not in map) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_insert_fast( map, &key, memo, sentinel );

      FD_TEST( ele               );
      FD_TEST( ele!=sentinel     );
      FD_TEST( ele->mykey==key   );
      FD_TEST( !ele->used        );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;
      ele->used = 1;

      map_key[ map_cnt++ ] = key;

      break;
    }

    case 16: { /* advanced insert (key not in map, cancelled) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_insert_fast( map, &key, memo, sentinel );

      FD_TEST( ele               );
      FD_TEST( ele!=sentinel     );
      FD_TEST( ele->mykey==key   );
      FD_TEST( !ele->used        );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;

      break;
    }

    case 17: { /* advanced upsert (key in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_upsert_fast( map, &key, memo, sentinel );

      FD_TEST( ele                        );
      FD_TEST( ele!=sentinel              );
      FD_TEST( ele->mykey==key            );
      FD_TEST( ele->used                  );
      FD_TEST( ele->val==(key ^ ele->mod) );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo          );
#     endif

      ele->val = key ^ (++ele->mod);

      break;
    }

    case 18: { /* advanced upsert (key not in map) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_upsert_fast( map, &key, memo, sentinel );

      FD_TEST( ele               );
      FD_TEST( ele!=sentinel     );
      FD_TEST( ele->mykey==key   );
      FD_TEST( !ele->used        );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;
      ele->used = 1;

      map_key[ map_cnt++ ] = key;

      break;
    }

    case 19: { /* advanced upsert (key not in map, cancelled) */

      if( FD_UNLIKELY( map_cnt>=ele_max ) ) break;
      uint key = (uint)(iter_idx << 1);
      ulong memo = mymap_hint( map, &key, 0 );
      FD_TEST( memo==mymap_key_hash( &key, seed ) );
      myele_t * ele = mymap_upsert_fast( map, &key, memo, sentinel );

      FD_TEST( ele               );
      FD_TEST( ele->mykey==key   );
      FD_TEST( !ele->used        );
      /* val and mod invalid here */
#     if HAS_MEMO
      FD_TEST( ele->mymemo==memo );
#     endif

      ele->mod  = 0;
      ele->val  = key ^ ele->mod;

      break;
    }

    case 20: { /* memo iteration */
//break;/* FIXME: MEMO ITERATION NEEDS TO HANDLE COMPLETELY FULL MAP */

      ulong memo;
      ulong iter_min;
      if( FD_UNLIKELY( !map_cnt ) ) {
        memo     = fd_rng_ulong( rng );
        iter_min = 0UL;
      } else {
        uint key = map_key[ fd_rng_ulong_roll( rng, map_cnt ) ];
        memo     = mymap_key_hash( &key, seed );
        iter_min = 1UL;
      }

      ulong iter_cnt = 0UL;

      for( mymap_iter_t iter = mymap_iter_init( map, memo );
           !mymap_iter_done( map, memo, iter );
           iter = mymap_iter_next( map, memo, iter ) ) {
        myele_t const * ele = mymap_iter_ele_const( map, memo, iter );

        FD_TEST( ele                                       );
        FD_TEST( ele==mymap_iter_ele( map, memo, iter )    );
        FD_TEST( mymap_key_hash( &ele->mykey, seed )==memo );
        FD_TEST( ele->used                                 );
        FD_TEST( ele->val==(ele->mykey ^ ele->mod)         );
#       if HAS_MEMO
        FD_TEST( ele->mymemo==memo                         );
#       endif

        iter_cnt++;
      }

      FD_TEST( iter_cnt>=iter_min );

      break;
    }

    case 21:
    case 22:
    case 23:
    case 24: { /* remove (multiple cases to match number of cases that insert) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx = fd_rng_ulong_roll( rng, map_cnt );
      uint  key = map_key[ idx ];
      myele_t * ele = mymap_update( map, &key );

      FD_TEST( ele                        );
      FD_TEST( ele->mykey==key            );
      FD_TEST( ele->used                  );
      FD_TEST( ele->val==(key ^ ele->mod) );
#     if HAS_MEMO
      FD_TEST( ele->mymemo==mymap_key_hash( &key, seed ) );
#     endif

      mymap_remove( map, ele );

      FD_TEST( !mymap_update( map, &key ) );

      map_key[ idx ] = map_key[ --map_cnt ];
      break;
    }

    default: break;
    }

  }

  FD_TEST( !mymap_verify( map ) );

  FD_LOG_NOTICE(( "Testing destruction" ));

  FD_TEST( !mymap_leave( NULL )      ); /* NULL join */
  FD_TEST(  mymap_leave( map  )==map );

  FD_TEST( !mymap_delete( NULL        )        ); /* NULL ele0 */
  FD_TEST( !mymap_delete( (void *)1UL )        ); /* misaligned ele0 */
  FD_TEST(  mymap_delete( shmem       )==shmem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
