
#include "../fd_util.h"

struct wrapped_ul {
  ulong key;
};
typedef struct wrapped_ul wrapped_ul_t;

#define MAP_PERFECT_NAME      prime100
#define MAP_PERFECT_LG_TBL_SZ 5 /* 32 elements */
#define MAP_PERFECT_T         wrapped_ul_t
#define MAP_PERFECT_HASH_C    2460647081U
#define MAP_PERFECT_KEY_T     ulong
#define MAP_PERFECT_ZERO_KEY  0UL

#define MAP_PERFECT_0   2,
#define MAP_PERFECT_1   3,
#define MAP_PERFECT_2   5,
#define MAP_PERFECT_3   7,
#define MAP_PERFECT_4  11,
#define MAP_PERFECT_5  13,
#define MAP_PERFECT_6  17,
#define MAP_PERFECT_7  19,
#define MAP_PERFECT_8  23,
#define MAP_PERFECT_9  29,
#define MAP_PERFECT_10 31,
#define MAP_PERFECT_11 37,
#define MAP_PERFECT_12 41,
#define MAP_PERFECT_13 43,
#define MAP_PERFECT_14 47,
#define MAP_PERFECT_15 53,
#define MAP_PERFECT_16 59,
#define MAP_PERFECT_17 61,
#define MAP_PERFECT_18 67,
#define MAP_PERFECT_19 71,
#define MAP_PERFECT_20 73,
#define MAP_PERFECT_21 79,
#define MAP_PERFECT_22 83,
#define MAP_PERFECT_23 89,
#define MAP_PERFECT_24 97,

#include "fd_map_perfect.c"

static inline void
test_primes( void ) {
  ulong ssq = 0UL;
  for( ulong i=0UL; i<100UL; i++ ) if( prime100_contains( i ) ) ssq += i*i;

  FD_TEST( ssq==65796UL );
}



typedef struct {
  int prime;
  int primitive_root;
} prime_to_primitive_root_t;

#define MAP_PERFECT_NAME       prim_root100
#define MAP_PERFECT_LG_TBL_SZ  5
#define MAP_PERFECT_T          prime_to_primitive_root_t
#define MAP_PERFECT_HASH_C     2460647081U
#define MAP_PERFECT_KEY_T      int
#define MAP_PERFECT_ZERO_KEY   0UL
#define MAP_PERFECT_KEY        prime

#define MAP_PERFECT_0   2,1
#define MAP_PERFECT_1   3, .primitive_root=2 /* show other syntax */
#define MAP_PERFECT_2   5, 2
#define MAP_PERFECT_3   7, 3
#define MAP_PERFECT_4  11, 2
#define MAP_PERFECT_5  13, 2
#define MAP_PERFECT_6  17, 3
#define MAP_PERFECT_7  19, 2
#define MAP_PERFECT_8  23, 5
#define MAP_PERFECT_9  29, 2
#define MAP_PERFECT_10 31, 3
#define MAP_PERFECT_11 37, 2
#define MAP_PERFECT_12 41, 6
#define MAP_PERFECT_13 43, 3
#define MAP_PERFECT_14 47, 5
#define MAP_PERFECT_15 53, 2
#define MAP_PERFECT_16 59, 2
#define MAP_PERFECT_17 61, 2
#define MAP_PERFECT_18 67, 2
#define MAP_PERFECT_19 71, 7
#define MAP_PERFECT_20 73, 5
#define MAP_PERFECT_21 79, 3
#define MAP_PERFECT_22 83, 2
#define MAP_PERFECT_23 89, 3
#define MAP_PERFECT_24 97, 5


#include "fd_map_perfect.c"

static inline void
test_primitive_root( void ) {
  for( int j=3; j<100; j++ ) {
    prime_to_primitive_root_t const * ele = prim_root100_query( j, NULL );
    if( FD_UNLIKELY( ele ) ) {
      /* If x is a primitive root of p, then x^((p-1)/2) == -1 (mod p) */
      int prod = 1;
      for( int k=0; k<(j-1)/2; k++ ) prod = (prod * ele->primitive_root) % ele->prime;
      FD_TEST( prod == ele->prime-1 );
    }
  }
}

typedef union {
  uchar key[3];
  uint _ukey;
} b3_t;

#define MAP_PERFECT_NAME        permq
#define MAP_PERFECT_LG_TBL_SZ   3
#define MAP_PERFECT_T           b3_t
#define MAP_PERFECT_HASH_C      533181283U
#define MAP_PERFECT_KEY_T       uchar const *
#define MAP_PERFECT_ZERO_KEY    (0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_HASH( u )   (( MAP_PERFECT_HASH_C *       (u))>>(32-(MAP_PERFECT_LG_TBL_SZ)))
#define MAP_PERFECT_HASH_PP(a,b,c) (MAP_PERFECT_HASH( (((c)<<16) | ((b)<<8) | (a)) )&0x7)
#define MAP_PERFECT_HASH_R( ptr ) MAP_PERFECT_HASH( fd_uint_load_4( ptr ) )
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 3UL ))

#define MAP_PERFECT_0   (0,1,2),
#define MAP_PERFECT_1   (0,2,1),
#define MAP_PERFECT_2   (1,0,2),
#define MAP_PERFECT_3   (1,2,0),
#define MAP_PERFECT_4   (2,0,1),
#define MAP_PERFECT_5   (2,1,0),

#include "fd_map_perfect.c"

static inline void
test_is_permutation( void ) {
  uchar query[4] __attribute__((aligned(4UL)));
  for( uchar a=0; a<4; a++ ) for( uchar b=0; b<4; b++ ) for( uchar c=0; c<4; c++ ) {
    query[ 0 ]=a; query[ 1 ]=b; query[ 2 ]=c; query[ 3 ]=0;
    int contained = permq_contains( query );
    int should_contain = (a!=b) & (a!=c) & (b!=c) & (fd_uchar_max( fd_uchar_max( a,b ), c )<3);
    FD_TEST( contained==should_contain );
  }
}

typedef struct {
  uchar key[3];
  ulong index;
  int   dummy;
} b3_idx_t;

#define MAP_PERFECT_NAME        permq2
#define MAP_PERFECT_LG_TBL_SZ   3
#define MAP_PERFECT_T           b3_idx_t
#define MAP_PERFECT_HASH_C      533181283U
#define MAP_PERFECT_KEY_T       uint
#define MAP_PERFECT_ZERO_KEY    (0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_HASH( u )   (( MAP_PERFECT_HASH_C *       (u))>>(32-(MAP_PERFECT_LG_TBL_SZ)))
#define MAP_PERFECT_HASH_PP(a,b,c) (MAP_PERFECT_HASH( (((c)<<16) | ((b)<<8) | (a)) )&0x7)
#define MAP_PERFECT_HASH_R( u ) MAP_PERFECT_HASH( u )
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (fd_uint_load_3( k1 )==k2)

#define MAP_PERFECT_0   (0,1,2), 0UL, .dummy=1
#define MAP_PERFECT_1   (0,2,1), 1UL, 0
#define MAP_PERFECT_2   (1,0,2), 2UL, -4
#define MAP_PERFECT_3   (1,2,0), 3UL, 6
#define MAP_PERFECT_4   (2,0,1), .index=4UL, 1
#define MAP_PERFECT_5   (2,1,0), .index=5UL, .dummy=-99

#include "fd_map_perfect.c"

/* Unfortunately, fd_map_perfect.c undefines these at the end, so we
   have to redefine them in order to use them as a dispatch table like
   this. */
#define MAP_PERFECT_LG_TBL_SZ   3
#define MAP_PERFECT_HASH_C      533181283U
#define MAP_PERFECT_HASH_PP(a,b,c) (MAP_PERFECT_HASH( (((c)<<16) | ((b)<<8) | (a)) )&0x7)

static inline void
test_permutation_idx( void ) {
  ulong cnt = 0UL;
  for( uint i=0U; i<0xFFFFFF; i++ ) {
    switch( permq2_hash_or_default( i ) ) {
      case MAP_PERFECT_HASH_PP(0,1,2): cnt += 1UL<<0; break;
      case MAP_PERFECT_HASH_PP(0,2,1): cnt += 1UL<<1; break;
      case MAP_PERFECT_HASH_PP(1,0,2): cnt += 1UL<<2; break;
      case MAP_PERFECT_HASH_PP(1,2,0): cnt += 1UL<<3; break;
      case MAP_PERFECT_HASH_PP(2,0,1): cnt += 1UL<<4; break;
      case MAP_PERFECT_HASH_PP(2,1,0): cnt += 1UL<<5; break;
      case UINT_MAX: break;
      default: FD_LOG_ERR(( "hash or default returned bad value" ));
    }
  }
  FD_TEST( cnt == 0x3FUL );
}
#undef MAP_PERFECT_LG_TBL_SZ
#undef MAP_PERFECT_HASH_C
#undef MAP_PERFECT_HASH_PP
#undef MAP_PERFECT_HASH


#define MAP_PERFECT_NAME      table_with_0
#define MAP_PERFECT_LG_TBL_SZ 1
#define MAP_PERFECT_T         wrapped_ul_t
#define MAP_PERFECT_HASH_C    1U
#define MAP_PERFECT_KEY_T     ulong
#define MAP_PERFECT_ZERO_KEY  0UL

#define MAP_PERFECT_0 0,

#include "fd_map_perfect.c"

#define MAP_PERFECT_NAME      table_without_0
#define MAP_PERFECT_LG_TBL_SZ 1
#define MAP_PERFECT_T         wrapped_ul_t
#define MAP_PERFECT_HASH_C    2147483648U
#define MAP_PERFECT_KEY_T     ulong
#define MAP_PERFECT_ZERO_KEY  0UL

#define MAP_PERFECT_0 1,

#include "fd_map_perfect.c"

static inline void
test_zero( void ) {
  FD_TEST(  table_with_0_contains( 0 ) );
  FD_TEST( !table_with_0_contains( 1 ) );
  FD_TEST( !table_without_0_contains( 0 ) );
  FD_TEST(  table_without_0_contains( 1 ) );
  FD_TEST( table_without_0_tbl[ 0 ].key );
  FD_TEST( table_without_0_tbl[ 1 ].key );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_primes();         /* No value,  simple key  */
  test_primitive_root(); /* Has value, simple key  */
  test_is_permutation(); /* No value,  complex key */
  test_permutation_idx();/* Has value, complex key */
  test_zero();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
