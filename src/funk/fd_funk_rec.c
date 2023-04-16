#include "fd_funk.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* Provide the actual record map implementation */

#define MAP_NAME              fd_funk_rec_map
#define MAP_T                 fd_funk_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_KEY_COPY(kd,ks)   fd_funk_xid_key_pair_copy((kd),(ks))
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_giant.c"

int
fd_funk_rec_verify( fd_funk_t * funk ) {
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, fd_funk_wksp( funk ) ); /* Previously verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  TEST( !fd_funk_rec_map_verify( rec_map ) );

# undef TEST

  return FD_FUNK_SUCCESS;
}

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
