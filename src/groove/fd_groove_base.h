#ifndef HEADER_fd_src_groove_fd_groove_base_h
#define HEADER_fd_src_groove_fd_groove_base_h

#include "../util/fd_util.h"

/* FD_GROOVE_PARANOID enables extra integrity checking in various
   operations. */

#ifndef FD_GROOVE_PARANOID
#define FD_GROOVE_PARANOID 1
#endif

/* fd_groove error code API *******************************************/

/* Note: Harmonized with fd_*_para error codes */

#define FD_GROOVE_SUCCESS     (0)
#define FD_GROOVE_ERR_INVAL   (-1)
#define FD_GROOVE_ERR_AGAIN   (-2)
#define FD_GROOVE_ERR_CORRUPT (-3)
#define FD_GROOVE_ERR_EMPTY   (-4)
#define FD_GROOVE_ERR_FULL    (-5)
#define FD_GROOVE_ERR_KEY     (-6)

FD_PROTOTYPES_BEGIN

/* fd_groove_strerror converts an FD_GROOVE_SUCCESS / FD_GROOVE_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

FD_FN_CONST char const *
fd_groove_strerror( int err );

FD_PROTOTYPES_END

/* fd_groove_key API **************************************************/

/* A fd_groove_key_t identifies a groove record.  Compact binary keys
   are encouraged but a cstr can be used so long as it has
   strlen(cstr)<FD_FUNK_REC_KEY_FOOTPRINT and the characters c[i] for i
   in [strlen(cstr),FD_FUNK_REC_KEY_FOOTPRINT) are zero.  (Also, if
   encoding a cstr in a key, recommend using first byte to encode the
   strlen for accelerating cstr operations further but this is up to the
   user.) */

/* FIXME: binary compat with funk key? */
/* FIXME: consider aligning key 16 or 32 and/or AVX accelerating? */

#define FD_GROOVE_KEY_ALIGN     (8UL)
#define FD_GROOVE_KEY_FOOTPRINT (32UL)

union __attribute__((aligned(FD_GROOVE_KEY_ALIGN))) fd_groove_key {
  char   c[ FD_GROOVE_KEY_FOOTPRINT ];
  uchar uc[ FD_GROOVE_KEY_FOOTPRINT ];
  ulong ul[ FD_GROOVE_KEY_FOOTPRINT / sizeof(ulong) ];
};

typedef union fd_groove_key fd_groove_key_t;

FD_PROTOTYPES_BEGIN

/* fd_groove_key_init initializes the key pointed to by k to src_sz
   bytes pointed ito by src.  If src_sz is {less than,greater than}
   FD_GROOVE_KEY_FOOTPRINT, it will be {zero padded,truncated} to
   FD_GROOVE_KEY_FOOTPRINT bytes.  Assumes k and src point to valid
   non-overlapping regions in the caller's address stable for the
   duration of the call.  Retains no interest in k or src.  Returns k. */

static inline fd_groove_key_t *
fd_groove_key_init( fd_groove_key_t *        k,
                    void const * FD_RESTRICT src,
                    ulong                    src_sz ) {
  void * FD_RESTRICT dst = k->c;
  ulong csz = fd_ulong_min( src_sz, FD_GROOVE_KEY_FOOTPRINT ); /* typically compile time */
  ulong zsz = FD_GROOVE_KEY_FOOTPRINT - csz;                   /* " */
  if( zsz ) memset( dst, 0,   FD_GROOVE_KEY_FOOTPRINT );       /* " */
  if( csz ) memcpy( dst, src, csz                     );       /* " */
  return k;
}

/* fd_groove_key_ulong initializes the key pointed to by k with the
   ulongs k0, k1, k2, and k3.  Assumes k points in the caller's address
   space to the location to store the key.  Retains no interest in k.
   Returns k. */

static inline fd_groove_key_t *
fd_groove_key_init_ulong( fd_groove_key_t * k,
                          ulong             k0,
                          ulong             k1,
                          ulong             k2,
                          ulong             k3 ) {
  k->ul[0] = k0; k->ul[1] = k1; k->ul[2] = k2; k->ul[3] = k3;
  return k;
}

/* fd_groove_key_eq tests keys ka and kb for equality.  Assumes ka and
   kb point in the caller's address space to valid keys for the duration
   of the call.  Retains no interest in ka or kb.  Returns 1 if the keys
   are equal and 0 otherwise. */

FD_FN_PURE static inline int
fd_groove_key_eq( fd_groove_key_t const * ka,
                  fd_groove_key_t const * kb ) {
  ulong const * a = ka->ul;
  ulong const * b = kb->ul;
  return !(((a[0]^b[0]) | (a[1]^b[1])) | ((a[2]^b[2]) | (a[3]^b[3]))); /* tons of ILP and vectorizable */
}

/* fd_groove_key_hash provides a family of hashes that hash the key
   pointed to by k to a uniform quasi-random 64-bit integer.  seed
   selects the particular hash function to use and can be an arbitrary
   64-bit value.  The hash functions are high quality but not
   cryptographically secure.  Assumes ka points in the caller's address
   space to a valid key for the duration of the call.  Retains no
   interest in ka.  Returns the hash. */

FD_FN_UNUSED FD_FN_PURE static ulong /* Workaround -Winline */
fd_groove_key_hash( fd_groove_key_t const * ka,
                    ulong                   seed ) {
  ulong const * a = ka->ul;
  return (fd_ulong_hash( a[0] ^ seed ) ^ fd_ulong_hash( a[1] ^ seed )) ^
         (fd_ulong_hash( a[2] ^ seed ) ^ fd_ulong_hash( a[3] ^ seed )); /* tons of ILP and vectorizable */
}

FD_PROTOTYPES_END

/* fd_groove_block API ************************************************/

/* Groove data objects are backed by FD_GROOVE_BLOCK_ALIGN aligned
   FD_GROOVE_BLOCK_FOOTPRINT byte blocks.  ALIGN==FOOTPRINT and are a
   power of 2.  512 is used for tight coupling to typical HPC I/O API,
   operating system, driver and hardware limits. */

#define FD_GROOVE_BLOCK_ALIGN     (512UL)
#define FD_GROOVE_BLOCK_FOOTPRINT (512UL)

#endif /* HEADER_fd_src_groove_fd_groove_base_h */
