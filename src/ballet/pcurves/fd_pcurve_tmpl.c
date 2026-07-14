/* Instantiate ECDSA verification for a prime curve. */

#ifndef PCURVE_NAME
#error "Define PCURVE_NAME"
#endif
#ifndef PCURVE_SCALAR_SZ
#error "Define PCURVE_SCALAR_SZ"
#endif
#ifndef PCURVE_SCALAR_T
#error "Define PCURVE_SCALAR_T"
#endif
#ifndef PCURVE_POINT_T
#error "Define PCURVE_POINT_T"
#endif
#ifndef PCURVE_SHA_NAME
#error "Define PCURVE_SHA_NAME"
#endif
#ifndef PCURVE_SHA_T
#error "Define PCURVE_SHA_T"
#endif
#ifndef PCURVE_SHA_SZ
#error "Define PCURVE_SHA_SZ"
#endif
#ifndef PCURVE_SUCCESS
#error "Define PCURVE_SUCCESS"
#endif
#ifndef PCURVE_FAILURE
#error "Define PCURVE_FAILURE"
#endif

#define PCURVE_(x) FD_EXPAND_THEN_CONCAT3(PCURVE_NAME,_,x)
#define SHA_(x)    FD_EXPAND_THEN_CONCAT3(PCURVE_SHA_NAME,_,x)

static int
PCURVE_(verify_impl)( uchar const    msg[],
                      ulong          msg_sz,
                      uchar const    sig[ 2*PCURVE_SCALAR_SZ ],
                      uchar const    public_key[ 1+PCURVE_SCALAR_SZ ],
                      PCURVE_SHA_T * sha,
                      int            low_s ) {
  PCURVE_SCALAR_T r[1], s[1], u1[1], u2[1];
  PCURVE_POINT_T  public[1], point[1];

  if( FD_UNLIKELY( !PCURVE_(scalar_frombytes)( r, sig ) ) ) return PCURVE_FAILURE;
  if( FD_UNLIKELY( !( low_s ? PCURVE_(scalar_frombytes_positive)( s, sig+PCURVE_SCALAR_SZ )
                              : PCURVE_(scalar_frombytes)         ( s, sig+PCURVE_SCALAR_SZ ) ) ) ) return PCURVE_FAILURE;
  if( FD_UNLIKELY( PCURVE_(scalar_is_zero)( r ) | PCURVE_(scalar_is_zero)( s ) ) ) return PCURVE_FAILURE;
  if( FD_UNLIKELY( !PCURVE_(point_frombytes)( public, public_key ) ) ) return PCURVE_FAILURE;

  uchar hash[ PCURVE_SHA_SZ ];
  SHA_(fini)( SHA_(append)( SHA_(init)( sha ), msg, msg_sz ), hash );
  PCURVE_(scalar_from_digest)( u1, hash );

  PCURVE_(scalar_inv)( s, s );
  PCURVE_(scalar_mul)( u1, u1, s );
  PCURVE_(scalar_mul)( u2, r,  s );
  PCURVE_(double_scalar_mul_base)( point, u1, public, u2 );
  return PCURVE_(point_eq_x)( point, r ) ? PCURVE_SUCCESS : PCURVE_FAILURE;
}

int
PCURVE_(verify)( uchar const    msg[],
                 ulong          msg_sz,
                 uchar const    sig[ 2*PCURVE_SCALAR_SZ ],
                 uchar const    public_key[ 1+PCURVE_SCALAR_SZ ],
                 PCURVE_SHA_T * sha ) {
  return PCURVE_(verify_impl)( msg, msg_sz, sig, public_key, sha, 1 );
}

int
PCURVE_(verify_no_low_s)( uchar const    msg[],
                          ulong          msg_sz,
                          uchar const    sig[ 2*PCURVE_SCALAR_SZ ],
                          uchar const    public_key[ 1+PCURVE_SCALAR_SZ ],
                          PCURVE_SHA_T * sha ) {
  return PCURVE_(verify_impl)( msg, msg_sz, sig, public_key, sha, 0 );
}

#undef PCURVE_
#undef SHA_
#undef PCURVE_NAME
#undef PCURVE_SCALAR_SZ
#undef PCURVE_SCALAR_T
#undef PCURVE_POINT_T
#undef PCURVE_SHA_NAME
#undef PCURVE_SHA_T
#undef PCURVE_SHA_SZ
#undef PCURVE_SUCCESS
#undef PCURVE_FAILURE
