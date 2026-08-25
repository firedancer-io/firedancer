#include "fd_bls12_381.h"
#include "fd_bls.h"

int
fd_bls12_381_g1_decompress_syscall( uchar       out[ 96 ],
                                    uchar const in [ 48 ],
                                    int         big_endian ) {
  return fd_bls_g1_decompress( out, in, big_endian );
}

int
fd_bls12_381_g1_validate_syscall( uchar const in[ 96 ],
                                  int         big_endian ) {
  return fd_bls_g1_validate( in, big_endian );
}

int
fd_bls12_381_g1_add_syscall( uchar       out[ 96 ],
                             uchar const a  [ 96 ],
                             uchar const b  [ 96 ],
                             int         big_endian ) {
  return fd_bls_g1_add( out, a, b, big_endian );
}

int
fd_bls12_381_g1_sub_syscall( uchar       out[ 96 ],
                             uchar const a  [ 96 ],
                             uchar const b  [ 96 ],
                             int         big_endian ) {
  return fd_bls_g1_sub( out, a, b, big_endian );
}

int
fd_bls12_381_g1_mul_syscall( uchar       out   [ 96 ],
                             uchar const scalar[ 32 ],
                             uchar const a     [ 96 ],
                             int         big_endian ) {
  return fd_bls_g1_mul( out, scalar, a, big_endian );
}

int
fd_bls12_381_g2_decompress_syscall( uchar       out[ 192 ],
                                    uchar const in [  96 ],
                                    int         big_endian ) {
  return fd_bls_g2_decompress( out, in, big_endian );
}

int
fd_bls12_381_g2_compress( uchar       out[  96 ],
                          uchar const in [ 192 ],
                          int         big_endian ) {
  return fd_bls_g2_compress( out, in, big_endian );
}

int
fd_bls12_381_g2_validate_syscall( uchar const in[ 192 ],
                                  int         big_endian ) {
  return fd_bls_g2_validate( in, big_endian );
}

int
fd_bls12_381_g2_add_syscall( uchar       out[ 192 ],
                             uchar const a  [ 192 ],
                             uchar const b  [ 192 ],
                             int         big_endian ) {
  return fd_bls_g2_add( out, a, b, big_endian );
}

int
fd_bls12_381_g2_sub_syscall( uchar       out[ 192 ],
                             uchar const a  [ 192 ],
                             uchar const b  [ 192 ],
                             int         big_endian ) {
  return fd_bls_g2_sub( out, a, b, big_endian );
}

int
fd_bls12_381_g2_mul_syscall( uchar       out   [ 192 ],
                             uchar const scalar[  32 ],
                             uchar const a     [ 192 ],
                             int         big_endian ) {
  return fd_bls_g2_mul( out, scalar, a, big_endian );
}

int
fd_bls12_381_pairing_syscall( uchar       out[ 48*12 ],
                              uchar const g1 [],
                              uchar const g2 [],
                              ulong       cnt,
                              int         big_endian ) {
  if( FD_UNLIKELY( cnt>FD_BLS12_381_PAIRING_BATCH_SZ ) ) return -1;
  return fd_bls_pairing_bytes( out, g1, g2, cnt, big_endian );
}

#define FD_BLS_LITERAL(STR) ("" STR), (sizeof(STR)-1UL)
#define FD_BLS_SIG_DOMAIN_POP "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

int
fd_bls12_381_proof_of_possession_verify( uchar const msg[],
                                         ulong       msg_sz,
                                         uchar const proof     [ static 96 ],
                                         uchar const public_key[ static 48 ] ) {
  /* The caller must bind the public key into the message.  Rejecting shorter
     payloads prevents accidentally accepting the RFC's empty-message mode. */
  if( FD_UNLIKELY( msg_sz<48UL ) ) return -1;
  return fd_bls_verify( msg, msg_sz, proof, public_key,
                        FD_BLS_LITERAL( FD_BLS_SIG_DOMAIN_POP ) );
}
