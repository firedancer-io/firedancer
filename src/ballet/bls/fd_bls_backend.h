#ifndef HEADER_fd_src_ballet_bls_fd_bls_backend_h
#define HEADER_fd_src_ballet_bls_fd_bls_backend_h

/* Internal compile-time backend dispatch for fd_bls.  The reference
   backend (src/ballet/bls/ref, implemented on blst) provides the full
   surface and is always linked.  On AVX-512 builds the native backend
   (src/ballet/bls/avx512) overrides the operations it implements:
   the pairing family, hash-to-curve, aggregate verification, pub_sum,
   and the G2 subgroup validation / deserialization path. */

#include "fd_bls.h"

FD_PROTOTYPES_BEGIN

/* --- reference backend (full surface) --- */

/* secret keys */

void fd_bls_ref_sec_to_pub( fd_bls_sec_t const *, fd_bls_pub_t * );
void fd_bls_ref_sec_derive( fd_bls_sec_t *, uchar const *, ulong );
void fd_bls_ref_sec_sign( fd_bls_sec_t const *, uchar const *, ulong, fd_bls_sig_t * );

/* public keys (G1) */

void fd_bls_ref_pub_ser( fd_bls_pub_t const *, uchar [ static FD_BLS_PUB_SZ ] );
void fd_bls_ref_pub_compress( fd_bls_pub_t const *, uchar [ static FD_BLS_PUB_COMPRESSED_SZ ] );
int  fd_bls_ref_pub_de( fd_bls_pub_t *, uchar const *, ulong );
int  fd_bls_ref_pub_de_compressed( fd_bls_pub_t *, uchar const [ static FD_BLS_PUB_COMPRESSED_SZ ] );
void fd_bls_ref_pub_add( fd_bls_pub_t *, fd_bls_pub_t const *, fd_bls_pub_t const * );
void fd_bls_ref_pub_neg( fd_bls_pub_t *, fd_bls_pub_t const * );
int  fd_bls_ref_pub_is_inf( fd_bls_pub_t const * );
int  fd_bls_ref_pub_eq( fd_bls_pub_t const *, fd_bls_pub_t const * );
void fd_bls_ref_pub_sum( fd_bls_pub_t *, fd_bls_pub_t const *, fd_bls_set_t const * );

/* signatures (G2) */

void fd_bls_ref_sig_ser( fd_bls_sig_t const *, uchar [ static FD_BLS_SIG_SZ ] );
void fd_bls_ref_sig_compress( fd_bls_sig_t const *, uchar [ static FD_BLS_SIG_COMPRESSED_SZ ] );
int  fd_bls_ref_sig_de( fd_bls_sig_t *, uchar const [ static FD_BLS_SIG_SZ ] );
int  fd_bls_ref_sig_de_unchecked( fd_bls_sig_t *, uchar const [ static FD_BLS_SIG_SZ ] );
int  fd_bls_ref_sig_de_compressed( fd_bls_sig_t *, uchar const [ static FD_BLS_SIG_COMPRESSED_SZ ] );
void fd_bls_ref_sig_add( fd_bls_sig_t *, fd_bls_sig_t const *, fd_bls_sig_t const * );
void fd_bls_ref_sig_neg( fd_bls_sig_t *, fd_bls_sig_t const * );
int  fd_bls_ref_sig_validate( fd_bls_sig_t const * );
int  fd_bls_ref_sig_is_inf( fd_bls_sig_t const * );
int  fd_bls_ref_sig_eq( fd_bls_sig_t const *, fd_bls_sig_t const * );

/* hash-to-curve and aggregate verification */

void fd_bls_ref_hash_msg( uchar const *, ulong, fd_bls_hash_t * );
int  fd_bls_ref_agg_verify_hashed( fd_bls_hash_t const *, fd_bls_pub_t const *,
                                   fd_bls_hash_t const *, fd_bls_pub_t const *,
                                   fd_bls_sig_t const * );
int  fd_bls_ref_agg_to_pair( fd_bls_hash_t const *, fd_bls_pub_t const *,
                             fd_bls_hash_t const *, fd_bls_pub_t const *,
                             fd_bls_sig_t const *,
                             fd_bls_g1_t *, fd_bls_g2_t *, ulong * );

/* pairing family */

int fd_bls_ref_g2_prepare( fd_bls_g2_prepared_t * out, fd_bls_g2_t const * q );
int fd_bls_ref_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const * p_prepared, fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const * p_checked,  fd_bls_g2_t const * q_checked );
int fd_bls_ref_pairing_finalverify_checked( fd_bls_g1_t const * p, fd_bls_g2_t const * q,
                                            ulong cnt, ulong q_subgroup_mask );
int fd_bls_ref_pairing_finalverify( fd_bls_g1_t const * p, fd_bls_g2_t const * q,
                                    ulong cnt );
int fd_bls_ref_pairing( ulong out[12][6], fd_bls_g1_t const * p, fd_bls_g2_t const * q,
                        ulong cnt );
int fd_bls_ref_pairing_bytes( uchar out[ 48*12 ], uchar const g1[], uchar const g2[],
                              ulong cnt, int big_endian );

/* syscall byte operations */

int fd_bls_ref_g1_decompress( uchar out[ 96 ], uchar const in[ 48 ], int big_endian );
int fd_bls_ref_g1_validate( uchar const in[ 96 ], int big_endian );
int fd_bls_ref_g1_add( uchar out[ 96 ], uchar const a[ 96 ], uchar const b[ 96 ], int big_endian );
int fd_bls_ref_g1_sub( uchar out[ 96 ], uchar const a[ 96 ], uchar const b[ 96 ], int big_endian );
int fd_bls_ref_g1_mul( uchar out[ 96 ], uchar const scalar[ 32 ], uchar const a[ 96 ], int big_endian );
int fd_bls_ref_g2_decompress( uchar out[ 192 ], uchar const in[ 96 ], int big_endian );
int fd_bls_ref_g2_compress( uchar out[ 96 ], uchar const in[ 192 ], int big_endian );
int fd_bls_ref_g2_validate( uchar const in[ 192 ], int big_endian );
int fd_bls_ref_g2_add( uchar out[ 192 ], uchar const a[ 192 ], uchar const b[ 192 ], int big_endian );
int fd_bls_ref_g2_sub( uchar out[ 192 ], uchar const a[ 192 ], uchar const b[ 192 ], int big_endian );
int fd_bls_ref_g2_mul( uchar out[ 192 ], uchar const scalar[ 32 ], uchar const a[ 192 ], int big_endian );
int fd_bls_ref_verify( uchar const msg[], ulong msg_sz,
                       uchar const signature[ 96 ], uchar const public_key[ 48 ],
                       char const * domain, ulong domain_len );

#if FD_HAS_AVX512

/* --- AVX-512 backend (native operations only) --- */

void fd_bls_avx512_pub_sum( fd_bls_pub_t *, fd_bls_pub_t const *, fd_bls_set_t const * );

int  fd_bls_avx512_sig_de( fd_bls_sig_t *, uchar const [ static FD_BLS_SIG_SZ ] );
int  fd_bls_avx512_sig_de_compressed( fd_bls_sig_t *, uchar const [ static FD_BLS_SIG_COMPRESSED_SZ ] );
int  fd_bls_avx512_sig_validate( fd_bls_sig_t const * );

void fd_bls_avx512_hash_msg( uchar const *, ulong, fd_bls_hash_t * );
int  fd_bls_avx512_agg_verify_hashed( fd_bls_hash_t const *, fd_bls_pub_t const *,
                                      fd_bls_hash_t const *, fd_bls_pub_t const *,
                                      fd_bls_sig_t const * );

int  fd_bls_avx512_g2_prepare( fd_bls_g2_prepared_t * out, fd_bls_g2_t const * q );
int  fd_bls_avx512_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const * p_prepared, fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const * p_checked,  fd_bls_g2_t const * q_checked );
int  fd_bls_avx512_pairing_finalverify_checked( fd_bls_g1_t const * p, fd_bls_g2_t const * q,
                                                ulong cnt, ulong q_subgroup_mask );
int  fd_bls_avx512_pairing_finalverify( fd_bls_g1_t const * p, fd_bls_g2_t const * q, ulong cnt );
int  fd_bls_avx512_pairing( ulong out[12][6], fd_bls_g1_t const * p, fd_bls_g2_t const * q,
                            ulong cnt );

#endif /* FD_HAS_AVX512 */

FD_PROTOTYPES_END

/* Default dispatch: everything goes to the reference backend. */

#define fd_bls_backend_sec_to_pub        fd_bls_ref_sec_to_pub
#define fd_bls_backend_sec_derive        fd_bls_ref_sec_derive
#define fd_bls_backend_sec_sign          fd_bls_ref_sec_sign
#define fd_bls_backend_pub_ser           fd_bls_ref_pub_ser
#define fd_bls_backend_pub_compress      fd_bls_ref_pub_compress
#define fd_bls_backend_pub_de            fd_bls_ref_pub_de
#define fd_bls_backend_pub_de_compressed fd_bls_ref_pub_de_compressed
#define fd_bls_backend_pub_add           fd_bls_ref_pub_add
#define fd_bls_backend_pub_neg           fd_bls_ref_pub_neg
#define fd_bls_backend_pub_is_inf        fd_bls_ref_pub_is_inf
#define fd_bls_backend_pub_eq            fd_bls_ref_pub_eq
#define fd_bls_backend_pub_sum           fd_bls_ref_pub_sum
#define fd_bls_backend_sig_ser           fd_bls_ref_sig_ser
#define fd_bls_backend_sig_compress      fd_bls_ref_sig_compress
#define fd_bls_backend_sig_de            fd_bls_ref_sig_de
#define fd_bls_backend_sig_de_unchecked  fd_bls_ref_sig_de_unchecked
#define fd_bls_backend_sig_de_compressed fd_bls_ref_sig_de_compressed
#define fd_bls_backend_sig_add           fd_bls_ref_sig_add
#define fd_bls_backend_sig_neg           fd_bls_ref_sig_neg
#define fd_bls_backend_sig_validate      fd_bls_ref_sig_validate
#define fd_bls_backend_sig_is_inf        fd_bls_ref_sig_is_inf
#define fd_bls_backend_sig_eq            fd_bls_ref_sig_eq
#define fd_bls_backend_hash_msg          fd_bls_ref_hash_msg
#define fd_bls_backend_agg_verify_hashed fd_bls_ref_agg_verify_hashed
#define fd_bls_backend_g2_prepare        fd_bls_ref_g2_prepare
#define fd_bls_backend_pairing_finalverify_prepared_checked fd_bls_ref_pairing_finalverify_prepared_checked
#define fd_bls_backend_pairing_finalverify_checked          fd_bls_ref_pairing_finalverify_checked
#define fd_bls_backend_pairing_finalverify                  fd_bls_ref_pairing_finalverify
#define fd_bls_backend_pairing           fd_bls_ref_pairing
#define fd_bls_backend_pairing_bytes     fd_bls_ref_pairing_bytes
#define fd_bls_backend_g1_decompress     fd_bls_ref_g1_decompress
#define fd_bls_backend_g1_validate       fd_bls_ref_g1_validate
#define fd_bls_backend_g1_add            fd_bls_ref_g1_add
#define fd_bls_backend_g1_sub            fd_bls_ref_g1_sub
#define fd_bls_backend_g1_mul            fd_bls_ref_g1_mul
#define fd_bls_backend_g2_decompress     fd_bls_ref_g2_decompress
#define fd_bls_backend_g2_compress       fd_bls_ref_g2_compress
#define fd_bls_backend_g2_validate       fd_bls_ref_g2_validate
#define fd_bls_backend_g2_add            fd_bls_ref_g2_add
#define fd_bls_backend_g2_sub            fd_bls_ref_g2_sub
#define fd_bls_backend_g2_mul            fd_bls_ref_g2_mul

/* AVX-512 overrides for the natively implemented operations. */

#if FD_HAS_AVX512

#undef  fd_bls_backend_pub_sum
#undef  fd_bls_backend_sig_de
#undef  fd_bls_backend_sig_de_compressed
#undef  fd_bls_backend_sig_validate
#undef  fd_bls_backend_hash_msg
#undef  fd_bls_backend_agg_verify_hashed
#undef  fd_bls_backend_g2_prepare
#undef  fd_bls_backend_pairing_finalverify_prepared_checked
#undef  fd_bls_backend_pairing_finalverify_checked
#undef  fd_bls_backend_pairing_finalverify
#undef  fd_bls_backend_pairing

#define fd_bls_backend_pub_sum           fd_bls_avx512_pub_sum
#define fd_bls_backend_sig_de            fd_bls_avx512_sig_de
#define fd_bls_backend_sig_de_compressed fd_bls_avx512_sig_de_compressed
#define fd_bls_backend_sig_validate      fd_bls_avx512_sig_validate
#define fd_bls_backend_hash_msg          fd_bls_avx512_hash_msg
#define fd_bls_backend_agg_verify_hashed fd_bls_avx512_agg_verify_hashed
#define fd_bls_backend_g2_prepare        fd_bls_avx512_g2_prepare
#define fd_bls_backend_pairing_finalverify_prepared_checked fd_bls_avx512_pairing_finalverify_prepared_checked
#define fd_bls_backend_pairing_finalverify_checked          fd_bls_avx512_pairing_finalverify_checked
#define fd_bls_backend_pairing_finalverify                  fd_bls_avx512_pairing_finalverify
#define fd_bls_backend_pairing           fd_bls_avx512_pairing

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bls_fd_bls_backend_h */
