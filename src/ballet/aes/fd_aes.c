/* fd_aes_ref.c was imported from the OpenSSL project circa 2023-Aug.
   Original source files:  crypto/evp/e_aes.c crypto/modes/gcm128.c */

#include "fd_aes_gcm.h"
#include "fd_aes_gcm_private.h"
#include "fd_aes_private.h"

/* TODO: Do we need to support ivlen other than 12? */

static void
fd_aes_gcm_setiv( fd_aes_gcm_t * gcm,
                  uchar const    iv[ static 12 ] ) {

  uint ctr;
  gcm->len.u[ 0 ] = 0;  /* AAD length */
  gcm->len.u[ 1 ] = 0;  /* Message length */
  gcm->ares = 0;
  gcm->mres = 0;

  memcpy( gcm->Yi.c, iv, 12 );
  gcm->Yi.c[12] = 0;
  gcm->Yi.c[13] = 0;
  gcm->Yi.c[14] = 0;
  gcm->Yi.c[15] = 1;
  ctr = 1;

  gcm->Xi.u[0] = 0;
  gcm->Xi.u[1] = 0;

  fd_aesni_encrypt( gcm->Yi.c, gcm->EK0.c, &gcm->key );
  ctr++;

  gcm->Yi.d[3] = fd_uint_bswap( ctr );
}

void
fd_aes_gcm_init( fd_aes_gcm_t * gcm,
                 uchar const *  key,
                 ulong          key_sz,
                 uchar const    iv[ static 12 ] ) {

  /* TODO: Check key size */

  memset( gcm, 0, sizeof(fd_aes_gcm_t) );

  fd_aes_key_t * ks = &gcm->key;

  ulong key_bitcnt = key_sz << 3UL;
  fd_aesni_set_encrypt_key( key, key_bitcnt, ks );

  fd_aesni_encrypt( gcm->H.c, gcm->H.c, ks );
  gcm->H.u[ 0 ] = fd_ulong_bswap( gcm->H.u[ 0 ] );
  gcm->H.u[ 1 ] = fd_ulong_bswap( gcm->H.u[ 1 ] );

  fd_gcm_init_avx( gcm->Htable, gcm->H.u );
  fd_aes_gcm_setiv( gcm, iv );
}

static int
fd_gcm128_aad( fd_aes_gcm_t * aes_gcm,
               uchar const *  aad,
               ulong          aad_sz ) {

  ulong alen = aes_gcm->len.u[ 0 ];

  if( FD_UNLIKELY( aes_gcm->len.u[ 1 ] ) )
    return -2;

  alen += aad_sz;
  if (alen > (1UL<<61) || (sizeof(aad_sz) == 8 && alen < aad_sz))
    return -1;
  aes_gcm->len.u[0] = alen;

  uint n = aes_gcm->ares;
  if (n) {
    while (n && aad_sz) {
      aes_gcm->Xi.c[n] ^= *(aad++);
      --aad_sz;
      n = (n + 1) % 16;
    }
    if (n == 0)
      fd_gcm_gmult_avx( aes_gcm->Xi.u, aes_gcm->Htable );
    else {
      aes_gcm->ares = n;
      return 0;
    }
  }
  ulong i;
  if ((i = (aad_sz & (ulong)-16))) {
    fd_gcm_ghash_avx( aes_gcm->Xi.u, aes_gcm->Htable, aad, i );
    aad += i;
    aad_sz -= i;
  }
  if (aad_sz) {
    n = (unsigned int)aad_sz;
    for (i = 0; i < aad_sz; ++i)
      aes_gcm->Xi.c[i] ^= aad[i];
  }

  aes_gcm->ares = n;
  return 0;
}

/* TODO separate reference code and GCM128 */

static int
fd_gcm128_encrypt( fd_aes_gcm_t * ctx,
                   uchar const *  in,
                   uchar *        out,
                   ulong          len ) {

  uint n, ctr, mres;
  ulong i;
  ulong mlen = ctx->len.u[1];
  void *key = &ctx->key;

  mlen += len;
  if (mlen > ((1UL<<36) - 32) || (sizeof(len) == 8 && mlen < len))
    return -1;
  ctx->len.u[1] = mlen;

  mres = ctx->mres;

  if (ctx->ares) {
    /* First call to encrypt finalizes GHASH(AAD) */
    if (len == 0) {
      fd_gcm_gmult_avx( ctx->Xi.u, ctx->Htable );
      ctx->ares = 0;
      return 0;
    }
    memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    mres = sizeof(ctx->Xi);
    ctx->ares = 0;
  }

  ctr = fd_uint_bswap( ctx->Yi.d[3] );

  n = mres % 16;
  if (16 % sizeof(ulong) == 0) { /* always true actually */
    do {
      if (n) {
        while (n && len) {
          ctx->Xn[mres++] = *(out++) = *(in++) ^ ctx->EKi.c[n];
          --len;
          n = (n + 1) % 16;
        }
        if (n == 0) {
          fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
          mres = 0;
        } else {
          ctx->mres = mres;
          return 0;
        }
      }
      if (len >= 16 && mres) {
        fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
        mres = 0;
      }
      if ((i = (len & (ulong)-16))) {
        ulong j = i;

        while (len >= 16) {
          ulong *out_t = (ulong *)out;
          const ulong *in_t = (const ulong *)in;

          fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
          ++ctr;
          ctx->Yi.d[3] = fd_uint_bswap( ctr );
          for (i = 0; i < 16 / sizeof(ulong); ++i)
            out_t[i] = in_t[i] ^ ctx->EKi.t[i];
          out += 16;
          in += 16;
          len -= 16;
        }
        fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, out - j, j );
      }
      if (len) {
        fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
        ++ctr;
        ctx->Yi.d[3] = fd_uint_bswap( ctr );
        while (len--) {
          ctx->Xn[mres++] = out[n] = in[n] ^ ctx->EKi.c[n];
          ++n;
        }
      }

      ctx->mres = mres;
      return 0;
    } while (0);
  }
  for (i = 0; i < len; ++i) {
    if (n == 0) {
      fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
      ++ctr;
      ctx->Yi.d[3] = fd_uint_bswap( ctr );
    }
    ctx->Xn[mres++] = out[i] = in[i] ^ ctx->EKi.c[n];
    n = (n + 1) % 16;
    if (mres == sizeof(ctx->Xn)) {
      fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, sizeof(ctx->Xn) );
      mres = 0;
    }
  }

  ctx->mres = mres;
  return 0;
}

static int
fd_gcm128_decrypt( fd_aes_gcm_t * ctx,
                   uchar const *  in,
                   uchar *        out,
                   ulong          len ) {

  uint n, ctr, mres;
  ulong i;
  ulong mlen = ctx->len.u[1];
  void * key = &ctx->key;

  mlen += len;
  if (mlen > ((1UL<<36) - 32) || (sizeof(len) == 8 && mlen < len))
    return -1;
  ctx->len.u[1] = mlen;

  mres = ctx->mres;

  if (ctx->ares) {
    /* First call to decrypt finalizes GHASH(AAD) */
    if (len == 0) {
      fd_gcm_gmult_avx( ctx->Xi.u, ctx->Htable );
      ctx->ares = 0;
      return 0;
    }
    memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    mres = sizeof(ctx->Xi);
    ctx->ares = 0;
  }

  ctr = fd_uint_bswap( ctx->Yi.d[3] );

  n = mres % 16;
  if (16 % sizeof(ulong) == 0) { /* always true actually */
    do {
      if (n) {
        while (n && len) {
          *(out++) = (ctx->Xn[mres++] = *(in++)) ^ ctx->EKi.c[n];
          --len;
          n = (n + 1) % 16;
        }
        if (n == 0) {
          fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
          mres = 0;
        } else {
          ctx->mres = mres;
          return 0;
        }
      }
      if (len >= 16 && mres) {
        fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
        mres = 0;
      }
      if ((i = (len & (ulong)-16))) {
        fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, in, i );
        while (len >= 16) {
          ulong *out_t = (ulong *)out;
          const ulong *in_t = (const ulong *)in;

          fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
          ++ctr;
          ctx->Yi.d[3] = fd_uint_bswap( ctr );
          for (i = 0; i < 16 / sizeof(ulong); ++i)
              out_t[i] = in_t[i] ^ ctx->EKi.t[i];
          out += 16;
          in += 16;
          len -= 16;
        }
      }
      if (len) {
        fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
        ++ctr;
        ctx->Yi.d[3] = fd_uint_bswap( ctr );
        while (len--) {
          out[n] = (ctx->Xn[mres++] = in[n]) ^ ctx->EKi.c[n];
          ++n;
        }
      }

      ctx->mres = mres;
      return 0;
    } while (0);
  }
  for (i = 0; i < len; ++i) {
    uchar c;
    if (n == 0) {
      fd_aesni_encrypt( ctx->Yi.c, ctx->EKi.c, key );
      ++ctr;
      ctx->Yi.d[3] = fd_uint_bswap( ctr );
    }
    out[i] = (ctx->Xn[mres++] = c = in[i]) ^ ctx->EKi.c[n];
    n = (n + 1) % 16;
    if (mres == sizeof(ctx->Xn)) {
      fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, sizeof(ctx->Xn) );
      mres = 0;
    }
  }

  ctx->mres = mres;
  return 0;
}

void
fd_gcm128_finish( fd_aes_gcm_t * ctx ) {

  ulong alen = ctx->len.u[0] << 3;  // 176
  ulong clen = ctx->len.u[1] << 3;  // 9296

  struct {
    ulong hi;
    ulong lo;
  } bitlen;
  uint mres = ctx->mres;

  if( mres ) {
    uint blocks = (mres + 15u) & 0xfffffff0u; // 16

    memset(ctx->Xn + mres, 0, blocks - mres);
    mres = blocks;
    if (mres == sizeof(ctx->Xn)) {
      fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
      mres = 0;
    }
  } else if( ctx->ares ) {
    fd_gcm_gmult_avx( ctx->Xi.u, ctx->Htable );
  }

  alen = fd_ulong_bswap( alen );
  clen = fd_ulong_bswap( clen );

  bitlen.hi = alen;
  bitlen.lo = clen;
  memcpy( ctx->Xn + mres, &bitlen, sizeof(bitlen) );
  mres += (uint)sizeof(bitlen);
  fd_gcm_ghash_avx( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );

  ctx->Xi.u[0] ^= ctx->EK0.u[0];
  ctx->Xi.u[1] ^= ctx->EK0.u[1];
}

void
fd_aes_gcm_aead_encrypt( fd_aes_gcm_t * aes_gcm,
                         uchar *        c,
                         uchar const *  p,
                         ulong          sz,
                         uchar const *  aad,
                         ulong          aad_sz,
                         uchar          tag[ static 16 ] ) {

  fd_gcm128_aad( aes_gcm, aad, aad_sz );

  ulong bulk = 0UL;
  if( sz>=32UL ) {
    ulong res = (16UL - aes_gcm->mres ) % 16UL;
    FD_TEST( 0==fd_gcm128_encrypt( aes_gcm, p, c, res ) );
    bulk = fd_aesni_gcm_encrypt_private( p+res, c+res, sz-res, &aes_gcm->key, aes_gcm->Yi.c, aes_gcm->Xi.u );
    aes_gcm->len.u[1] += bulk;
    bulk += res;
  }

  FD_TEST( 0==fd_gcm128_encrypt( aes_gcm, p+bulk, c+bulk, sz-bulk ) );

  /* CRYPTO_gcm128_tag */
  fd_gcm128_finish( aes_gcm );
  fd_memcpy( tag, aes_gcm->Xi.c, 16 );
}

int
fd_aes_gcm_aead_decrypt( fd_aes_gcm_t * aes_gcm,
                         uchar const *  c,
                         uchar *        p,
                         ulong          sz,
                         uchar const *  aad,
                         ulong          aad_sz,
                         uchar const    tag[ static 16 ] ) {

  fd_gcm128_aad( aes_gcm, aad, aad_sz );

  ulong bulk = 0UL;
  if( sz>=16UL ) {
    ulong res = (16UL - aes_gcm->mres ) % 16UL;
    FD_TEST( 0==fd_gcm128_decrypt( aes_gcm, c, p, res ) );
    bulk = fd_aesni_gcm_decrypt_private( c+res, p+res, sz-res, &aes_gcm->key, aes_gcm->Yi.c, aes_gcm->Xi.u );
    aes_gcm->len.u[1] += bulk;
    bulk += res;
  }

  FD_TEST( 0==fd_gcm128_decrypt( aes_gcm, c+bulk, p+bulk, sz-bulk ) );

  /* CRYPTO_gcm128_finish */
  fd_gcm128_finish( aes_gcm );
  return 0==memcmp( aes_gcm->Xi.c, tag, 16 );  /* TODO USE CONSTANT TIME COMPARE */
}
