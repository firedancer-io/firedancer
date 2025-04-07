#include "fd_snp_private.h"
#include "../../ballet/siphash13/fd_siphash13.h"

uchar *
snp_cookie_create(uchar cookie[static SNP_COOKIE_SZ],
                  snp_cookie_claims_t const *ctx,
                  uchar const cookie_secret[static SNP_COOKIE_KEY_SZ])
{
  *(ulong *)cookie = fd_siphash13_hash(
      ctx->b,
      SNP_COOKIE_CLAIMS_B_SZ,
      *(ulong *)cookie_secret,
      *(ulong *)(cookie_secret + 8));

  return cookie;
}

int snp_cookie_verify(uchar const cookie[static SNP_COOKIE_SZ],
                      snp_cookie_claims_t const *ctx,
                      uchar const cookie_secret[static SNP_COOKIE_KEY_SZ])
{

  uchar expected[SNP_COOKIE_KEY_SZ];
  snp_cookie_create(expected, ctx, cookie_secret);

  return (*(volatile ulong *)expected) == (*(volatile ulong *)cookie);
}

void snp_gen_session_id(uchar session_id[SNP_SESSION_ID_SZ])
{
  static fd_rng_t _rng[1];
  static int _done_init = 0;
  if( !_done_init ) {
    fd_rng_join( fd_rng_new( _rng, 3, 4 ) ); /* TODO - figure out correct args here */
    _done_init = 1;
  }

  ulong rnd_num = fd_rng_ulong( _rng );
  memcpy( session_id, &rnd_num, SNP_SESSION_ID_SZ );
  //FIXME: remove
  session_id[3] = (uchar)0xDE;
  session_id[4] = (uchar)0xAD;
  session_id[5] = (uchar)0xBE;
  session_id[6] = (uchar)0xEF;
}
