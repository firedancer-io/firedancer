#include "fd_stl_private.h"
#include "../../ballet/siphash13/fd_siphash13.h"

uchar *
stl_cookie_create(uchar cookie[static STL_COOKIE_SZ],
                  stl_cookie_claims_t const *ctx,
                  uchar const cookie_secret[static STL_COOKIE_KEY_SZ])
{
  *(ulong *)cookie = fd_siphash13_hash(
      ctx->b,
      STL_COOKIE_CLAIMS_B_SZ,
      *(ulong *)cookie_secret,
      *(ulong *)(cookie_secret + 8));

  return cookie;
}

int stl_cookie_verify(uchar const cookie[static STL_COOKIE_SZ],
                      stl_cookie_claims_t const *ctx,
                      uchar const cookie_secret[static STL_COOKIE_KEY_SZ])
{

  uchar expected[STL_COOKIE_KEY_SZ];
  stl_cookie_create(expected, ctx, cookie_secret);

  return (*(volatile ulong *)expected) == (*(volatile ulong *)cookie);
}

void stl_gen_session_id(uchar session_id[STL_SESSION_ID_SZ])
{
  static fd_rng_t _rng[1];
  static int _done_init = 0;
  if( !_done_init ) {
    fd_rng_join( fd_rng_new( _rng, 3, 4 ) ); /* TODO - figure out correct args here */
    _done_init = 1;
  }

  ulong rnd_num = fd_rng_ulong( _rng );
  memcpy( session_id, &rnd_num, STL_SESSION_ID_SZ );
  //FIXME: remove
  session_id[3] = (uchar)0xDE;
  session_id[4] = (uchar)0xAD;
  session_id[5] = (uchar)0xBE;
  session_id[6] = (uchar)0xEF;
}
