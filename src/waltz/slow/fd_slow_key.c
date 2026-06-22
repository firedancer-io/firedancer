#include "fd_slow_key.h"
#include "../../ballet/hmac/fd_hkdf.h"

static uchar const fd_slow_initial_salt[ 20UL ] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
};

void
fd_slow_initial_secret( uchar         secret_out[ FD_SLOW_SECRET_SZ ],
                        uchar const * conn_id,
                        ulong         conn_id_sz ) {
  fd_hkdf_extract( secret_out, fd_slow_initial_salt, 20UL, conn_id, conn_id_sz );
}

void
fd_slow_initial_client_secret( uchar       secret_out    [ FD_SLOW_SECRET_SZ ],
                               uchar const initial_secret[ FD_SLOW_SECRET_SZ ] ) {
  fd_hkdf_expand_label_tls(
      secret_out, FD_SLOW_SECRET_SZ,
      initial_secret,
      "client in", 9UL,
      NULL, 0UL );
}

void
fd_slow_initial_server_secret( uchar       secret_out    [ FD_SLOW_SECRET_SZ ],
                               uchar const initial_secret[ FD_SLOW_SECRET_SZ ] ) {
  fd_hkdf_expand_label_tls(
      secret_out, FD_SLOW_SECRET_SZ,
      initial_secret,
      "server in", 9UL,
      NULL, 0UL );
}

void
fd_slow_secret_update( uchar       secret_out[ FD_SLOW_SECRET_SZ ],
                       uchar const secret_in [ FD_SLOW_SECRET_SZ ] ) {
  fd_hkdf_expand_label_tls(
      secret_out, FD_SLOW_SECRET_SZ,
      secret_in,
      "quic ku", 7UL,
      NULL, 0UL );
}

void
fd_slow_key_derive( uchar       key_out  [ FD_SLOW_KEY_SZ    ],
                    uchar       iv_out   [ FD_SLOW_IV_SZ     ],
                    uchar       hp_out   [ FD_SLOW_KEY_SZ    ],
                    uchar const secret_in[ FD_SLOW_SECRET_SZ ] ) {
  fd_hkdf_expand_label_tls(
      key_out, FD_SLOW_KEY_SZ,
      secret_in,
      "quic key", 8UL,
      NULL, 0UL );
  fd_hkdf_expand_label_tls(
      iv_out, FD_SLOW_IV_SZ,
      secret_in,
      "quic iv", 7UL,
      NULL, 0UL );
  fd_hkdf_expand_label_tls(
      hp_out, FD_SLOW_KEY_SZ,
      secret_in,
      "quic hp", 7UL,
      NULL, 0UL );
}
