#ifndef HEADER_fd_src_waltz_slow_fd_slow_key_h
#define HEADER_fd_src_waltz_slow_fd_slow_key_h

/* fd_slow_key.h deals with QUIC encryption keys. */

#include "fd_slow_base.h"

#define FD_SLOW_KEY_SZ     16
#define FD_SLOW_IV_SZ      12
#define FD_SLOW_SECRET_SZ  32

#define FD_SLOW_KEY_MAX    FD_SLOW_KEY_SZ
#define FD_SLOW_IV_MAX     FD_SLOW_IV_SZ
#define FD_SLOW_SECRET_MAX FD_SLOW_SECRET_SZ

void
fd_slow_initial_secret( uchar         secret_out[ FD_SLOW_SECRET_SZ ],
                        uchar const * conn_id,
                        ulong         conn_id_sz );

void
fd_slow_initial_client_secret( uchar       secret_out    [ FD_SLOW_SECRET_SZ ],
                               uchar const initial_secret[ FD_SLOW_SECRET_SZ ] );

void
fd_slow_initial_server_secret( uchar       secret_out    [ FD_SLOW_SECRET_SZ ],
                               uchar const initial_secret[ FD_SLOW_SECRET_SZ ] );

void
fd_slow_secret_update( uchar       secret_out[ FD_SLOW_SECRET_SZ ],
                       uchar const secret_in [ FD_SLOW_SECRET_SZ ] );

void
fd_slow_key_derive( uchar       key_out  [ FD_SLOW_KEY_SZ    ],
                    uchar       iv_out   [ FD_SLOW_IV_SZ     ],
                    uchar       hp_out   [ FD_SLOW_KEY_SZ    ],
                    uchar const secret_in[ FD_SLOW_SECRET_SZ ] );

#endif /* HEADER_fd_src_waltz_slow_fd_slow_key_h */
