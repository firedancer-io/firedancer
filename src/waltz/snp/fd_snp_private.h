#ifndef HEADER_snp_private_h
#define HEADER_snp_private_h

/* snp_private.h contains reusable internal modules.  The APIs in this
   file may change without notice. */

#include "fd_snp_v1.h"
#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

void
snp_gen_session_id( ulong * session_id );

void
fd_snp_s0_crypto_key_share_generate( uchar private_key[32], uchar public_key[32] );

void
fd_snp_s0_crypto_enc_state_generate( uchar private_key_enc[48], uchar public_key[32], uchar const key[16] );

int
fd_snp_s0_crypto_enc_state_verify( uchar private_key[32], uchar const private_key_enc[48], uchar const public_key[32], uchar const key[16] );

FD_PROTOTYPES_END

#endif /* HEADER_snp_private_h */
