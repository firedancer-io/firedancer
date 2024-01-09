#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_encryption_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_encryption_h

#include "../../../../fd_flamenco_base.h"
#include "../../../../../ballet/ed25519/fd_ristretto255_ge.h"

FD_PROTOTYPES_BEGIN

void
fd_zktpp_encryption_placeholder( void const * placeholder );

/* Pedersen base point for encoding messages to be committed.
   This is the ed25519/ristretto255 basepoint. */
static const fd_ed25519_ge_p3_t fd_zktpp_basepoint_G[1] =
  {{
    {{{ 52811034, 25909283, 16144682, 17082669, 27570973, 30858332, 40966398,  8378388, 20764389,  8758491 }}},
    {{{ 40265304, 26843545, 13421772, 20132659, 26843545,  6710886, 53687091, 13421772, 40265318, 26843545 }}},
    {{{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}},
    {{{ 28827043, 27438313, 39759291,   244362,  8635006, 11264893, 19351346, 13413597, 16611511, 27139452 }}},
  }}
;

/* Pedersen base point for encoding the commitment openings.
   This is the hash-to-ristretto of sha3-512(G), with G in compressed form. */
static const fd_ed25519_ge_p3_t fd_zktpp_basepoint_H[1] =
  {{
    {{{ 40998203,  2063966, 1997403, 21910019, 10001302, 28340105, 31018068, 30247598, 44969459, 27978516 }}},
    {{{ 25049938, 21508463, 2957960, 12980313, 19086906, 27133103, 18563717,  9015235, 32151973, 11027403 }}},
    {{{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}},
    {{{ 21817739, 30341896, 1133171,  6916003, 24385560,  2838151, 12040266, 22392941, 46054120, 28975297 }}},
  }}
;

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_encryption_h */
