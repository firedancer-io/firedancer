/* Unit tests for fd_precompiles.c (native precompile instruction handlers).

   This file starts with Ed25519: one successful verify using the same
   signing vectors as test_ed25519.c (test_sign). */

#include "fd_precompiles.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/hex/fd_hex.h"

/* Mirrors packed layout in fd_precompiles.c (SIGNATURE_OFFSETS_SERIALIZED_SIZE). */
struct __attribute__((packed)) fd_precompile_ed25519_offsets_wire {
  ushort sig_offset;
  ushort sig_instr_idx;
  ushort pubkey_offset;
  ushort pubkey_instr_idx;
  ushort msg_offset;
  ushort msg_data_sz;
  ushort msg_instr_idx;
};

FD_STATIC_ASSERT( sizeof(struct fd_precompile_ed25519_offsets_wire)==14UL, layout );

#define PRECOMPILE_ED25519_SIG_COUNT_OFF     (0UL)
#define PRECOMPILE_ED25519_OFFSETS_START     (2UL) /* SIGNATURE_OFFSETS_START */
#define PRECOMPILE_ED25519_PAYLOAD_MIN       (PRECOMPILE_ED25519_OFFSETS_START + sizeof(struct fd_precompile_ed25519_offsets_wire))

/* Offsets are relative to the current instruction's data when instr_idx==USHORT_MAX. */
#define TEST_ED25519_SIG_OFF     (PRECOMPILE_ED25519_PAYLOAD_MIN)
#define TEST_ED25519_PUB_OFF     (TEST_ED25519_SIG_OFF + 64UL)
#define TEST_ED25519_MSG_OFF     (TEST_ED25519_PUB_OFF + 32UL)

static void
test_ed25519_precompile_verify_ok( void ) {
  FD_LOG_NOTICE(( "test_ed25519_precompile_verify_ok" ));

  /* Same key material as test_ed25519.c:test_sign (known-good signature for empty msg). */
  uchar prv[ 32 ];
  uchar pub[ 32 ];
  uchar sig[ 64 ];
  fd_hex_decode( prv, "57835dc6a20e4efd70e90882dbd832b577dbc469960284e0ee718fb526d2ec84", 32UL );

  fd_sha512_t sha[ 1 ];
  fd_ed25519_public_from_private( pub, prv, sha );

  uchar const * msg     = (uchar const *)"hello";
  ulong         msg_len = 5UL;
  fd_ed25519_sign( sig, msg, msg_len, pub, prv, sha );

  fd_instr_info_t instr[ 1 ];
  fd_memset( instr, 0, sizeof( instr ) );

  uchar * d = instr->data;
  d[ PRECOMPILE_ED25519_SIG_COUNT_OFF ] = 1;

  struct fd_precompile_ed25519_offsets_wire * offs =
    (struct fd_precompile_ed25519_offsets_wire *)(d + PRECOMPILE_ED25519_OFFSETS_START);
  offs->sig_offset       = (ushort)TEST_ED25519_SIG_OFF;
  offs->sig_instr_idx    = USHORT_MAX;
  offs->pubkey_offset    = (ushort)TEST_ED25519_PUB_OFF;
  offs->pubkey_instr_idx = USHORT_MAX;
  offs->msg_offset       = (ushort)TEST_ED25519_MSG_OFF;
  offs->msg_data_sz      = (ushort)msg_len;
  offs->msg_instr_idx    = USHORT_MAX;

  fd_memcpy( d + TEST_ED25519_SIG_OFF, sig, 64UL );
  fd_memcpy( d + TEST_ED25519_PUB_OFF, pub, 32UL );
  fd_memcpy( d + TEST_ED25519_MSG_OFF, msg, msg_len );

  ulong const total = TEST_ED25519_MSG_OFF + msg_len;
  FD_TEST( total <= FD_INSTR_DATA_MAX );
  instr->data_sz = (ushort)total;

  fd_exec_instr_ctx_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof( ctx ) );
  ctx->instr   = instr;
  ctx->txn_in  = NULL;
  ctx->txn_out = NULL;

  FD_TEST( fd_precompile_ed25519_verify( ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  instr->data[ 1 ] = 0xFF;
  FD_TEST( fd_precompile_ed25519_verify( ctx )==FD_EXECUTOR_INSTR_SUCCESS );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_ed25519_precompile_verify_ok();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
