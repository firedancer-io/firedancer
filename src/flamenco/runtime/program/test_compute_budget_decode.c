/* Wire-format conformance tests for fd_compute_budget_instr_decode.

   Reference: Agave's ComputeBudgetInstruction is borsh-serialized:
     - 1-byte u8 discriminant
     - LE payload (u32 or u64 depending on variant)
     - Trailing bytes allowed (try_from_slice_unchecked)

   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.7/sdk/src/compute_budget.rs
   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.7/compute-budget-instruction/src/compute_budget_instruction_details.rs */

#include "fd_compute_budget_program.h"

static void
test_decode_request_heap_frame( void ) {
  FD_LOG_NOTICE(( "test_decode_request_heap_frame" ));
  uchar buf[] = { 0x01, 0x00, 0x40, 0x00, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant       == FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_HEAP_FRAME );
  FD_TEST( instr->request_heap_frame == 0x00004000U );
}

static void
test_decode_set_compute_unit_limit( void ) {
  FD_LOG_NOTICE(( "test_decode_set_compute_unit_limit" ));
  uchar buf[] = { 0x02, 0x40, 0x42, 0x0F, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant           == FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_LIMIT );
  FD_TEST( instr->set_compute_unit_limit == 1000000U );
}

static void
test_decode_set_compute_unit_price( void ) {
  FD_LOG_NOTICE(( "test_decode_set_compute_unit_price" ));
  /* borsh: disc=3, then 8-byte LE u64 = 12345 = 0x0000000000003039 */
  uchar buf[] = { 0x03, 0x39, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant           == FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_PRICE );
  FD_TEST( instr->set_compute_unit_price == 12345UL );
}

static void
test_decode_set_loaded_accounts_data_size_limit( void ) {
  FD_LOG_NOTICE(( "test_decode_set_loaded_accounts_data_size_limit" ));
  uchar buf[] = { 0x04, 0x00, 0x00, 0x10, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant                       == FD_COMPUTE_BUDGET_INSTR_DISC_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT );
  FD_TEST( instr->set_loaded_accounts_data_size_limit == 0x00100000U );
}

/* Variant 0 (Unused / RequestUnitsDeprecated) decodes successfully via
   borsh but Agave rejects it in the catch-all match arm.  We mirror:
   decode succeeds with disc=0; caller's switch/default rejects. */
static void
test_decode_unused_variant( void ) {
  FD_LOG_NOTICE(( "test_decode_unused_variant" ));
  uchar buf[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant == FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_UNITS_DEPRECATED );
}

/* Variant 0 borsh-deserializes as a unit variant in the latest Agave,
   but historically carried (u32, u32).  Our decoder requires 8 payload
   bytes to match the Firedancer historical wire shape. */
static void
test_decode_unused_variant_truncated( void ) {
  FD_LOG_NOTICE(( "test_decode_unused_variant_truncated" ));
  uchar buf[] = { 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) != 0 );
}

static void
test_decode_unknown_variants( void ) {
  FD_LOG_NOTICE(( "test_decode_unknown_variants" ));
  fd_compute_budget_instr_t instr[1];

  uchar buf5[] = { 0x05, 0x00, 0x00, 0x00, 0x00 };
  FD_TEST( fd_compute_budget_instr_decode( buf5, sizeof(buf5), instr ) != 0 );

  uchar bufFF[] = { 0xFF, 0x00, 0x00, 0x00, 0x00 };
  FD_TEST( fd_compute_budget_instr_decode( bufFF, sizeof(bufFF), instr ) != 0 );
}

static void
test_decode_empty( void ) {
  FD_LOG_NOTICE(( "test_decode_empty" ));
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( NULL, 0, instr ) != 0 );
}

static void
test_decode_truncated_payloads( void ) {
  FD_LOG_NOTICE(( "test_decode_truncated_payloads" ));
  fd_compute_budget_instr_t instr[1];

  /* disc=1 needs 4 payload bytes; only 3 present */
  uchar buf_short_u32[] = { 0x01, 0x00, 0x00, 0x00 };
  FD_TEST( fd_compute_budget_instr_decode( buf_short_u32, sizeof(buf_short_u32), instr ) != 0 );

  /* disc=3 needs 8 payload bytes; only 7 present */
  uchar buf_short_u64[] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  FD_TEST( fd_compute_budget_instr_decode( buf_short_u64, sizeof(buf_short_u64), instr ) != 0 );
}

/* Agave uses try_from_slice_unchecked which allows trailing bytes. */
static void
test_decode_trailing_bytes_allowed( void ) {
  FD_LOG_NOTICE(( "test_decode_trailing_bytes_allowed" ));
  uchar buf[] = { 0x01, 0x00, 0x40, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->discriminant       == FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_HEAP_FRAME );
  FD_TEST( instr->request_heap_frame == 0x00004000U );
}

/* Verify byte-for-byte against a known Agave-produced wire output.
   SetComputeUnitPrice(1_000_000) = borsh [3, 0x40,0x42,0x0F,0x00,0x00,0x00,0x00,0x00] */
static void
test_decode_known_agave_output( void ) {
  FD_LOG_NOTICE(( "test_decode_known_agave_output" ));
  uchar buf[] = { 0x03, 0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00 };
  fd_compute_budget_instr_t instr[1];
  FD_TEST( fd_compute_budget_instr_decode( buf, sizeof(buf), instr ) == 0 );
  FD_TEST( instr->set_compute_unit_price == 1000000UL );
}

/* Discriminant is a strict u8 per borsh.  A disc byte of 0x80 (128)
   should be rejected as an unknown variant, NOT decoded via multi-byte
   varint.  This distinguishes borsh u8 from the old compact_u16. */
static void
test_decode_disc_is_strict_u8( void ) {
  FD_LOG_NOTICE(( "test_decode_disc_is_strict_u8" ));
  fd_compute_budget_instr_t instr[1];

  uchar buf128[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x00 };
  FD_TEST( fd_compute_budget_instr_decode( buf128, sizeof(buf128), instr ) != 0 );
  FD_TEST( instr->discriminant == 0x80 );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_decode_request_heap_frame();
  test_decode_set_compute_unit_limit();
  test_decode_set_compute_unit_price();
  test_decode_set_loaded_accounts_data_size_limit();
  test_decode_unused_variant();
  test_decode_unused_variant_truncated();
  test_decode_unknown_variants();
  test_decode_empty();
  test_decode_truncated_payloads();
  test_decode_trailing_bytes_allowed();
  test_decode_known_agave_output();
  test_decode_disc_is_strict_u8();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
