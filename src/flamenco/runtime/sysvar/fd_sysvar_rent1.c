#include "fd_sysvar_rent.h"
#include "../../types/fd_cast.h"

/* https://github.com/anza-xyz/solana-sdk/blob/rent%40v4.2.1/rent/src/lib.rs#L86 */
#define ACCOUNT_STORAGE_OVERHEAD (128UL)

/* Bit patterns of 1.0 and 2.0, the two exemption thresholds computed in
   integer arithmetic.
   https://github.com/anza-xyz/solana-sdk/blob/rent%40v4.2.1/rent/src/lib.rs#L59-L66 */

#define EXEMPTION_THRESHOLD_1_BITS (0x3ff0000000000000UL)
#define EXEMPTION_THRESHOLD_2_BITS (0x4000000000000000UL)

ulong
fd_rent_exempt_minimum_balance( fd_rent_t const * rent,
                                ulong             data_len ) {
  ulong bytes = data_len + ACCOUNT_STORAGE_OVERHEAD;

  /* For thresholds 1.0 and 2.0 the product is exact in integer
     arithmetic, whereas the double round trip below rounds it once it
     exceeds 2^53.  The threshold is matched bit-for-bit, as upstream
     compares the raw 8 bytes.
     https://github.com/anza-xyz/solana-sdk/blob/rent%40v4.2.1/rent/src/lib.rs#L136-L162 */

  ulong threshold_bits = fd_dblbits( rent->exemption_threshold );
  if( FD_LIKELY( threshold_bits==EXEMPTION_THRESHOLD_1_BITS ) ) return       bytes * rent->lamports_per_uint8_year;
  if( FD_LIKELY( threshold_bits==EXEMPTION_THRESHOLD_2_BITS ) ) return 2UL * bytes * rent->lamports_per_uint8_year;

  return fd_rust_cast_double_to_ulong( (double)( bytes * rent->lamports_per_uint8_year ) * rent->exemption_threshold );
}
