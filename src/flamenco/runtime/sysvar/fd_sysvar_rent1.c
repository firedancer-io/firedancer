#include "fd_sysvar_rent.h"

/* Moved into a separate compile unit to minimize dependencies on fd_funk */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L36 */
#define ACCOUNT_STORAGE_OVERHEAD (128)

ulong
fd_rent_exempt_minimum_balance( fd_rent_t const * rent,
                                ulong             data_len ) {
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/program/src/rent.rs#L74 */
  return fd_rust_cast_double_to_ulong( (double)((data_len + ACCOUNT_STORAGE_OVERHEAD) * rent->lamports_per_uint8_year) * rent->exemption_threshold );
}
