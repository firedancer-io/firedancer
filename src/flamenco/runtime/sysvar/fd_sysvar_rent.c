#include "fd_sysvar_rent.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L36 */
#define ACCOUNT_STORAGE_OVERHEAD (128)

ulong
fd_rent_exempt_minimum_balance2( fd_rent_t const * rent,
                                 ulong             data_len ) {
  /* https://github.com/solana-labs/solana/blob/792fafe0c25ac06868e3ac80a2b13f1a5b4a1ef8/sdk/program/src/rent.rs#L72 */
  return (ulong)( (double)((data_len + ACCOUNT_STORAGE_OVERHEAD) * rent->lamports_per_uint8_year) * (double)rent->exemption_threshold );
}
