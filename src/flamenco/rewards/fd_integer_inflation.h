#ifndef HEADER_fd_src_flamenco_rewards_fd_integer_inflation_h
#define HEADER_fd_src_flamenco_rewards_fd_integer_inflation_h

/* fd_integer_inflation is the implementation of
   remove_runtime_float_ops and double_disinflation_rate: computing
   the inflation rate without using floating point operations. */

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

/* fd_integer_inflation_epoch_rewards returns the inflation rewards
   in lamports for the given epoch, using the integer calculation path.
   This function should be used to calculate the inflation rewards
   once remove_runtime_float_ops is active.

   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3155-L3172 */

ulong
fd_integer_inflation_epoch_rewards( fd_bank_t const * bank,
                                    ulong             inflation_start_slot,
                                    ulong             capitalization,
                                    ulong             epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_integer_inflation_h */
