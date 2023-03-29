#ifndef HEADER_fd_src_ballet_runtime_fd_clock_h
#define HEADER_fd_src_ballet_runtime_fd_clock_h

/* 
The clock sysvar provides an approximate measure of real-world time.
The initial value is derived from the genesis creation time:
https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2200

The clock is updated every slot, using a stake-weighted estimate of the latest
(timestamp, slot) values received from voting validators in vote instructions:
https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L24

Linear interpolation, using the Leader's PoH estimate for the real-world duration
of a slot, is then used to calculate the timestamp estimate for the current slot:

  timestamp = (stake-weighted votes timestamp) + ((PoH slot duration estimate) * (slots since votes were received))

This estimate is bounded to ensure it stays within a certain range of the PoH estimate:
https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/stake_weighted_timestamp.rs#L13
*/

#endif /* HEADER_fd_src_ballet_runtime_fd_clock_h */
