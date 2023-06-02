#include "fd_sysvar_epoch_schedule.h"
#include "../fd_types.h"
#include "fd_sysvar.h"
#include <math.h>

/* Has to be larger than MAX_LOCKOUT_HISTORY
   https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L21 */
#define MINIMUM_SLOTS_PER_EPOCH ( 32 )

void write_epoch_schedule( fd_global_ctx_t* global, fd_epoch_schedule_t* epoch_schedule ) {
  ulong          sz = fd_epoch_schedule_size( epoch_schedule );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_epoch_schedule_encode( epoch_schedule, &ctx ) )
    FD_LOG_ERR(("fd_epoch_schedule_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_epoch_schedule, enc, sz, global->bank.solana_bank.slot );
}

void fd_sysvar_epoch_schedule_read( fd_global_ctx_t* global, fd_epoch_schedule_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_epoch_schedule, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_epoch_schedule, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_epoch_schedule_decode( result, &ctx ) )
    FD_LOG_ERR(("fd_epoch_schedule_decode failed"));
}

void fd_sysvar_epoch_schedule_init( fd_global_ctx_t* global ) {
  write_epoch_schedule( global, &global->genesis_block.epoch_schedule );
}

/* Returns the number of trailing zeroes in the binary representation of x */
ulong trailing_zeroes( ulong x ) {
  ulong bits = 0;
  while ( ( x > 0 ) && ( ( x & 1 ) == 0 ) ) {
    bits += 1;
    x >>= 1;
  }
  return bits;
}

ulong saturating_pow( ulong x, ulong exp ) {
  double res = pow( (double)x, (double)exp );
  return fd_ulong_if( res == HUGE_VAL, ULONG_MAX, (ulong)res );
}

/* Get the number of slots in the given epoch
   https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L105 */
ulong get_slots_in_epoch( fd_global_ctx_t* global, ulong epoch ) {
  fd_epoch_schedule_t epoch_schedule;
  fd_sysvar_epoch_schedule_read( global, &epoch_schedule );

  if ( FD_UNLIKELY( epoch < epoch_schedule.first_normal_epoch ) ) {
    return saturating_pow(
      2,
      fd_uint_sat_add( (uint)epoch, (uint)trailing_zeroes( MINIMUM_SLOTS_PER_EPOCH ) ) );
  }
  else {
    return epoch_schedule.slots_per_epoch;
  }
}

/* Returns the next power of 2 >= x */
ulong next_power_of_2( ulong x ) {
  ulong power = 1;
  while ( power < x ) {
    power <<= 1;
  }
  return power;
}

/* Get the epoch and offset into the epoch for the given slot
   https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L140 */
void get_epoch_and_slot_idx( fd_global_ctx_t* global, ulong slot, ulong* res_epoch, ulong* res_idx ) {
  fd_epoch_schedule_t epoch_schedule;
  fd_sysvar_epoch_schedule_read( global, &epoch_schedule );

  if ( FD_UNLIKELY( slot < epoch_schedule.first_normal_slot ) ) {
    ulong epoch = fd_ulong_sat_sub(
      fd_ulong_sat_sub(
        trailing_zeroes(
          next_power_of_2(
            fd_ulong_sat_add(
              fd_ulong_sat_add(
                slot,
                MINIMUM_SLOTS_PER_EPOCH ),
              1 ) ) ),
        trailing_zeroes( MINIMUM_SLOTS_PER_EPOCH ) ),
      1 );

    ulong epoch_len = saturating_pow(
      2,
      fd_ulong_sat_add(
        epoch,
        trailing_zeroes( MINIMUM_SLOTS_PER_EPOCH ) ) );

    ulong idx = fd_ulong_sat_sub(
      slot,
      fd_ulong_sat_sub(
        epoch_len,
        MINIMUM_SLOTS_PER_EPOCH
      )
    );

    *res_epoch = epoch;
    *res_idx = idx;
  } else {
    ulong normal_slot_idx = fd_ulong_sat_sub( slot, epoch_schedule.first_normal_slot );
    /* TODO: checked div */
    ulong normal_epoch_idx = slot / epoch_schedule.slots_per_epoch;
    ulong epoch = fd_ulong_sat_add( epoch_schedule.first_normal_epoch, normal_epoch_idx );
    /* TODO: checked rem */
    ulong slot_idx = normal_slot_idx % epoch_schedule.slots_per_epoch;

    *res_epoch = epoch;
    *res_idx = slot_idx;
  }
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L170 */
ulong get_first_slot_in_epoch( fd_global_ctx_t* global, ulong epoch ) {
  fd_epoch_schedule_t epoch_schedule;
  fd_sysvar_epoch_schedule_read( global, &epoch_schedule );

  if ( FD_UNLIKELY( epoch < epoch_schedule.first_normal_epoch ) ) {
    return fd_ulong_sat_mul(
      fd_ulong_sat_sub(
        saturating_pow(
          2,
          epoch ),
        1 ),
      MINIMUM_SLOTS_PER_EPOCH );
  } else {
    return fd_ulong_sat_add(
      fd_ulong_sat_mul(
        fd_ulong_sat_sub(
          epoch,
          epoch_schedule.first_normal_epoch ),
        epoch_schedule.slots_per_epoch ),
      epoch_schedule.first_normal_slot );
  }
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L183 */
ulong get_last_slot_in_epoch( fd_global_ctx_t* global, ulong epoch ) {
  ulong first_slot_in_epoch = get_first_slot_in_epoch( global, epoch );
  ulong slots_in_epoch = get_slots_in_epoch( global, epoch );
  return fd_ulong_sat_sub( fd_ulong_sat_add( first_slot_in_epoch, slots_in_epoch ), 1 );
}
