#include "fd_qos_entry.h"

#include "fd_qos_base.h"


int
fd_qos_atomic_cas_float( float * dest,
                         float * expected_value,
                         float * new_value ) {
  uint * ui_p_dest    = (uint*)fd_type_pun( dest );
  uint * ui_p_exp_val = (uint*)fd_type_pun( expected_value );
  uint * ui_p_new_val = (uint*)fd_type_pun( new_value );

  /* fetch once */
  uint   ui_exp_val   = *ui_p_exp_val;

  uint   updated_val  = __sync_val_compare_and_swap(
                          ui_p_dest,
                          ui_exp_val,
                          *ui_p_new_val );


  *ui_p_exp_val = updated_val;

  return updated_val == ui_exp_val;
}


void
fd_qos_atomic_add( float * member, float delta ) {
  /* simply use compare-and-swap to ensure the value is updated
   * correctly
   *
   * If there were an atomic floating point add, we could use it here */

  /* read the current value */
  float expected_value = *FD_VOLATILE( member );

  while(1) {
    /* do the calculation with the value read previously */
    float new_value = expected_value + delta;

    /* do compare-and-swap
     * expected_value will be updated to the value at *member immediately
     * prior to the swap, since it might have changed between fetching earlier
     * and here */
    if( FD_LIKELY( fd_qos_atomic_cas_float( member, &expected_value, &new_value ) ) ) {
      /* operation was successful */
      break;
    }

    /* if a race was detected, use the newly updated value for the next
     * iteration */
  }
}


void
fd_qos_atomic_mul_add( float * member, float scale, float addend ) {
  /* simply use compare-and-swap to ensure the value is updated correctly */

  /* read the current value */
  float expected_value = *FD_VOLATILE( member );

  while(1) {
    /* do the calculation with the value read previously */
    float new_value = scale * expected_value + addend;

    /* do compare-and-swap
     * expected_value will be updated to the value at *member immediately
     * prior to the swap, since it might have changed between fetching earlier
     * and here */
    if( FD_LIKELY( fd_qos_atomic_cas_float( member, &expected_value, &new_value ) ) ) {
      /* operation was successful */
      break;
    }

    /* if a race was detected, use the freshly fetched value for the next
     * iteration */
  }
}

/* atomically swaps the value at *value with replacement
 * and returns the value previosly there */
float
fd_qos_atomic_swap( float * value, float replacement ) {
  uint * u32_value = (uint*)fd_type_pun( value );
  uint * u32_repl  = (uint*)fd_type_pun( &replacement );
  uint   u32_rtn   = 0;

  u32_rtn = __atomic_exchange_n( u32_value, *u32_repl, __ATOMIC_SEQ_CST );

  return *(float*)fd_type_pun( &u32_rtn );
}


/* atomic transfer
 *
 * takes two pointers:
 *   accum
 *   delta
 *
 * it atomically swaps *delta with zero
 * it then atomically adds the old value of *delta to *accum
 */
void
fd_qos_atomic_xfer( float * accum, float * delta ) {
  float old_value = fd_qos_atomic_swap( delta, 0.0f );
  fd_qos_atomic_add( accum, old_value );
}


/* atomic ema
 *
 * takes two pointers:
 *   accum
 *   delta
 *
 * it decays the old values according to time, adds the new values
 * 
 */
void
fd_qos_atomic_ema( float * accum,
                   float * delta,
                   float   ema_scale ) {

  /* values are decayed according to ema_scale */ 
  float addend = fd_qos_atomic_swap( delta, 0.0f );

  /* scale old value, and add the new addend */
  fd_qos_atomic_mul_add( accum, ema_scale, addend );
}

/* apply all the updates from one entry to another */
void
fd_qos_delta_apply( fd_qos_entry_t * entry,
                    fd_qos_entry_t * delta,
                    float            decay ) {

  /* fetch new_time from delta */
  ulong new_time = delta->value.last_update;

  /* fetch old_time, but also update it to new_time */
  ulong old_time = __atomic_exchange_n( &entry->value.last_update,
                                        new_time,
                                        __ATOMIC_SEQ_CST );

  /* the lapsed time is used for the decay */
  long delta_time = (long)new_time - (long)old_time;

  /* calc scale factor from time and decay */
  float ema_scale = expf( decay * (float)delta_time );
  /* TODO use fast approximation of expf */

  /* profit is a simple total */
  fd_qos_atomic_add( &entry->value.stats.profit    , delta->value.stats.profit     );

  /* these are EMAs */
  fd_qos_atomic_ema( &entry->value.stats.txn_success , &delta->value.stats.txn_success , ema_scale );
  fd_qos_atomic_ema( &entry->value.stats.txn_fail    , &delta->value.stats.txn_fail    , ema_scale );
  fd_qos_atomic_ema( &entry->value.stats.sgn_success , &delta->value.stats.sgn_success , ema_scale );
  fd_qos_atomic_ema( &entry->value.stats.sgn_fail    , &delta->value.stats.sgn_fail    , ema_scale );
}

/* set values to zero */
void
fd_qos_entry_clear( fd_qos_entry_t * entry ) {
  entry->value.stats.profit      = 0.0f;
  entry->value.stats.txn_success = 0.0f;
  entry->value.stats.txn_fail    = 0.0f;
  entry->value.stats.sgn_success = 0.0f;
  entry->value.stats.sgn_fail    = 0.0f;
}

void
fd_qos_delta_update( float * ema,
                     float   decay,
                     float   delta,
                     long    decay_time ) {
  float current = *ema;

  /* calc scale factor from time and decay */
  float ema_scale = expf( decay * (float)decay_time );

  /* update local ema */
  *ema = ema_scale * current + delta;
}
