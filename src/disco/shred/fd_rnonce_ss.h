#ifndef HEADER_fd_src_disco_shred_fd_rnonce_ss_h
#define HEADER_fd_src_disco_shred_fd_rnonce_ss_h
#include "../../util/fd_util.h"

/* fd_rnonce_ss_t is a strongly typed version of the 64 byte shared
   secret used to generate and verify nonces for repair requests and
   responses. */
union fd_rnonce_ss {
  uchar bytes[64];
  struct {
    ulong ss0[3];
    ulong slot;
    ulong ss1[1];
    uint  shred_idx;
    uint  ss2[2];
    uint  time;
    ulong ss3[1];
  } private;
};
typedef union fd_rnonce_ss fd_rnonce_ss_t;
FD_STATIC_ASSERT( sizeof(fd_rnonce_ss_t)==64, rnonce_ss );

FD_PROTOTYPES_BEGIN

/* fd_rnonce_ss_{compute,verify} compute and verify, respectively, the
   nonce for the specifed repair request issued or received at time_ns.
   slot and shred_idx specify the slot and shred index of the
   requested/received shred.  normal_repair must be non-zero if the
   request is a "normal" repair request, i.e., one for a specific shred
   index.  If normal_repair is zero, shred_idx is ignored, and slot is
   adjusted (see below). ss is a pointer to the shared secret value.
   ss_compute returns the value of the nonce.  ss_verify takes the
   supposed value of the nonce in the nonce parameter.  ss_verify
   returns 1 if the nonce is correct and 0 otherwise.

   These satisfy:
   1==ss_verify( ss_v, ss_compute( ss_c, 1, slot_c, shred_idx_c, rq_time ), 1, slot_v, shred_idx_v, rs_time )
   when
      ss_v        == ss_c,
      slot_v      == slot_c,
      shred_idx_v == shred_idx_c, AND
      rq_time <= rs_time < rq_time + 1.02 seconds.
   When any of these of these conditions is false, it should return 0
   with high probability, approx (1 - 2^25).

   And
   1==ss_verify( ss_v, ss_compute( ss_c, 0, slot_c, shred_idx_c, rq_time ), 0, slot_v, shred_idx_v, rs_time )
   when
      ss_v        == ss_c,
      -1 <= floor(slot_v/128) - floor(slot_c/128) <= 0,  which is looser than slot_c - 128 <= slot_v <= slot_c
      rq_time <= rs_time < rq_time + 1.02 seconds.
   When any of these of these conditions is false, it should return 0
   with high probability, approx (1 - 2^25).
*/
static inline uint
fd_rnonce_ss_compute( fd_rnonce_ss_t const * ss,
                      int                    normal_repair,
                      ulong                  slot,
                      uint                   shred_idx,
                      long                   time_ns ) {
  fd_rnonce_ss_t temp[1] = { *ss };
  /* truncate time down to intervals of 2^32 ns, which is ~4 seconds. */
  temp->private.time      = (uint)(time_ns>>32);
  temp->private.slot      = fd_ulong_if( normal_repair, slot,      slot/128UL );
  temp->private.shred_idx = fd_uint_if ( normal_repair, shred_idx, 0U         );
  /* seed is fractional part of sqrt(17) */
  /* Then we add back in time_ns>>24 (truncated to 16ms intervals).
     This is kind of surprising, but it means that we can generate a new
     nonce when we re-request a specific shred, but we don't need to
     compute a ton of hashes. */
  return (uint)(
    fd_ulong_if( normal_repair, 0x80000000UL, 0UL ) |
    (0x7FFFFFFFUL & (fd_hash( 2270897969802886507UL, temp, sizeof(temp) ) + (((ulong)time_ns)>>24) ) ) );
}

static inline int
fd_rnonce_ss_verify( fd_rnonce_ss_t const * ss,
                     uint                   nonce,
                     ulong                  slot,
                     uint                   shred_idx,
                     long                   time_ns ) {
  fd_rnonce_ss_t temp[1] = { *ss };
  int normal_repair      = !!(nonce>>31);

  temp->private.time      = (uint)(time_ns>>32);
  temp->private.slot      = fd_ulong_if( normal_repair, slot,      slot/128UL );
  temp->private.shred_idx = fd_uint_if ( normal_repair, shred_idx, 0U         );
#define ALLOWED_TIME_DELTA ((uint)((1000000000UL + (1UL<<24) - 1UL)/(1UL<<24)))  /* == 60 */

#define CHECKN( temp ) do{ if( FD_LIKELY(                                                                                       \
                         ( (0x7FFFFFFFUL & (fd_hash( 2270897969802886507UL, temp, sizeof(temp) ) + (((ulong)time_ns)>>24) )) -  \
                           (0x7FFFFFFFUL & nonce) ) <= ALLOWED_TIME_DELTA ) )                                                   \
                             return 1;                                                                                          \
                       } while( 0 )


  CHECKN( temp );

  int try_prev_time = ((time_ns-1000000000L)>>32) != (time_ns>>32);
  if( try_prev_time ) {
    /* If that doesn't match, check the previous time bucket. */
    temp->private.time--;
    CHECKN( temp );
    temp->private.time++;
  }

  if( FD_UNLIKELY( !normal_repair ) ) {
    /* Check the next slot bucket */
    temp->private.slot++;
    CHECKN( temp );
    if( try_prev_time ) {
      /* And check it with the prev time bucket */
      temp->private.time--;
      CHECKN( temp );
    }
  }
#undef CHECKN
#undef ALLOWED_TIME_DELTA
  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_shred_fd_rnonce_ss_h */
