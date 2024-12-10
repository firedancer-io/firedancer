#ifndef HEADER_fd_src_ballet_pack_fd_pack_pacing_h
#define HEADER_fd_src_ballet_pack_fd_pack_pacing_h

/* One of the keys to packing well is properly pacing CU consumption.
   Without pacing, pack will end up filling the block with non-ideal
   transactions.  Since at the current limits, the banks can execute a
   block worth of CUs in a fraction of the block time, without pacing,
   any lucrative transactions that arrive at towards the end of a block
   will have to be delayed until the next block (or another leader's
   block if it's the last in our rotation). */


struct fd_pack_pacing_private {
  /* Start and end time of block in ticks */
  long t_start;
  long t_end;
  /* Number of CUs in the block */
  ulong max_cus;

  float ticks_per_cu;
  float remaining_cus;
};

typedef struct fd_pack_pacing_private fd_pack_pacing_t;


/* fd_pack_pacing_init begins pacing for a slot which starts at now and
   ends at t_end (both measured in fd_tickcount() space) and will
   contain cus CUs.  cus in (0, 2^32). t_end - t_start should be about
   400ms or less, but must be in (0, 2^32) as well. */
static inline void
fd_pack_pacing_init( fd_pack_pacing_t * pacer,
                     long               t_start,
                     long               t_end,
                     float              ticks_per_ns,
                     ulong              max_cus ) {

  pacer->t_start = t_start;
  pacer->t_end   = t_end - (long)((t_start-t_end)/50L); /* try to finish 98% of the way through */
  pacer->max_cus = max_cus;

  /* Time per CU depends on the hardware, the transaction mix, what
     fraction of the transactions land, etc.  It's hard to just come up
     with a value, but a small sample says 8 ns/CU is in the right
     ballpark. */
  pacer->ticks_per_cu = 8.0f * ticks_per_ns;
  pacer->remaining_cus = (float)max_cus;
}

/* fd_pack_pacing_update_consumed_cus notes that the instantaneous value
   of consumed CUs may have updated.  pacer must be a local join.
   consumed_cus should be below the value of max_cus but it's treated as
   max_cus if it's larger.  Now should be the time (in fd_tickcount
   space) at which the measurement was taken.  */
static inline void
fd_pack_pacing_update_consumed_cus( fd_pack_pacing_t * pacer,
                                    ulong              consumed_cus,
                                    long               now ) {
  /* Keep this function separate so in the future we can learn the
     ticks_per_cu rate. */
  (void)now;
  /* It's possible (but unlikely) that consumed_cus can be greater than
     max_cus, so clamp the value at 0 */
  pacer->remaining_cus = (float)(fd_ulong_max( pacer->max_cus, consumed_cus ) - consumed_cus);
}


/* fd_pack_pacing_enabled_bank_cnt computes how many banks should be
   active at time `now` (in fd_tickcount space) given the most recent
   value specified for consumed CUs.  The returned value may be 0, which
   indicates that no banks should be active at the moment.  It may also
   be higher than the number of available banks, which should be
   interpreted as all banks being enabled. */
FD_FN_PURE static inline ulong
fd_pack_pacing_enabled_bank_cnt( fd_pack_pacing_t const * pacer,
                                 long                     now ) {
  /* We want to use as few banks as possible to fill the block in 400
     milliseconds.  That way we pass up the best transaction because it
     conflicts with something actively running as infrequently as
     possible.  To do that, we draw lines through in the time-CU plane
     that pass through (400 milliseconds, 48M CUs) with slope k*(single
     bank speed), where k varies between 1 and the number of bank tiles
     configured.  This splits the plane into several regions, and the
     region we are in tells us how many bank tiles to use.


       48M -                                                   / /|
           |                                                /  / /
           |                                             /   // |
       U   |                                          /    / / /
       s   |      0 banks active                   /     /  /  |
       e   |                                    /      /   /  /
       d   |                                 /    e  /    /   |
           |                              /  k  v  /     /   /
       C   |                           /   n  i  /      /    |
       U   |                        /    a  t  /       /    /
       s   |                     /     B  c  /        /     |
           |                  /     1   a  / 2 Banks /     /
           |               /             /   active / ...  |
       0   |--------------------------------------------------------
             0 ms                                                400ms
       */
  /* We want to be pretty careful with the math here.  We want to make
     sure we never divide by 0, so clamp the denominator at 1.  The
     numerator is non-negative.  Ticks_per_cu is between 1 and 100, so
     it'll always fit in a ulong. */
  return (ulong)(pacer->remaining_cus/
                 (float)(fd_long_max( 1L, pacer->t_end - now )) * pacer->ticks_per_cu );
}

#endif /* HEADER_fd_src_ballet_pack_fd_pack_pacing_h */
