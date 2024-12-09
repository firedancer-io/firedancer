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

  ulong home_stretch_cutoff; /* in CUs, where the slope switches */
  float raw_slope; /* in ticks per CU */
  float offset;    /* in ticks */
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
                     ulong              max_cus ) {
   /* The exact style of pacing needs to be the subject of quantitative
   experimentation, so for now we're just doing something that passes
   the gut check.  We'll pace for 90% of the CUs through the first 75%
   of the block time, and then the last 10% through the last 25% of the
   block time.  This gives us pretty good tolerance against transactions
   taking longer to execute than we expect (the extreme of which being
   transactions that fail to land). */

  pacer->t_start = t_start;
  pacer->t_end   = t_end;
  pacer->max_cus = max_cus;

  pacer->raw_slope = (float)(t_end - t_start)/(float)max_cus;
  pacer->offset    = 1.5f * (float)(t_end - t_start); /* the math works out to be 1.5x */
  pacer->home_stretch_cutoff = (max_cus*9UL + 4UL)/10UL;
}

/* fd_pack_pacing_next returns the time (in fd_tickcount() space) at
   which the next attempt should be made to schedule transactions.

   The returned value will typically be between t_start and t_end, but
   may be slightly out of range due to rounding or if consumed_cus is
   larger than the max cu value provided in fd_pack_pacing_init.
   consumed_cus need not increase monotonically between calls.

   now should be the time at which the consumed_cus was measured.  It's
   not used right now, but is provided to allow for more sophisticated
   implementations in the future.

   fd_pack_pacing_init must have been called prior to the first call of
   fd_pack_pacing_next. */
static inline long
fd_pack_pacing_next( fd_pack_pacing_t * pacer,
                     ulong              consumed_cus,
                     long               now ) {
  (void)now;
  int non_home_stretch = consumed_cus < pacer->home_stretch_cutoff;
  return pacer->t_start + (long)( (float)consumed_cus * pacer->raw_slope * fd_float_if( non_home_stretch, 0.75f/0.9f, 0.25f/0.1f    )
                                                                         - fd_float_if( non_home_stretch, 0.0f,       pacer->offset ));
}

#endif /* HEADER_fd_src_ballet_pack_fd_pack_pacing_h */
