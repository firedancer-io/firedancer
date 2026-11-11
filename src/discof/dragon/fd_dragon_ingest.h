#ifndef HEADER_fd_src_discof_dragon_fd_dragon_ingest_h
#define HEADER_fd_src_discof_dragon_fd_dragon_ingest_h

/* fd_dragon_ingest.h reassembles the records the producer tiles send
   (see src/disco/events/generated/fd_event_internal_gen.h) out of the
   fragments of their links.

   One logical record is a run of consecutive fragments of one link:
   the first carries som and, in its signal, the record's type and total
   size; the last carries eom.  A record can be megabytes, so it is
   accumulated in a buffer of its own per link, which is why the module
   owns memory rather than pointing at the links.

   Nothing here fails on what it is given.  The fragments come from
   another tile over an unreliable link, so a fragment that cannot be
   part of a record, a record that claims a size the buffer cannot hold,
   and a run whose pieces do not add up are all counted and dropped.

   A fragment that does not follow the previous one of its link is the
   only evidence of an overrun the module needs, whichever way the tile
   lost the fragments in between: the record in progress is dropped and
   a gap is reported, because whole records may have gone missing
   too. */

#include "../../disco/events/fd_event_report.h"

#define FD_DRAGON_INGEST_ALIGN (128UL)

/* FD_DRAGON_INGEST_LINK_MAX bounds the links one instance serves. */

#define FD_DRAGON_INGEST_LINK_MAX (64UL)

struct fd_dragon_ingest_metrics {
  ulong record_cnt;      /* records reassembled */
  ulong multi_frag_cnt;  /* records that did not fit one fragment */
  ulong malformed_cnt;   /* records dropped for their framing */
  ulong gap_drop_cnt;    /* records in progress dropped because of a gap */
  ulong overrun_cnt;     /* gaps seen */
};

typedef struct fd_dragon_ingest_metrics fd_dragon_ingest_metrics_t;

struct fd_dragon_ingest;
typedef struct fd_dragon_ingest fd_dragon_ingest_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_dragon_ingest_align( void );

/* fd_dragon_ingest_footprint returns the memory one instance needs for
   link_cnt links, or 0 if link_cnt is out of range.  Each link gets a
   buffer for the largest record a producer can send. */

FD_FN_CONST ulong
fd_dragon_ingest_footprint( ulong link_cnt );

void *
fd_dragon_ingest_new( void * mem,
                      ulong  link_cnt );

fd_dragon_ingest_t *
fd_dragon_ingest_join( void * mem );

/* fd_dragon_ingest_frag takes one fragment of link link_idx.  data
   points at the fragment's payload and is copied, so it need not
   outlive the call.  Returns 1 if the fragment completed a record,
   which the caller reads with fd_dragon_ingest_record once it knows the
   fragment was not overrun while it was being read, and 0 otherwise. */

int
fd_dragon_ingest_frag( fd_dragon_ingest_t * ing,
                       ulong                link_idx,
                       ulong                seq,
                       ulong                sig,
                       ulong                ctl,
                       void const *         data,
                       ulong                sz );

/* fd_dragon_ingest_record points type, rec and rec_sz at the record
   link_idx last completed.  Valid until the next fragment of that
   link. */

void
fd_dragon_ingest_record( fd_dragon_ingest_t const * ing,
                         ulong                      link_idx,
                         ulong *                    opt_type,
                         void const **              opt_rec,
                         ulong *                    opt_rec_sz );

/* fd_dragon_ingest_next_seq returns the sequence number the next
   fragment of a link must have, or ULONG_MAX before its first.  The
   distance to what the producer has published is how close the link is
   to losing records. */

FD_FN_PURE ulong
fd_dragon_ingest_next_seq( fd_dragon_ingest_t const * ing,
                           ulong                      link_idx );

/* fd_dragon_ingest_gap_clear returns 1 if a gap has been seen since it
   was last called, and forgets it. */

int
fd_dragon_ingest_gap_clear( fd_dragon_ingest_t * ing );

FD_FN_PURE fd_dragon_ingest_metrics_t const *
fd_dragon_ingest_metrics( fd_dragon_ingest_t const * ing );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_ingest_h */
