#ifndef HEADER_fd_src_disco_gui_fd_gui_gossip_bw_h
#define HEADER_fd_src_disco_gui_fd_gui_gossip_bw_h

/* fd_gui_gossip_bw aggregates the per-peer gossip byte counts the gui
   shows.  The gossip tile (egress, keyed by destination socket) and
   each gossvf tile (ingress, keyed by source socket) add every packet
   they already handle, keyed by (ip4, port, message tag), and publish
   the aggregates to the gui at most every FD_GUI_GOSSIP_BW_FLUSH_NS
   instead of the gui reading every raw packet.  The gui attributes
   each record to a peer by socket when it applies it, the same lookup
   it did per packet.  Records are only ever summed, so the byte
   counts match the per packet path exactly; they reach the gui's
   150 ms rate windows at most one flush interval later. */

#include "../../util/bits/fd_bits.h"
#include "../metrics/generated/fd_metrics_enums.h"

struct fd_gui_gossip_bw_rec {
  uint   ip4;  /* net order */
  ushort port; /* net order */
  ushort tag;  /* in [0,FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT) */
  ulong  sz;   /* sum of gossip payload bytes */
};

typedef struct fd_gui_gossip_bw_rec fd_gui_gossip_bw_rec_t;

#define FD_GUI_GOSSIP_BW_REC_MAX     (256UL)
#define FD_GUI_GOSSIP_BW_MTU         (FD_GUI_GOSSIP_BW_REC_MAX*sizeof(fd_gui_gossip_bw_rec_t))
#define FD_GUI_GOSSIP_BW_LG_SLOT_CNT (9)
#define FD_GUI_GOSSIP_BW_FLUSH_NS    (10L*1000L*1000L)

#define FD_GUI_GOSSIP_BW_ALIGN (128UL)
#define FD_GUI_GOSSIP_BW_MAGIC (0xf17eda2c37b0b500UL) /* firedancer gui bw ver 0 */

/* Pending byte counts, keyed by ip4 | port<<32 | tag<<48 (tag is
   below FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT, so no key is ULONG_MAX). */

struct fd_gui_gossip_bw_ele {
  ulong key;
  ulong sz;
};

typedef struct fd_gui_gossip_bw_ele fd_gui_gossip_bw_ele_t;

#define MAP_NAME         fd_gui_gossip_bw_map
#define MAP_T            fd_gui_gossip_bw_ele_t
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) ((k)==ULONG_MAX)
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(FD_GUI_GOSSIP_BW_ALIGN))) fd_gui_gossip_bw_private {
  ulong                    magic;    /* ==FD_GUI_GOSSIP_BW_MAGIC */
  long                     flush_ticks;
  long                     deadline; /* tickcount the pending records are due, LONG_MAX if none */
  fd_gui_gossip_bw_ele_t * map;
};

typedef struct fd_gui_gossip_bw_private fd_gui_gossip_bw_t;

FD_PROTOTYPES_BEGIN

/* fd_gui_gossip_bw_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a gui_gossip_bw. */

FD_FN_CONST ulong
fd_gui_gossip_bw_align( void );

FD_FN_CONST ulong
fd_gui_gossip_bw_footprint( void );

/* fd_gui_gossip_bw_new formats an unused memory region for use as a
   gui_gossip_bw with no pending records.  seed seeds the key hash.
   Returns shmem on success and NULL on failure (logs details). */

void *
fd_gui_gossip_bw_new( void * shmem,
                      ulong  seed );

fd_gui_gossip_bw_t *
fd_gui_gossip_bw_join( void * shbw );

void *
fd_gui_gossip_bw_leave( fd_gui_gossip_bw_t const * bw );

void *
fd_gui_gossip_bw_delete( void * shbw );

/* fd_gui_gossip_bw_add counts a gossip payload sent to or received
   from ip4:port (net order) at tickcount now.  Payloads the gui does
   not attribute (too short for a tag, unknown tag) are ignored.
   Returns 1 if the table is full and must be flushed before the next
   add. */

static inline int
fd_gui_gossip_bw_add( fd_gui_gossip_bw_t * bw,
                      uint                 ip4,
                      ushort               port,
                      uchar const *        payload,
                      ulong                payload_sz,
                      long                 now ) {
  if( FD_UNLIKELY( payload_sz<sizeof(uint) ) ) return 0;
  uint tag = FD_LOAD( uint, payload );
  if( FD_UNLIKELY( tag>=FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ) ) return 0;

  ulong key = (ulong)ip4 | ((ulong)port<<32) | ((ulong)tag<<48);
  fd_gui_gossip_bw_ele_t * ele = fd_gui_gossip_bw_map_query( bw->map, key, NULL );
  if( FD_LIKELY( ele ) ) {
    ele->sz += payload_sz;
    return 0;
  }

  if( FD_UNLIKELY( !fd_gui_gossip_bw_map_key_cnt( bw->map ) ) ) bw->deadline = now + bw->flush_ticks;
  fd_gui_gossip_bw_map_insert( bw->map, key )->sz = payload_sz;
  return fd_gui_gossip_bw_map_key_cnt( bw->map )==FD_GUI_GOSSIP_BW_REC_MAX;
}

/* fd_gui_gossip_bw_due returns 1 if there are records and they are due
   at tickcount now. */

static inline int
fd_gui_gossip_bw_due( fd_gui_gossip_bw_t const * bw,
                      long                       now ) {
  return fd_gui_gossip_bw_map_key_cnt( bw->map ) && now>=bw->deadline;
}

/* fd_gui_gossip_bw_next_deadline returns the tickcount the pending
   records are due, LONG_MAX if there are none. */

static inline long
fd_gui_gossip_bw_next_deadline( fd_gui_gossip_bw_t const * bw ) {
  return fd_gui_gossip_bw_map_key_cnt( bw->map ) ? bw->deadline : LONG_MAX;
}

/* fd_gui_gossip_bw_flush copies the pending records to out (room for
   FD_GUI_GOSSIP_BW_REC_MAX) and empties the table.  Returns the number
   of records copied. */

static inline ulong
fd_gui_gossip_bw_flush( fd_gui_gossip_bw_t *     bw,
                        fd_gui_gossip_bw_rec_t * out ) {
  ulong cnt      = 0UL;
  ulong slot_cnt = fd_gui_gossip_bw_map_slot_cnt( bw->map );
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    fd_gui_gossip_bw_ele_t const * ele = bw->map + i;
    if( fd_gui_gossip_bw_map_key_inval( ele->key ) ) continue;
    out[ cnt++ ] = (fd_gui_gossip_bw_rec_t){ .ip4 = (uint)ele->key, .port = (ushort)(ele->key>>32), .tag = (ushort)(ele->key>>48), .sz = ele->sz };
  }
  fd_gui_gossip_bw_map_clear( bw->map );
  bw->deadline = LONG_MAX;
  return cnt;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_gossip_bw_h */
