/* ag_viz drives the real consensus core -- ag_pool and ag_votor -- from a
   simulated cluster and draws what it does in the terminal: votes and certs
   arriving, per-slot vote aggregation crossing the quorum thresholds, and the
   notarized / finalized / skipped verdicts that fall out of it.

   Everything drawn is read back out of the pool and the votor.  The
   simulation only supplies what a validator does not compute itself: peer
   votes, peer certs, network latency and loss, leader crashes, equivocating
   leaders, and the clock.  Our own votes come from a real ag_votor_t whose
   pool events, blockstore events and timeouts are dispatched exactly the way
   the votor tile dispatches them.

   Keys: [c] crash the next leader window   [f] fork the next slot
         [s] slashable double vote          [w] withhold votes, send a cert
         [p] partition a third of stake     [space] pause  [q] quit

   Examples:
     ag_viz --validators 21 --slot-ms 250 --speed 2 --warmup-slots 24
     ag_viz --frames 1 --warmup-slots 30 --no-color --ascii   (one static frame,
       deterministic for a given --seed, for capturing into a log or a diff) */

#include "../consensus/ag_pool.h"
#include "../consensus/ag_votor.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* ---------------------------------------------------------------- canvas */

/* The frame is composed into a cell grid and flushed as one write, so
   panels can sit side by side without escape sequences confusing the
   column arithmetic. */

#define CV_ROWS (128UL)
#define CV_COLS (400UL)

#define A_NONE  ( 0)
#define A_DIM   ( 1)
#define A_TITLE ( 2)
#define A_HDR   ( 3)
#define A_NOTAR ( 4)
#define A_FORK  ( 5)
#define A_NFB   ( 6)
#define A_SKIP  ( 7)
#define A_FINAL ( 8)
#define A_FAST  ( 9)
#define A_CERT  (10)
#define A_OWN   (11)
#define A_WARN  (12)
#define A_BAD   (13)
#define A_TICK  (14)
#define A_SFB   (15)
#define A_ATTR_CNT (16)

static char const * g_sgr[ A_ATTR_CNT ] = {
  "\033[0m",       /* NONE  */
  "\033[38;5;242m",/* DIM   */
  "\033[1;97m",    /* TITLE */
  "\033[38;5;110m",/* HDR   */
  "\033[38;5;41m", /* NOTAR */
  "\033[38;5;177m",/* FORK  */
  "\033[38;5;221m",/* NFB   */
  "\033[38;5;203m",/* SKIP  */
  "\033[38;5;39m", /* FINAL */
  "\033[1;38;5;207m", /* FAST */
  "\033[38;5;80m", /* CERT  */
  "\033[1;38;5;123m", /* OWN */
  "\033[38;5;214m",/* WARN  */
  "\033[1;38;5;196m", /* BAD */
  "\033[38;5;238m",/* TICK  */
  "\033[38;5;167m" /* SFB   */
};

struct cv_cell {
  char  c[ 5 ];
  uchar attr;
};

static struct cv_cell g_cv[ CV_ROWS ][ CV_COLS ];
static ulong          g_rows = 40UL;
static ulong          g_cols = 120UL;
static int            g_color = 1;
static int            g_tty   = 0;

/* glyph table, swapped out by --ascii */

static struct {
  char const * full;
  char const * fork;
  char const * half;
  char const * lite;
  char const * dot;
  char const * tick;
  char const * hbar;
  char const * vbar;
  char const * tl;
  char const * tr;
  char const * bl;
  char const * br;
  char const * arrow;
  char const * down;
  char const * star;
} g;

static void
glyphs_init( int ascii ) {
  if( ascii ) {
    g.full="#"; g.fork="%"; g.half="="; g.lite="-"; g.dot="."; g.tick=":";
    g.hbar="-"; g.vbar="|"; g.tl="+"; g.tr="+"; g.bl="+"; g.br="+";
    g.arrow=">"; g.down="v"; g.star="*";
  } else {
    g.full="█"; g.fork="▚"; g.half="▓"; g.lite="▒"; g.dot="·"; g.tick="┊";
    g.hbar="─"; g.vbar="│"; g.tl="┌"; g.tr="┐"; g.bl="└"; g.br="┘";
    g.arrow="▸"; g.down="↓"; g.star="★";
  }
}

static void
cv_clear( void ) {
  for( ulong r=0UL; r<g_rows; r++ ) {
    for( ulong c=0UL; c<g_cols; c++ ) {
      g_cv[r][c].c[0]  = ' ';
      g_cv[r][c].c[1]  = '\0';
      g_cv[r][c].attr  = A_NONE;
    }
  }
}

static void
cv_put( ulong        r,
        ulong        c,
        int          attr,
        char const * glyph ) {
  if( FD_UNLIKELY( r>=g_rows || c>=g_cols ) ) return;
  ulong n = strlen( glyph );
  if( FD_UNLIKELY( n>4UL ) ) n = 4UL;
  memcpy( g_cv[r][c].c, glyph, n );
  g_cv[r][c].c[n] = '\0';
  g_cv[r][c].attr = (uchar)attr;
}

/* cv_text writes a string one codepoint per cell (so a multi-byte glyph
   costs one column) and returns the column just past it. */

static ulong
cv_text( ulong        r,
         ulong        c,
         int          attr,
         char const * fmt,
         ... ) {
  char buf[ 4UL*CV_COLS ];
  va_list ap;
  va_start( ap, fmt );
  int n = vsnprintf( buf, sizeof(buf), fmt, ap );
  va_end( ap );
  if( FD_UNLIKELY( n<0 ) ) return c;

  ulong i = 0UL;
  while( i<(ulong)n ) {
    ulong len = 1UL;
    uchar b   = (uchar)buf[i];
    if     ( b>=0xf0U ) len = 4UL;
    else if( b>=0xe0U ) len = 3UL;
    else if( b>=0xc0U ) len = 2UL;
    if( i+len>(ulong)n ) len = 1UL;
    char s[5];
    memcpy( s, buf+i, len );
    s[len] = '\0';
    cv_put( r, c++, attr, s );
    i += len;
  }
  return c;
}

static void
cv_fill( ulong        r,
         ulong        c0,
         ulong        c1,
         int          attr,
         char const * glyph ) {
  for( ulong c=c0; c<c1; c++ ) cv_put( r, c, attr, glyph );
}

static void
cv_box( ulong        r0,
        ulong        c0,
        ulong        r1,
        ulong        c1,
        int          attr,
        char const * title ) {
  if( FD_UNLIKELY( r1<=r0+1UL || c1<=c0+1UL ) ) return;
  cv_fill( r0, c0+1UL, c1-1UL, attr, g.hbar );
  cv_fill( r1-1UL, c0+1UL, c1-1UL, attr, g.hbar );
  for( ulong r=r0+1UL; r<r1-1UL; r++ ) { cv_put( r, c0, attr, g.vbar ); cv_put( r, c1-1UL, attr, g.vbar ); }
  cv_put( r0, c0, attr, g.tl ); cv_put( r0, c1-1UL, attr, g.tr );
  cv_put( r1-1UL, c0, attr, g.bl ); cv_put( r1-1UL, c1-1UL, attr, g.br );
  if( title ) cv_text( r0, c0+2UL, A_HDR, " %s ", title );
}

static char g_out[ 1UL<<20 ];

static void
cv_flush( void ) {
  ulong o = 0UL;

#define EMIT(...) do { int _n = snprintf( g_out+o, sizeof(g_out)-o, __VA_ARGS__ ); \
                       if( _n>0 ) o += (ulong)_n; } while(0)

  if( g_tty ) EMIT( "\033[H" );
  for( ulong r=0UL; r<g_rows; r++ ) {
    ulong last = 0UL;
    for( ulong c=0UL; c<g_cols; c++ ) if( g_cv[r][c].c[0]!=' ' || g_cv[r][c].c[1] ) last = c+1UL;
    if( g_tty ) EMIT( "\033[%lu;1H", r+1UL );
    int attr = A_NONE;
    if( g_color ) EMIT( "%s", g_sgr[ A_NONE ] );
    for( ulong c=0UL; c<last; c++ ) {
      if( g_color && g_cv[r][c].attr!=attr ) {
        attr = g_cv[r][c].attr;
        EMIT( "%s", g_sgr[ attr ] );
      }
      EMIT( "%s", g_cv[r][c].c );
    }
    if( g_color ) EMIT( "%s", g_sgr[ A_NONE ] );
    if( g_tty ) EMIT( "\033[K" );
    else        EMIT( "\n" );
  }
  if( g_tty ) EMIT( "\033[J" );
#undef EMIT

  ulong off = 0UL;
  while( off<o ) {
    long w = write( STDOUT_FILENO, g_out+off, o-off );
    if( w<=0L ) break;
    off += (ulong)w;
  }
}

/* ------------------------------------------------------------ simulation */

#define VTR_MAX     ( 64UL)
#define LADDER_MAX  (256UL)
#define EV_MAX      (8192UL)
#define TMO_MAX     (4096UL)
#define FEED_MAX    (128UL)
#define VARIANT_MAX (  2UL)

#define STANDSTILL_CERT_MAX (256UL)
#define STANDSTILL_VOTE_MAX (256UL)

/* network / local events, all timestamped on the virtual clock */

#define EV_VOTE  (0) /* a peer's vote arrives (signed on delivery)         */
#define EV_CERT  (1) /* a peer's cert arrives, aggregated from ev->mask    */
#define EV_SHRED (2) /* our replay saw the leader's first shred            */
#define EV_BLOCK (3) /* our replay completed the block                    */

struct ev {
  long  ts;
  int   used;
  int   kind;
  ulong from;      /* EV_VOTE: peer id                                    */
  uint  vote_kind; /* EV_VOTE: AG_VOTE_TYPE_*                             */
  uint  cert_kind; /* EV_CERT: AG_CERT_TYPE_*                             */
  ulong slot;
  ulong variant;   /* which block of an equivocating leader               */
  ulong mask;      /* EV_CERT: voters aggregated into the cert            */
  int   evil;      /* EV_VOTE: vote for a hash nobody proposed            */
};

struct tmo {
  long  ts;
  int   used;
  uint  kind;
  ulong slot;
};

struct feed {
  long ts;
  int  attr;
  char text[ 160 ];
};

struct slot_row {
  ulong     slot;
  int       used;
  ulong     leader;
  int       crashed;
  int       forked;
  fd_hash_t blk[ VARIANT_MAX ];
  ulong     blk_cnt;
  ag_block_id_t parent;

  /* who voted what, from votes the pool accepted.  Stake is derived from
     the masks at render time so a voter that notarizes and then
     notarize-fallbacks the same block is only counted once. */
  ulong notar_mask[ VARIANT_MAX ];
  ulong nfb_mask;
  ulong skip_mask;
  ulong skip_fb_mask;
  ulong final_mask;
  ulong r1_mask;

  /* peers whose fallback votes are already in flight, so a peer decides
     each fallback at most once */
  ulong nfb_sched[ VARIANT_MAX ];
  ulong sfb_sched;
  ulong skip_sched;

  ulong cert_mask;            /* 1<<AG_CERT_TYPE_*, from CERT_CREATED     */
  ulong cert_short_mask;      /* certs we built that miss the quorum      */
  int   cert_in;              /* a cert for this slot came off the network */
  int   slashed;

  long  t_open;
  long  t_notar;
  long  t_final;

  int   we_notar;
  int   we_nfb;
  int   we_skip;
  int   we_final;
};

struct viz {
  /* config */
  ulong  nv;
  ulong  own_id;
  long   slot_ns;
  long   lat_ns;
  long   jit_ns;
  long   replay_ns;
  ulong  drop_pct;
  ulong  crash_pct;
  ulong  fork_pct;
  ulong  cert_pct;
  ulong  offline_pct;
  ushort shred_version;
  long   frame_ns;

  /* cluster */
  ag_aggsig_sk_t      sk  [ VTR_MAX ];
  ag_validator_info_t info[ VTR_MAX ];
  long                lat [ VTR_MAX ];
  int                 offline[ VTR_MAX ];
  ulong               total_stake;
  ulong               silent_mask;
  long                silent_until;

  /* core under test */
  ag_pool_t *       pool;
  ag_votor_t *      votor;
  ag_epoch_info_t * epoch_info; /* our own copy, for cert threshold checks */

  /* virtual clock */
  long now;
  long next_slot;
  long next_frame;
  long next_standstill;

  /* chain */
  ulong         slot;      /* next slot to open        */
  ulong         hi_slot;   /* highest slot opened      */
  ag_block_id_t tip;       /* canonical chain tip      */
  int           window_crashed;
  ulong         window;    /* window of window_crashed */

  struct slot_row row[ LADDER_MAX ];
  struct ev       ev [ EV_MAX     ];
  struct tmo      tmo[ TMO_MAX    ];
  struct feed     feed[ FEED_MAX  ];
  ulong           feed_cnt;

  /* counters */
  ulong rx_vote_ok, rx_vote_dup, rx_vote_slash, rx_vote_oob, rx_vote_sig, rx_vote_unk;
  ulong rx_kind[ 5 ];          /* accepted votes by AG_VOTE_TYPE_*      */
  ulong own_kind[ 5 ];         /* our own votes by AG_VOTE_TYPE_*       */
  ulong rx_cert_ok, rx_cert_dup, rx_cert_thr, rx_cert_oob, rx_cert_sig;
  ulong tx_vote, tx_cert, ev_drop, tmo_drop, tmo_armed;
  ulong repair_req, standstill_cnt, parent_ready_cnt, s2n_cnt, s2s_cnt, cert_short;
  ulong fin_slot;
  long  fin_progress;
  long  fin_sum_ns;
  ulong fin_cnt;

  /* faults armed from the keyboard */
  int armed_crash, armed_fork, armed_slash, armed_cert;
  int paused;

  fd_rng_t rng[1];
};

static struct viz g_v;
static volatile int g_stop = 0;

static void
on_signal( int sig ) {
  (void)sig;
  g_stop = 1;
}

/* -------------------------------------------------------------- helpers */

static ulong
roll100( struct viz * v ) {
  return (ulong)fd_rng_uint_roll( v->rng, 100U );
}

static fd_hash_t
rand_hash( struct viz * v ) {
  fd_hash_t h;
  for( ulong i=0UL; i<4UL; i++ ) h.ul[i] = fd_rng_ulong( v->rng );
  return h;
}

static struct slot_row *
row_of( struct viz * v,
        ulong        slot ) {
  struct slot_row * r = &v->row[ slot % LADDER_MAX ];
  return ( r->used && r->slot==slot ) ? r : NULL;
}

/* row_ensure returns the row for slot, creating it if a vote for a slot we
   have not opened yet arrives first (skip votes routinely do). */

static struct slot_row *
row_ensure( struct viz * v,
            ulong        slot ) {
  struct slot_row * r = &v->row[ slot % LADDER_MAX ];
  if( r->used && r->slot==slot ) return r;
  memset( r, 0, sizeof(struct slot_row) );
  r->used   = 1;
  r->slot   = slot;
  r->leader = ( slot / AG_ALPENGLOW_SLOTS_PER_WINDOW ) % v->nv;
  r->t_open = v->now;
  return r;
}

static ulong
pct_of( struct viz * v,
        ulong        stake ) {
  if( FD_UNLIKELY( !v->total_stake ) ) return 0UL;
  return ( stake*100UL ) / v->total_stake;
}

static ulong
mask_stake( struct viz * v,
            ulong        mask ) {
  ulong s = 0UL;
  for( ulong p=0UL; p<v->nv; p++ ) if( mask & (1UL<<p) ) s += v->info[p].stake;
  return s;
}

static int
peer_live( struct viz * v,
           ulong        p ) {
  if( v->offline[p] ) return 0;
  if( v->now < v->silent_until && ( v->silent_mask & (1UL<<p) ) ) return 0;
  return 1;
}

static void
feed_push( struct viz * v,
           int          attr,
           char const * fmt,
           ... ) {
  struct feed * f = &v->feed[ v->feed_cnt % FEED_MAX ];
  v->feed_cnt++;
  f->ts   = v->now;
  f->attr = attr;
  va_list ap;
  va_start( ap, fmt );
  vsnprintf( f->text, sizeof(f->text), fmt, ap );
  va_end( ap );
}

static struct ev *
ev_alloc( struct viz * v ) {
  for( ulong i=0UL; i<EV_MAX; i++ ) if( !v->ev[i].used ) { v->ev[i].used = 1; return &v->ev[i]; }
  v->ev_drop++;
  return NULL;
}

static void
ev_vote( struct viz * v,
         ulong        from,
         uint         vote_kind,
         ulong        slot,
         ulong        variant,
         int          evil,
         long         ts ) {
  struct ev * e = ev_alloc( v );
  if( FD_UNLIKELY( !e ) ) return;
  e->ts = ts; e->kind = EV_VOTE; e->from = from; e->vote_kind = vote_kind;
  e->slot = slot; e->variant = variant; e->evil = evil; e->mask = 0UL;
}

static void
ev_local( struct viz * v,
          int          kind,
          ulong        slot,
          ulong        variant,
          long         ts ) {
  struct ev * e = ev_alloc( v );
  if( FD_UNLIKELY( !e ) ) return;
  e->ts = ts; e->kind = kind; e->slot = slot; e->variant = variant;
}

static void
tmo_arm( struct viz * v,
         uint         kind,
         ulong        slot,
         long         ts ) {
  for( ulong i=0UL; i<TMO_MAX; i++ ) {
    if( !v->tmo[i].used ) {
      v->tmo[i].used = 1; v->tmo[i].kind = kind; v->tmo[i].slot = slot; v->tmo[i].ts = ts;
      v->tmo_armed++;
      return;
    }
  }
  v->tmo_drop++;
}

static ulong
tmo_pending( struct viz * v ) {
  ulong n = 0UL;
  for( ulong i=0UL; i<TMO_MAX; i++ ) if( v->tmo[i].used ) n++;
  return n;
}

/* variant_of maps a voted hash back to one of the leader's blocks. */

static ulong
variant_of( struct slot_row const * r,
            fd_hash_t const *       h ) {
  if( FD_UNLIKELY( !h ) ) return ULONG_MAX;
  for( ulong i=0UL; i<r->blk_cnt; i++ ) if( !memcmp( r->blk[i].uc, h->uc, sizeof(fd_hash_t) ) ) return i;
  return ULONG_MAX;
}

static char const *
vote_name( uint kind ) {
  switch( kind ) {
  case AG_VOTE_TYPE_NOTAR:          return "notar   ";
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return "notar-fb";
  case AG_VOTE_TYPE_SKIP:           return "skip    ";
  case AG_VOTE_TYPE_SKIP_FALLBACK:  return "skip-fb ";
  default:                          return "final   ";
  }
}

static int
vote_attr( uint kind ) {
  switch( kind ) {
  case AG_VOTE_TYPE_NOTAR:          return A_NOTAR;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return A_NFB;
  case AG_VOTE_TYPE_SKIP:           return A_SKIP;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  return A_SKIP;
  default:                          return A_FINAL;
  }
}

/* ------------------------------------------------------------- ingestion */

static void
tally_vote( struct viz *      v,
            struct slot_row * r,
            ag_vote_t const * vote ) {
  ulong bit     = 1UL<<ag_vote_signer( vote );
  ulong variant = variant_of( r, ag_vote_block_hash( vote ) );
  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR:
    if( variant<VARIANT_MAX ) r->notar_mask[variant] |= bit;
    r->r1_mask |= bit;
    break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: r->nfb_mask     |= bit; r->r1_mask |= bit; break;
  case AG_VOTE_TYPE_SKIP:           r->skip_mask    |= bit; r->r1_mask |= bit; break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  r->skip_fb_mask |= bit;                    break;
  default:                          r->final_mask   |= bit;                    break;
  }
  (void)v;
}

static void
ingest_vote( struct viz *      v,
             ag_vote_t const * vote,
             int               ours ) {
  ulong slot  = ag_vote_slot  ( vote );
  ulong from  = ag_vote_signer( vote );
  ulong stake = from<v->nv ? v->info[from].stake : 0UL;

  int err = ag_pool_add_vote( v->pool, vote );

  struct slot_row * r = row_ensure( v, slot );
  char const * who = ours ? "us " : "peer";
  char tag[ 8 ];
  snprintf( tag, sizeof(tag), "v%02lu", from );

  switch( err ) {
  case AG_POOL_SUCCESS:
    v->rx_vote_ok++;
    if( vote->kind<5U ) {
      v->rx_kind[ vote->kind ]++;
      if( ours ) v->own_kind[ vote->kind ]++;
    }
    if( r ) {
      tally_vote( v, r, vote );
      if( ours ) {
        switch( vote->kind ) {
        case AG_VOTE_TYPE_NOTAR:          r->we_notar = 1; break;
        case AG_VOTE_TYPE_NOTAR_FALLBACK: r->we_nfb   = 1; break;
        case AG_VOTE_TYPE_SKIP:
        case AG_VOTE_TYPE_SKIP_FALLBACK:  r->we_skip  = 1; break;
        default:                          r->we_final = 1; break;
        }
      }
    }
    feed_push( v, ours ? A_OWN : vote_attr( vote->kind ),
               "%s vote %s s%-7lu %s %+3lu%% ok", who, vote_name( vote->kind ), slot, tag, pct_of( v, stake ) );
    break;
  case AG_ADD_VOTE_ERR_SLASHABLE:
    v->rx_vote_slash++;
    if( r ) r->slashed = 1;
    feed_push( v, A_BAD, "%s vote %s s%-7lu %s      SLASHABLE OFFENCE", who, vote_name( vote->kind ), slot, tag );
    break;
  case AG_ADD_VOTE_ERR_DUPLICATE:        v->rx_vote_dup++; goto drop;
  case AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS: v->rx_vote_oob++; goto drop;
  case AG_ADD_VOTE_ERR_INVALID_SIGNATURE:  v->rx_vote_sig++; goto drop;
  default:                                 v->rx_vote_unk++; goto drop;
  drop:
    feed_push( v, A_DIM, "%s vote %s s%-7lu %s      drop: %s",
               who, vote_name( vote->kind ), slot, tag, ag_pool_strerror( err ) );
    break;
  }
}

static void
ingest_cert( struct viz *      v,
             ag_cert_t const * cert ) {
  ulong slot  = ag_cert_slot ( cert );
  ulong stake = ag_cert_stake( cert );
  int   err   = ag_pool_add_cert( v->pool, cert );

  struct slot_row * r = row_ensure( v, slot );
  if( r ) r->cert_in = 1;

  switch( err ) {
  case AG_POOL_SUCCESS:
    v->rx_cert_ok++;
    feed_push( v, A_CERT, "peer cert %-8s s%-7lu     %3lu%% ok  (arrived before our aggregate)",
               ag_cert_type_to_string( cert->kind ), slot, pct_of( v, stake ) );
    break;
  case AG_ADD_CERT_ERR_DUPLICATE:          v->rx_cert_dup++; goto drop;
  case AG_ADD_CERT_ERR_THRESHOLD_NOT_MET:  v->rx_cert_thr++; goto drop;
  case AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS: v->rx_cert_oob++; goto drop;
  default:                                 v->rx_cert_sig++; goto drop;
  drop:
    feed_push( v, A_DIM, "peer cert %-8s s%-7lu     %3lu%% drop: %s",
               ag_cert_type_to_string( cert->kind ), slot, pct_of( v, stake ), ag_pool_strerror( err ) );
    break;
  }
}

/* ------------------------------------------------------- votor plumbing */

/* pump_votor_out mirrors the votor tile's handle_votor_out: arm the
   timeouts the votor asked for, then loop our own votes back into the pool
   (the certs it echoes would go to the network). */

static void
pump_votor_out( struct viz * v ) {
  ag_votor_out_t const * out = ag_votor_out( v->votor );

  for( ulong i=0UL; i<out->timeout_cnt; i++ ) {
    ag_votor_timeout_t const * t = &out->timeouts[i];
    ulong first = ag_alpenglow_first_slot_in_window( t->slot );
    long  ts    = t->kind==AG_VOTOR_TIMEOUT_CRASHED_LEADER
                ? v->now + AG_ALPENGLOW_DELTA_TIMEOUT_NS + AG_ALPENGLOW_DELTA_FIRST_SLICE_NS
                : v->now + AG_ALPENGLOW_DELTA_TIMEOUT_NS + (long)( t->slot - first + 1UL )*AG_ALPENGLOW_DELTA_BLOCK_NS;
    tmo_arm( v, t->kind, t->slot, ts );
  }

  ag_consensus_message_t msgs[ AG_VOTOR_OUT_MSG_MAX ];
  ulong                  msg_cnt = out->msg_cnt;
  memcpy( msgs, out->msgs, msg_cnt*sizeof(ag_consensus_message_t) );

  for( ulong i=0UL; i<msg_cnt; i++ ) {
    if( msgs[i].kind==AG_CONSENSUS_MESSAGE_VOTE ) {
      ag_vote_t vote = msgs[i].inner.vote;
      ag_vote_set_signer( &vote, (ushort)v->own_id );
      v->tx_vote++;
      ingest_vote( v, &vote, 1 );
    } else {
      v->tx_cert++;
    }
  }
}

/* note_pool_event records what the pool decided so the ladder can show it,
   and gives the feed its cert-construction lines. */

static void
note_pool_event( struct viz *            v,
                 ag_pool_event_t const * e ) {
  switch( e->kind ) {

  case AG_POOL_EVENT_CERT_CREATED: {
    ag_cert_t const * cert = &e->inner.cert_created;
    ulong             slot = ag_cert_slot( cert );
    struct slot_row * r    = row_ensure( v, slot );
    if( r ) {
      r->cert_mask |= 1UL<<cert->kind;
      if( cert->kind==AG_CERT_TYPE_NOTAR && !r->t_notar ) r->t_notar = v->now;
      if( ( cert->kind==AG_CERT_TYPE_FINAL || cert->kind==AG_CERT_TYPE_FAST_FINAL ) && !r->t_final ) {
        r->t_final = v->now;
        if( r->t_open ) { v->fin_sum_ns += r->t_final - r->t_open; v->fin_cnt++; }
      }
    }
    int attr = cert->kind==AG_CERT_TYPE_FAST_FINAL ? A_FAST
             : cert->kind==AG_CERT_TYPE_FINAL      ? A_FINAL
             : cert->kind==AG_CERT_TYPE_SKIP       ? A_SKIP
             : cert->kind==AG_CERT_TYPE_NOTAR      ? A_NOTAR : A_NFB;
    /* a cert we minted is only useful if it clears the quorum on its own
       signer set -- every receiver runs this same check on ingest */
    int usable = ag_cert_check_threshold( cert, v->epoch_info );
    if( FD_UNLIKELY( !usable ) ) {
      v->cert_short++;
      if( r ) r->cert_short_mask |= 1UL<<cert->kind;
      feed_push( v, A_BAD, "     CERT %-8s s%-7lu     %3lu%% BELOW QUORUM, peers reject",
                 ag_cert_type_to_string( cert->kind ), slot, pct_of( v, ag_cert_stake( cert ) ) );
    } else {
      feed_push( v, attr, "     CERT %-8s s%-7lu     %3lu%% built from votes in the pool",
                 ag_cert_type_to_string( cert->kind ), slot, pct_of( v, ag_cert_stake( cert ) ) );
    }

    /* peers that notar-voted this block now finalize it */
    if( cert->kind==AG_CERT_TYPE_NOTAR && r ) {
      ulong variant = variant_of( r, ag_cert_block_hash( cert ) );
      if( variant<VARIANT_MAX ) {
        for( ulong p=0UL; p<v->nv; p++ ) {
          if( p==v->own_id || !peer_live( v, p ) ) continue;
          if( !( r->notar_mask[variant] & (1UL<<p) ) ) continue;
          long jit = v->jit_ns ? (long)fd_rng_ulong_roll( v->rng, (ulong)v->jit_ns ) : 0L;
          ev_vote( v, p, AG_VOTE_TYPE_FINAL, slot, variant, 0, v->now + v->lat[p] + jit );
        }
      }
    }
    break;
  }

  case AG_POOL_EVENT_PARENT_READY:
    v->parent_ready_cnt++;
    feed_push( v, A_HDR, "     pool parent-ready for window s%lu", e->inner.parent_ready.slot );
    break;

  case AG_POOL_EVENT_SAFE_TO_NOTAR:
    v->s2n_cnt++;
    feed_push( v, A_NFB, "     pool safe-to-notar s%lu (equivocation recovery)", e->inner.safe_to_notar.slot );
    break;

  case AG_POOL_EVENT_SAFE_TO_SKIP:
    v->s2s_cnt++;
    feed_push( v, A_SKIP, "     pool safe-to-skip s%lu", e->inner.safe_to_skip );
    break;

  case AG_POOL_EVENT_STANDSTILL:
    feed_push( v, A_WARN, "     pool standstill from s%lu", e->inner.standstill );
    break;

  default:
    break;
  }
}

/* drive_votor drains the pool's channels into the votor exactly as the
   tile's after_credit does: iterate the event channel in place (our own
   votes append to it), then drain. */

static void
drive_votor( struct viz * v ) {
  for( ulong i=0UL; i<ag_pool_votor_event_cnt( v->pool ); i++ ) {
    ag_pool_event_t e = ag_pool_votor_event_channel( v->pool )[i];
    note_pool_event( v, &e );
    ag_votor_handle_pool_event( v->votor, &e );
    pump_votor_out( v );
  }
  v->repair_req += ag_pool_repair_cnt( v->pool );
  ag_pool_drain_channels( v->pool );

  ulong fin = ag_pool_finalized_slot( v->pool );
  if( FD_UNLIKELY( fin>v->fin_slot ) ) {
    v->fin_slot      = fin;
    v->fin_progress  = v->now;
  }
}

/* ------------------------------------------------------------- fallbacks */

static long
peer_delay( struct viz * v,
            ulong        p ) {
  long jit = v->jit_ns ? (long)fd_rng_ulong_roll( v->rng, (ulong)v->jit_ns ) : 0L;
  return v->lat[p] + jit;
}

/* peer_bad_window is Votor::try_skip_window for a simulated peer: once it
   has fallen back, it skips every slot of the window it has not voted in
   (voting there too would be the slashable skip-and-notarize). */

static void
peer_bad_window( struct viz * v,
                 ulong        p,
                 ulong        slot ) {
  ulong first = ag_alpenglow_first_slot_in_window( slot );
  ulong bit   = 1UL<<p;
  for( ulong s=first; s<first+AG_ALPENGLOW_SLOTS_PER_WINDOW; s++ ) {
    struct slot_row * r = row_ensure( v, s );
    if( ( r->r1_mask | r->final_mask | r->skip_sched | r->sfb_sched ) & bit ) continue;
    ev_vote( v, p, AG_VOTE_TYPE_SKIP, s, 0UL, 0, v->now + peer_delay( v, p ) );
    r->skip_sched |= bit;
  }
}

/* pump_fallbacks decides the peers' fallback votes.  The peers do not each
   run a pool, so the two predicates the pool evaluates for us are evaluated
   here against the sim's global tallies instead:

     safe-to-notar (check_safe_to_notar): the block reached the weakest
       quorum, and either the weak quorum or quorum together with the skip
       stake, and its parent is certified -- a peer that skipped the slot or
       notarized a different block then notar-fallbacks it.

     safe-to-skip (the test in count_notar_stake): the notar-or-skip stake
       outside the leading block reached the weak quorum -- a peer that
       notarized then skip-fallbacks.

   Either fallback marks the peer's window bad.  Peers that already
   finalized the slot are left alone: falling back after a finalize vote is
   the slashable offence the pool would flag. */

static void
pump_fallbacks( struct viz * v ) {
  ulong lo   = v->hi_slot>16UL ? v->hi_slot-16UL : 0UL;
  ulong root = ag_pool_first_unpruned_slot( v->pool );
  ulong done = ( 1UL<<AG_CERT_TYPE_NOTAR      ) | ( 1UL<<AG_CERT_TYPE_SKIP )
             | ( 1UL<<AG_CERT_TYPE_FAST_FINAL ) | ( 1UL<<AG_CERT_TYPE_FINAL );

  for( ulong slot=fd_ulong_max( lo, root ); slot<=v->hi_slot; slot++ ) {
    struct slot_row * r = row_of( v, slot );
    if( !r || r->cert_mask & done ) continue;

    ulong skip_stake = mask_stake( v, r->skip_mask );
    ulong notar[ VARIANT_MAX ];
    ulong notar_tot = 0UL, top = 0UL;
    for( ulong i=0UL; i<VARIANT_MAX; i++ ) {
      notar[i]   = mask_stake( v, r->notar_mask[i] );
      notar_tot += notar[i];
      top        = fd_ulong_max( top, notar[i] );
    }
    ulong voted_notar = r->notar_mask[0] | r->notar_mask[1];

    for( ulong i=0UL; i<r->blk_cnt; i++ ) {
      if( !ag_alpenglow_is_weakest_quorum( notar[i], v->total_stake ) ) continue;
      if( !ag_alpenglow_is_weak_quorum( notar[i], v->total_stake )
          && !ag_alpenglow_is_quorum( notar[i]+skip_stake, v->total_stake ) ) continue;
      if( !ag_pool_has_notar_or_fallback_cert( v->pool, r->parent.slot ) ) continue;

      for( ulong p=0UL; p<v->nv; p++ ) {
        ulong bit = 1UL<<p;
        if( p==v->own_id || !peer_live( v, p ) ) continue;
        if( ( r->nfb_sched[i] | r->nfb_mask | r->final_mask ) & bit ) continue;
        int can = ( r->skip_mask & bit ) || ( ( voted_notar & ~r->notar_mask[i] ) & bit );
        if( !can ) continue;
        ev_vote( v, p, AG_VOTE_TYPE_NOTAR_FALLBACK, slot, i, 0, v->now + peer_delay( v, p ) );
        r->nfb_sched[i] |= bit;
        peer_bad_window( v, p, slot );
      }
    }

    if( ag_alpenglow_is_weak_quorum( notar_tot + skip_stake - top, v->total_stake ) ) {
      for( ulong p=0UL; p<v->nv; p++ ) {
        ulong bit = 1UL<<p;
        if( p==v->own_id || !peer_live( v, p ) ) continue;
        if( !( voted_notar & bit ) ) continue;
        if( ( r->sfb_sched | r->skip_fb_mask | r->skip_mask | r->final_mask ) & bit ) continue;
        ev_vote( v, p, AG_VOTE_TYPE_SKIP_FALLBACK, slot, 0UL, 0, v->now + peer_delay( v, p ) );
        r->sfb_sched |= bit;
        peer_bad_window( v, p, slot );
      }
    }
  }
}

/* ------------------------------------------------------------ scheduling */

static void
open_slot( struct viz * v ) {
  ulong slot = v->slot++;
  v->hi_slot = slot;

  struct slot_row * r = row_ensure( v, slot );
  r->t_open = v->now;

  ulong window = slot / AG_ALPENGLOW_SLOTS_PER_WINDOW;
  if( window!=v->window ) {
    v->window         = window;
    v->window_crashed = v->armed_crash || ( roll100( v ) < v->crash_pct );
    v->armed_crash    = 0;
    if( v->window_crashed )
      feed_push( v, A_SKIP, "     leader v%02lu crashed: no block for window s%lu..s%lu",
                 r->leader, slot, slot+AG_ALPENGLOW_SLOTS_PER_WINDOW-1UL );
  }

  if( v->window_crashed ) {
    r->crashed = 1;
    /* peers time the window out and skip-vote every slot in it at once, the
       way Votor::try_skip_window does */
    if( ag_alpenglow_is_start_of_window( slot ) ) {
      for( ulong p=0UL; p<v->nv; p++ ) {
        if( p==v->own_id || !peer_live( v, p ) ) continue;
        if( roll100( v ) < v->drop_pct ) continue;
        long jit = v->jit_ns ? (long)fd_rng_ulong_roll( v->rng, (ulong)v->jit_ns ) : 0L;
        long ts  = v->now + AG_ALPENGLOW_DELTA_TIMEOUT_NS + v->lat[p] + jit;
        for( ulong s=slot; s<slot+AG_ALPENGLOW_SLOTS_PER_WINDOW; s++ )
          ev_vote( v, p, AG_VOTE_TYPE_SKIP, s, 0UL, 0, ts );
      }
    }
    return;
  }

  /* the leader builds on the certified tip; at a window start it must build
     on a parent the pool declared ready */
  ag_block_id_t parent = v->tip;
  if( ag_alpenglow_is_start_of_window( slot ) ) {
    ulong                 cnt = 0UL;
    ag_block_id_t const * pr  = ag_pool_parents_ready( v->pool, slot, &cnt );
    if( cnt ) parent = pr[ cnt-1UL ];
  }

  r->parent  = parent;
  r->blk[0]  = rand_hash( v );
  r->blk_cnt = 1UL;
  if( v->armed_fork || roll100( v )<v->fork_pct ) {
    r->blk[1]   = rand_hash( v );
    r->blk_cnt  = 2UL;
    r->forked   = 1;
    v->armed_fork = 0;
    feed_push( v, A_FORK, "     leader v%02lu equivocates on s%lu (two blocks)", r->leader, slot );
  }

  v->tip.slot = slot;
  v->tip.hash = r->blk[0];

  /* our node: first shred, then replay completes and the block enters the
     pool ahead of the blockstore events, like the votor tile does */
  ev_local( v, EV_SHRED, slot, 0UL, v->now + AG_ALPENGLOW_DELTA_FIRST_SLICE_NS );
  ev_local( v, EV_BLOCK, slot, 0UL, v->now + v->replay_ns );

  /* peers vote; optionally hold a set back and deliver their cert instead */
  int   withhold = ( v->armed_cert || roll100( v )<v->cert_pct ) && !r->forked;
  ulong wmask    = 0UL;
  ulong wstake   = 0UL;
  v->armed_cert  = 0;

  for( ulong p=0UL; p<v->nv; p++ ) {
    ulong bit = 1UL<<p;
    if( p==v->own_id || !peer_live( v, p ) ) continue;
    if( roll100( v ) < v->drop_pct ) continue;
    /* a peer that already skipped this slot in a bad window cannot notarize
       it too -- that is the slashable skip-and-notarize */
    if( ( r->skip_mask | r->skip_sched | r->sfb_sched ) & bit ) continue;
    ulong variant = r->blk_cnt>1UL ? ( p & 1UL ) : 0UL;
    long  ts      = v->now + v->replay_ns + peer_delay( v, p );

    if( withhold && variant==0UL && pct_of( v, wstake )<70UL ) {
      wmask  |= bit;
      wstake += v->info[p].stake;
      continue;
    }
    ev_vote( v, p, AG_VOTE_TYPE_NOTAR, slot, variant, 0, ts );
  }

  if( wmask ) {
    struct ev * e = ev_alloc( v );
    if( e ) {
      e->ts        = v->now + v->replay_ns + 2L*v->lat_ns;
      e->kind      = EV_CERT;
      e->cert_kind = AG_CERT_TYPE_NOTAR;
      e->slot      = slot;
      e->variant   = 0UL;
      e->mask      = wmask;
      feed_push( v, A_DIM, "     %lu voters withheld on s%lu; their cert will arrive instead",
                 (ulong)fd_ulong_popcnt( wmask ), slot );
    }
  }

  if( v->armed_slash ) {
    v->armed_slash = 0;
    for( ulong p=0UL; p<v->nv; p++ ) {
      if( p==v->own_id || !peer_live( v, p ) ) continue;
      ev_vote( v, p, AG_VOTE_TYPE_NOTAR, slot, 0UL, 1, v->now + v->replay_ns + 2L*v->lat[p] );
      feed_push( v, A_BAD, "     v%02lu will double-vote s%lu", p, slot );
      break;
    }
  }
}

/* ----------------------------------------------------------- event pumps */

static void
deliver_vote( struct viz *      v,
              struct ev const * e ) {
  if( FD_UNLIKELY( e->from>=v->nv ) ) return;
  struct slot_row * r = row_ensure( v, e->slot );

  fd_hash_t hash;
  if( e->evil ) {
    hash = r->blk_cnt ? r->blk[0] : rand_hash( v );
    hash.uc[0] = (uchar)( hash.uc[0] ^ 0xffU );
  } else {
    ulong variant = fd_ulong_min( e->variant, r->blk_cnt ? r->blk_cnt-1UL : 0UL );
    hash = r->blk[ variant ];
  }

  ag_aggsig_sk_t const * sk     = &v->sk[ e->from ];
  ushort                 signer = (ushort)e->from;
  ag_vote_t              vote;

  switch( e->vote_kind ) {
  case AG_VOTE_TYPE_NOTAR:          ag_vote_new_notar         ( &vote, e->slot, &hash, sk, signer, v->shred_version ); break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: ag_vote_new_notar_fallback( &vote, e->slot, &hash, sk, signer, v->shred_version ); break;
  case AG_VOTE_TYPE_SKIP:           ag_vote_new_skip          ( &vote, e->slot,        sk, signer, v->shred_version ); break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  ag_vote_new_skip_fallback ( &vote, e->slot,        sk, signer, v->shred_version ); break;
  default:                          ag_vote_new_final         ( &vote, e->slot,        sk, signer, v->shred_version ); break;
  }
  ingest_vote( v, &vote, 0 );
}

static void
deliver_cert( struct viz *      v,
              struct ev const * e ) {
  struct slot_row * r = row_of( v, e->slot );
  if( FD_UNLIKELY( !r || !r->blk_cnt ) ) return;

  static ag_notar_vote_t nv[ VTR_MAX ];
  ulong                  cnt     = 0UL;
  ulong                  variant = fd_ulong_min( e->variant, r->blk_cnt-1UL );

  for( ulong p=0UL; p<v->nv; p++ ) {
    if( !( e->mask & (1UL<<p) ) ) continue;
    ag_notar_vote_new( &nv[cnt++], e->slot, &r->blk[variant], &v->sk[p], (ushort)p, v->shred_version );
  }
  if( FD_UNLIKELY( !cnt ) ) return;

  ag_cert_t cert;
  cert.kind = AG_CERT_TYPE_NOTAR;
  if( FD_UNLIKELY( ag_notar_cert_try_new( &cert.inner.notar, nv, cnt, v->info, v->nv )!=AG_CERT_SUCCESS ) ) return;
  ingest_cert( v, &cert );
}

static void
pump_events( struct viz * v ) {
  for(;;) {
    struct ev * best = NULL;
    for( ulong i=0UL; i<EV_MAX; i++ ) {
      struct ev * e = &v->ev[i];
      if( !e->used || e->ts>v->now ) continue;
      if( !best || e->ts<best->ts ) best = e;
    }
    if( !best ) break;

    struct ev e = *best;
    best->used = 0;

    switch( e.kind ) {

    case EV_VOTE: deliver_vote( v, &e ); break;
    case EV_CERT: deliver_cert( v, &e ); break;

    case EV_SHRED: {
      ag_votor_blockstore_event_t bs = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
      bs.inner.first_shred = e.slot;
      ag_votor_handle_blockstore_event( v->votor, &bs );
      pump_votor_out( v );
      break;
    }

    case EV_BLOCK: {
      struct slot_row * r = row_of( v, e.slot );
      if( FD_UNLIKELY( !r || !r->blk_cnt ) ) break;

      ag_block_id_t block  = { .slot = e.slot, .hash = r->blk[0] };
      ag_block_id_t parent = r->parent;

      if( FD_LIKELY( block.slot>parent.slot ) ) ag_pool_add_block( v->pool, &block, &parent );

      ag_votor_blockstore_event_t bs = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_BLOCK };
      bs.inner.block.slot            = e.slot;
      bs.inner.block.block_id        = block;
      bs.inner.block.parent_block_id = parent;
      ag_votor_handle_blockstore_event( v->votor, &bs );
      pump_votor_out( v );
      break;
    }

    default: break;
    }
  }
}

static void
pump_timeouts( struct viz * v ) {
  for(;;) {
    struct tmo * best = NULL;
    for( ulong i=0UL; i<TMO_MAX; i++ ) {
      struct tmo * t = &v->tmo[i];
      if( !t->used || t->ts>v->now ) continue;
      if( !best || t->ts<best->ts ) best = t;
    }
    if( !best ) break;

    ag_votor_timeout_t ev = { .kind = best->kind, .slot = best->slot };
    best->used = 0;
    ag_votor_handle_timeout_event( v->votor, &ev );
    pump_votor_out( v );
  }
}

/* standstill_poll mirrors the tile: if the pool's finalized slot has been
   stuck for DELTA_STANDSTILL, pull the recovery bundle and re-broadcast. */

static void
standstill_poll( struct viz * v ) {
  if( v->now < v->next_standstill ) return;
  v->next_standstill = v->now + AG_ALPENGLOW_DELTA_BLOCK_NS;

  if( v->now - v->fin_progress <= AG_ALPENGLOW_DELTA_STANDSTILL_NS ) return;
  v->fin_progress = v->now;
  if( !v->fin_slot ) return;

  static ag_cert_t certs[ STANDSTILL_CERT_MAX ];
  static ag_vote_t votes[ STANDSTILL_VOTE_MAX ];
  ulong certs_cnt = 0UL, votes_cnt = 0UL;

  ag_pool_recover_from_standstill( v->pool, certs, &certs_cnt, STANDSTILL_CERT_MAX,
                                            votes, &votes_cnt, STANDSTILL_VOTE_MAX );
  v->standstill_cnt++;
  v->tx_cert += certs_cnt;
  v->tx_vote += votes_cnt;
  feed_push( v, A_WARN, "     standstill recovery: re-broadcast %lu certs, %lu votes", certs_cnt, votes_cnt );
}

/* ---------------------------------------------------------------- render */

static void
bar( ulong  row,
     ulong  col,
     ulong  w,
     ulong  total,
     ulong  seg_stake[],
     int    seg_attr[],
     ulong  seg_cnt,
     ulong  tick_pct[],
     ulong  tick_cnt ) {
  /* background with quorum ticks */
  for( ulong i=0UL; i<w; i++ ) cv_put( row, col+i, A_TICK, g.dot );
  for( ulong t=0UL; t<tick_cnt; t++ ) {
    ulong at = ( tick_pct[t]*w )/100UL;
    if( at>=w ) at = w-1UL;
    cv_put( row, col+at, A_TICK, g.tick );
  }

  if( FD_UNLIKELY( !total ) ) return;

  ulong filled = 0UL;
  for( ulong s=0UL; s<seg_cnt; s++ ) {
    if( !seg_stake[s] ) continue;
    ulong cells = ( seg_stake[s]*w + total/2UL )/total;
    if( !cells ) cells = 1UL;
    for( ulong i=0UL; i<cells && filled<w; i++, filled++ ) {
      char const * glyph = seg_attr[s]==A_NFB  ? g.half
                         : seg_attr[s]==A_SFB  ? g.half
                         : seg_attr[s]==A_SKIP ? g.lite
                         : seg_attr[s]==A_FORK ? g.fork
                         :                       g.full;
      cv_put( row, col+filled, seg_attr[s], glyph );
    }
  }
}

static void
render( struct viz * v ) {
  struct winsize ws;
  if( g_tty && !ioctl( STDOUT_FILENO, TIOCGWINSZ, &ws ) && ws.ws_row && ws.ws_col ) {
    g_rows = fd_ulong_min( (ulong)ws.ws_row, CV_ROWS );
    g_cols = fd_ulong_min( (ulong)ws.ws_col, CV_COLS );
  }
  cv_clear();

  ulong fin  = ag_pool_finalized_slot     ( v->pool );
  ulong root = ag_pool_first_unpruned_slot( v->pool );

  /* ---- header ---- */
  ulong c = cv_text( 0UL, 1UL, A_TITLE, "ALPENGLOW" );
  c = cv_text( 0UL, c+1UL, A_HDR, "%s consensus core, simulated cluster", g.arrow );
  cv_text( 0UL, c+2UL, A_DIM, "%lu validators %s we are v%02lu (%lu%% stake) %s slot %ldms %s %s",
           v->nv, g.vbar, v->own_id, pct_of( v, v->info[ v->own_id ].stake ), g.vbar,
           v->slot_ns/1000000L, g.vbar, v->paused ? "PAUSED" : "running" );

  c = cv_text( 1UL, 1UL, A_DIM, "r1" );
  cv_put( 1UL, ++c, A_NOTAR, g.full ); c = cv_text( 1UL, c+1UL, A_DIM, " notar " );
  cv_put( 1UL, c, A_FORK,  g.fork ); c = cv_text( 1UL, c+1UL, A_DIM, " fork " );
  cv_put( 1UL, c, A_NFB,   g.half ); c = cv_text( 1UL, c+1UL, A_DIM, " notar-fb " );
  cv_put( 1UL, c, A_SKIP,  g.lite ); c = cv_text( 1UL, c+1UL, A_DIM, " skip    r2" );
  cv_put( 1UL, ++c, A_FINAL, g.full ); c = cv_text( 1UL, c+1UL, A_DIM, " final " );
  cv_put( 1UL, c, A_SFB,   g.half ); c = cv_text( 1UL, c+1UL, A_DIM, " skip-fb   " );
  cv_put( 1UL, c, A_TICK,  g.tick ); c = cv_text( 1UL, c+1UL, A_DIM, " 60/80%%   certs" );
  c = cv_text( 1UL, c+1UL, A_NOTAR, "N" );
  c = cv_text( 1UL, c+1UL, A_NFB,   "n" );
  c = cv_text( 1UL, c+1UL, A_SKIP,  "S" );
  c = cv_text( 1UL, c+1UL, A_FINAL, "F" );
  c = cv_text( 1UL, c+1UL, A_FAST,  "*" );
  cv_text( 1UL, c+2UL, A_DIM, "fb: fallback votes cast here" );

  /* ---- ladder geometry ---- */
  ulong fixed = 72UL;
  ulong avail = g_cols>fixed+24UL ? g_cols-fixed : 24UL;
  ulong w1    = fd_ulong_min( ( avail*2UL )/3UL, 46UL );
  ulong w2    = fd_ulong_min( avail-w1, 20UL );
  if( w1<12UL ) w1 = 12UL;
  if( w2< 6UL ) w2 =  6UL;

  ulong panel_rows  = 12UL;
  ulong footer_rows =  5UL;
  ulong lad_top     =  3UL;
  ulong lad_rows    = g_rows>lad_top+panel_rows+footer_rows ? g_rows-lad_top-panel_rows-footer_rows : 4UL;

  ulong x_slot = 1UL;
  ulong x_ldr  = x_slot + 7UL;
  ulong x_blk  = x_ldr  + 5UL;
  ulong x_b1   = x_blk  + 8UL;
  ulong x_p1   = x_b1   + w1 + 1UL;
  ulong x_b2   = x_p1   + 5UL;
  ulong x_p2   = x_b2   + w2 + 1UL;
  ulong x_cert = x_p2   + 5UL;
  ulong x_fb   = x_cert + 7UL;
  ulong x_stat = x_cert + 11UL;
  ulong x_lat  = x_stat + 12UL;

  cv_text( lad_top-1UL, x_slot, A_HDR, "slot" );
  cv_text( lad_top-1UL, x_ldr,  A_HDR, "ldr" );
  cv_text( lad_top-1UL, x_blk,  A_HDR, "block" );
  cv_text( lad_top-1UL, x_b1,   A_HDR, "round 1: notarize / skip" );
  cv_text( lad_top-1UL, x_p1,   A_HDR, "  %%" );
  cv_text( lad_top-1UL, x_b2,   A_HDR, "round 2" );
  cv_text( lad_top-1UL, x_p2,   A_HDR, "  %%" );
  cv_text( lad_top-1UL, x_cert, A_HDR, "certs" );
  cv_text( lad_top-1UL, x_fb,   A_HDR, "fb" );
  cv_text( lad_top-1UL, x_stat, A_HDR, "state" );
  cv_text( lad_top-1UL, x_lat,  A_HDR, "notar   final" );

  ulong shown = 0UL;
  for( ulong s=v->hi_slot+1UL; s>0UL && shown<lad_rows; s-- ) {
    ulong slot = s-1UL;
    struct slot_row const * r = row_of( v, slot );
    if( !r ) continue;
    ulong row = lad_top + shown++;
    int   old = slot<root;

    cv_text( row, x_slot, old ? A_DIM : A_NONE, "%-6lu", slot );
    cv_text( row, x_ldr, r->leader==v->own_id ? A_OWN : A_DIM, "%s%02lu",
             r->leader==v->own_id ? g.star : "v", r->leader );
    if( r->crashed )      cv_text( row, x_blk, A_SKIP, "--" );
    else if( r->blk_cnt ) cv_text( row, x_blk, r->forked ? A_FORK : A_DIM, "%02x%02x%02x",
                                   r->blk[0].uc[0], r->blk[0].uc[1], r->blk[0].uc[2] );

    /* round one: the leading notarize variant, the minority variant of an
       equivocating leader, then fallbacks and skips -- each voter counted
       once, in that order of precedence */
    ulong lead  = mask_stake( v, r->notar_mask[0] )>=mask_stake( v, r->notar_mask[1] ) ? 0UL : 1UL;
    ulong m_ld  = r->notar_mask[ lead      ];
    ulong m_ot  = r->notar_mask[ 1UL-lead  ] & ~m_ld;
    ulong m_nfb = r->nfb_mask   & ~( m_ld | m_ot );
    ulong m_skp = r->skip_mask  & ~( m_ld | m_ot | m_nfb );

    ulong seg_stake[4] = { mask_stake( v, m_ld ), mask_stake( v, m_ot ),
                           mask_stake( v, m_nfb ), mask_stake( v, m_skp ) };
    int   seg_attr [4] = { A_NOTAR, A_FORK, A_NFB, A_SKIP };
    ulong ticks    [2] = { 60UL, 80UL };
    bar( row, x_b1, w1, v->total_stake, seg_stake, seg_attr, 4UL, ticks, 2UL );
    cv_text( row, x_p1, old ? A_DIM : A_NONE, "%3lu", pct_of( v, mask_stake( v, r->r1_mask ) ) );

    ulong m_fin = r->final_mask;
    ulong m_sfb = r->skip_fb_mask & ~m_fin;
    ulong seg2[2]  = { mask_stake( v, m_fin ), mask_stake( v, m_sfb ) };
    int   att2[2]  = { A_FINAL, A_SFB };
    ulong tick2[1] = { 60UL };
    bar( row, x_b2, w2, v->total_stake, seg2, att2, 2UL, tick2, 1UL );
    cv_text( row, x_p2, old ? A_DIM : A_NONE, "%3lu", pct_of( v, seg2[0]+seg2[1] ) );

    /* certs the pool built (or accepted), one column per kind */
    struct { ulong kind; char const * ch; int attr; } cert_cols[5] = {
      { AG_CERT_TYPE_NOTAR,          "N", A_NOTAR },
      { AG_CERT_TYPE_NOTAR_FALLBACK, "n", A_NFB   },
      { AG_CERT_TYPE_SKIP,           "S", A_SKIP  },
      { AG_CERT_TYPE_FINAL,          "F", A_FINAL },
      { AG_CERT_TYPE_FAST_FINAL,     "*", A_FAST  }
    };
    for( ulong k=0UL; k<5UL; k++ ) {
      int have  = !!( r->cert_mask       & (1UL<<cert_cols[k].kind) );
      int short_= !!( r->cert_short_mask & (1UL<<cert_cols[k].kind) );
      cv_put( row, x_cert+k, !have ? A_TICK : short_ ? A_BAD : cert_cols[k].attr,
              have ? cert_cols[k].ch : g.dot );
    }
    if( r->cert_in ) cv_put( row, x_cert+5UL, A_CERT, g.down );

    /* fallback votes cast for this slot */
    cv_put( row, x_fb,      r->nfb_mask     ? A_NFB : A_TICK, r->nfb_mask     ? "n" : g.dot );
    cv_put( row, x_fb+1UL,  r->skip_fb_mask ? A_SFB : A_TICK, r->skip_fb_mask ? "s" : g.dot );

    char const * state; int attr;
    if(      r->cert_mask & (1UL<<AG_CERT_TYPE_FAST_FINAL) ) { state = "fast-final"; attr = A_FAST;  }
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_FINAL     ) ) { state = "finalized";  attr = A_FINAL; }
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_SKIP      ) ) { state = "skipped";    attr = A_SKIP;  }
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_NOTAR     ) ) { state = "notarized";  attr = A_NOTAR; }
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_NOTAR_FALLBACK) ) { state = "notar-fb"; attr = A_NFB; }
    else if( r->crashed )                                   { state = "no block";   attr = A_DIM;   }
    else if( r->r1_mask )                                   { state = "voting";     attr = A_NONE;  }
    else                                                    { state = "proposed";   attr = A_DIM;   }

    if( slot==fin ) cv_put( row, x_stat-2UL, A_FINAL, g.arrow );
    cv_text( row, x_stat, old ? A_DIM : attr, "%s", state );
    if( r->slashed ) cv_put( row, x_stat+11UL, A_BAD, "!" );

    if( r->t_notar ) cv_text( row, x_lat,      A_DIM, "%4ldms", ( r->t_notar-r->t_open )/1000000L );
    if( r->t_final ) cv_text( row, x_lat+8UL,  A_DIM, "%4ldms", ( r->t_final-r->t_open )/1000000L );
  }

  /* ---- panels ---- */
  ulong p_top  = lad_top + lad_rows;
  ulong p_bot  = p_top + panel_rows;
  ulong split  = ( g_cols*3UL )/5UL;

  cv_box( p_top, 0UL, p_bot, split, A_DIM, "incoming votes & certs" );
  ulong feed_rows = panel_rows-2UL;
  for( ulong i=0UL; i<feed_rows && i<v->feed_cnt; i++ ) {
    struct feed const * f = &v->feed[ ( v->feed_cnt-1UL-i ) % FEED_MAX ];
    ulong row = p_top+1UL+i;
    cv_text( row, 2UL, A_TICK, "%3ld.%03ld", f->ts/1000000000L, ( f->ts/1000000L )%1000L );
    ulong lim = split>12UL ? split-12UL : 1UL;
    char  cut[ CV_COLS ];
    snprintf( cut, fd_ulong_min( lim, sizeof(cut) ), "%s", f->text );
    cv_text( row, 10UL, f->attr, "%s", cut );
  }

  cv_box( p_top, split, p_bot, g_cols, A_DIM, "our node" );
  ulong nx = split+2UL;
  ulong ny = p_top+1UL;
  ag_votor_slot_state_t const * ss = ag_votor_slot_state( v->votor, v->hi_slot );
  cv_text( ny++, nx, A_NONE, "pool   finalized s%-8lu root s%-8lu", fin, root );
  cv_text( ny++, nx, A_NONE, "votor  final-cert s%-7lu timeouts %lu",
           ag_votor_highest_final_cert_slot( v->votor ), tmo_pending( v ) );
  cv_text( ny++, nx, A_NONE, "tip    s%lu %02x%02x%02x", v->tip.slot,
           v->tip.hash.uc[0], v->tip.hash.uc[1], v->tip.hash.uc[2] );
  if( ss ) cv_text( ny++, nx, A_DIM, "s%lu  voted %d  shred %d  bad-window %d",
                    v->hi_slot, ss->voted, ss->received_shred, ss->bad_window );
  else     ny++;
  cv_text( ny++, nx, A_DIM, "repair requests %lu   parent-ready %lu", v->repair_req, v->parent_ready_cnt );
  cv_text( ny++, nx, A_DIM, "safe-to-notar %lu     safe-to-skip %lu", v->s2n_cnt, v->s2s_cnt );
  if( v->fin_cnt )
    cv_text( ny++, nx, A_NONE, "mean block %s finalized  %ldms",
             g.arrow, ( v->fin_sum_ns/(long)v->fin_cnt )/1000000L );
  else ny++;
  long stuck = ( v->now - v->fin_progress )/1000000L;
  cv_text( ny++, nx, stuck>3000L ? A_WARN : A_DIM, "no finalization for %ldms  (standstill x%lu)",
           stuck, v->standstill_cnt );
  if( v->now < v->silent_until )
    cv_text( ny++, nx, A_BAD, "PARTITION: %lu%% stake silent for %ldms",
             pct_of( v, mask_stake( v, v->silent_mask ) ), ( v->silent_until - v->now )/1000000L );

  /* ---- footers ---- */
  ulong f0 = p_bot;
  cv_text( f0, 1UL, A_DIM, "votes in" );
  c = cv_text( f0, 10UL, A_NOTAR, "%lu ok", v->rx_vote_ok );
  c = cv_text( f0, c+2UL, A_DIM, "%lu dup", v->rx_vote_dup );
  c = cv_text( f0, c+2UL, A_DIM, "%lu stale", v->rx_vote_oob );
  c = cv_text( f0, c+2UL, v->rx_vote_slash ? A_BAD : A_DIM, "%lu slashable", v->rx_vote_slash );
  c = cv_text( f0, c+3UL, A_DIM, "certs in" );
  c = cv_text( f0, c+1UL, A_CERT, "%lu ok", v->rx_cert_ok );
  c = cv_text( f0, c+2UL, A_DIM, "%lu dup", v->rx_cert_dup );
  c = cv_text( f0, c+2UL, A_DIM, "%lu below-quorum", v->rx_cert_thr );
  c = cv_text( f0+1UL, 1UL, A_DIM, "by kind " );
  c = cv_text( f0+1UL, c, A_NOTAR, "%lu notar", v->rx_kind[ AG_VOTE_TYPE_NOTAR ] );
  c = cv_text( f0+1UL, c+2UL, A_NFB, "%lu notar-fb", v->rx_kind[ AG_VOTE_TYPE_NOTAR_FALLBACK ] );
  c = cv_text( f0+1UL, c+2UL, A_SKIP, "%lu skip", v->rx_kind[ AG_VOTE_TYPE_SKIP ] );
  c = cv_text( f0+1UL, c+2UL, A_SFB, "%lu skip-fb", v->rx_kind[ AG_VOTE_TYPE_SKIP_FALLBACK ] );
  cv_text( f0+1UL, c+2UL, A_FINAL, "%lu final", v->rx_kind[ AG_VOTE_TYPE_FINAL ] );

  c = cv_text( f0+2UL, 1UL, A_DIM, "we sent" );
  c = cv_text( f0+2UL, c+1UL, A_OWN, "%lu votes", v->tx_vote );
  c = cv_text( f0+2UL, c+1UL, A_DIM, " (notar-fb %lu, skip-fb %lu, skip %lu)",
               v->own_kind[ AG_VOTE_TYPE_NOTAR_FALLBACK ],
               v->own_kind[ AG_VOTE_TYPE_SKIP_FALLBACK  ],
               v->own_kind[ AG_VOTE_TYPE_SKIP           ] );
  c = cv_text( f0+2UL, c+2UL, A_DIM, "%lu certs", v->tx_cert );
  if( v->cert_short )
    cv_text( f0+2UL, c+3UL, A_BAD, "%lu certs we minted are one voter short of the quorum",
             v->cert_short );

  cv_text( f0+3UL, 1UL, A_DIM,
           "faults  crash %lu%%  fork %lu%%  cert-first %lu%%  loss %lu%%  latency %ldms",
           v->crash_pct, v->fork_pct, v->cert_pct, v->drop_pct, v->lat_ns/1000000L );

  cv_text( f0+4UL, 1UL, A_HDR,
           "[c] crash leader  [f] fork  [s] double-vote  [w] cert-first  [p] partition  [space] pause  [q] quit" );

  cv_flush();
}

/* ------------------------------------------------------------- terminal */

static struct termios g_tio;
static int            g_tio_saved = 0;

static void
term_restore( void ) {
  if( g_tio_saved ) tcsetattr( STDIN_FILENO, TCSANOW, &g_tio );
  if( g_tty ) {
    char const * s = "\033[?25h\033[?1049l";
    ulong        n = strlen( s );
    if( write( STDOUT_FILENO, s, n )!=(long)n ) {}
  }
}

static void
term_init( void ) {
  if( !g_tty ) return;
  if( !tcgetattr( STDIN_FILENO, &g_tio ) ) {
    struct termios raw = g_tio;
    raw.c_lflag &= (tcflag_t)~( ICANON | ECHO );
    raw.c_cc[ VMIN  ] = 0;
    raw.c_cc[ VTIME ] = 0;
    if( !tcsetattr( STDIN_FILENO, TCSANOW, &raw ) ) g_tio_saved = 1;
  }
  char const * s = "\033[?1049h\033[?25l\033[2J";
  ulong        n = strlen( s );
  if( write( STDOUT_FILENO, s, n )!=(long)n ) {}
}

static void
handle_keys( struct viz * v ) {
  if( !g_tty ) return;
  char buf[ 16 ];
  long n = read( STDIN_FILENO, buf, sizeof(buf) );
  for( long i=0L; i<n; i++ ) {
    switch( buf[i] ) {
    case 'q': case 3: g_stop = 1; break;
    case ' ': v->paused = !v->paused; break;
    case 'c': v->armed_crash = 1; feed_push( v, A_HDR, "     armed: next leader window crashes" ); break;
    case 'f': v->armed_fork  = 1; feed_push( v, A_HDR, "     armed: next leader equivocates"    ); break;
    case 's': v->armed_slash = 1; feed_push( v, A_HDR, "     armed: a peer will double-vote"    ); break;
    case 'w': v->armed_cert  = 1; feed_push( v, A_HDR, "     armed: cert arrives before votes"  ); break;
    case 'p': {
      ulong mask = 0UL, stake = 0UL;
      for( ulong p=0UL; p<v->nv; p++ ) {
        if( p==v->own_id ) continue;
        if( pct_of( v, stake )>=33UL ) break;
        mask |= 1UL<<p;
        stake += v->info[p].stake;
      }
      v->silent_mask  = mask;
      v->silent_until = v->now + 14L*1000000000L;
      feed_push( v, A_BAD, "     armed: %lu%% of stake goes silent", pct_of( v, stake ) );
      break;
    }
    default: break;
    }
  }
}

/* ----------------------------------------------------------------- main */

static void
tick( struct viz * v ) {
  if( v->now >= v->next_slot ) {
    v->next_slot += v->slot_ns;
    open_slot( v );
  }
  pump_events  ( v );
  pump_timeouts( v );
  drive_votor  ( v );
  pump_fallbacks( v );
  standstill_poll( v );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  struct viz * v = &g_v;

  ulong  nv          = fd_env_strip_cmdline_ulong ( &argc, &argv, "--validators",   NULL, 13UL   );
  ulong  slot_ms     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--slot-ms",      NULL, 400UL  );
  ulong  lat_ms      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--latency-ms",   NULL, 45UL   );
  ulong  jit_ms      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--jitter-ms",    NULL, 35UL   );
  ulong  replay_ms   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--replay-ms",    NULL, 60UL   );
  ulong  drop_pct    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--loss-pct",     NULL, 2UL    );
  ulong  crash_pct   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--crash-pct",    NULL, 8UL    );
  ulong  fork_pct    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--fork-pct",     NULL, 5UL    );
  ulong  cert_pct    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--cert-pct",     NULL, 8UL    );
  ulong  offline_pct = fd_env_strip_cmdline_ulong ( &argc, &argv, "--offline-pct",  NULL, 0UL    );
  ulong  own_rank    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--own-rank",     NULL, ULONG_MAX );
  ulong  frames      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--frames",       NULL, 0UL    );
  ulong  fps         = fd_env_strip_cmdline_ulong ( &argc, &argv, "--fps",          NULL, 12UL   );
  ulong  warmup      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--warmup-slots", NULL, 0UL    );
  double speed       = fd_env_strip_cmdline_double( &argc, &argv, "--speed",        NULL, 1.0    );
  uint   seed        = fd_env_strip_cmdline_uint  ( &argc, &argv, "--seed",         NULL, 42U    );
  ulong  rows        = fd_env_strip_cmdline_ulong ( &argc, &argv, "--rows",         NULL, 0UL    );
  ulong  cols        = fd_env_strip_cmdline_ulong ( &argc, &argv, "--cols",         NULL, 0UL    );
  int    ascii       = fd_env_strip_cmdline_contains( &argc, &argv, "--ascii"    );
  int    no_color    = fd_env_strip_cmdline_contains( &argc, &argv, "--no-color" );

  if( nv<4UL      ) nv = 4UL;
  if( nv>VTR_MAX  ) nv = VTR_MAX;
  if( fps<1UL     ) fps = 1UL;
  if( speed<0.05  ) speed = 0.05;
  if( own_rank==ULONG_MAX ) own_rank = nv/3UL;
  if( own_rank>=nv        ) own_rank = nv/3UL;

  g_color = !no_color;
  g_tty   = isatty( STDOUT_FILENO ) && !frames;
  glyphs_init( ascii );
  if( rows ) g_rows = fd_ulong_min( rows, CV_ROWS );
  if( cols ) g_cols = fd_ulong_min( cols, CV_COLS );

  /* NOTICE / WARNING lines would land in the middle of the frame; keep them
     in the log file only */
  fd_log_level_stderr_set( 4 );

  memset( v, 0, sizeof(struct viz) );
  fd_rng_new( v->rng, seed, 0UL );

  v->nv            = nv;
  v->own_id        = own_rank;
  v->slot_ns       = (long)slot_ms  *1000000L;
  v->lat_ns        = (long)lat_ms   *1000000L;
  v->jit_ns        = (long)jit_ms   *1000000L;
  v->replay_ns     = (long)replay_ms*1000000L;
  v->drop_pct      = drop_pct;
  v->crash_pct     = crash_pct;
  v->fork_pct      = fork_pct;
  v->cert_pct      = cert_pct;
  v->offline_pct   = offline_pct;
  v->shred_version = (ushort)0x5a5a;
  v->frame_ns      = 1000000000L/(long)fps;
  v->window        = ULONG_MAX;

  /* stake: a long tail, so quorums are not just head counts */
  for( ulong i=0UL; i<nv; i++ ) {
    memset( v->sk[i].v, (int)( i*7UL+1UL ), AG_AGGSIG_SECKEY_SZ );
    memset( &v->info[i], 0, sizeof(ag_validator_info_t) );
    v->info[i].id    = i;
    v->info[i].stake = 400UL/( i+1UL ) + 20UL + (ulong)fd_rng_uint_roll( v->rng, 40U );
    ag_aggsig_sk_to_pk( &v->info[i].voting_pubkey, &v->sk[i] );
    /* a long tail: a few peers are far away, so quorums fill in stages */
    v->lat[i]     = v->lat_ns/2L + (long)fd_rng_ulong_roll( v->rng, (ulong)v->lat_ns );
    if( roll100( v )<20UL ) v->lat[i] += 3L*v->lat_ns;
    v->offline[i] = i!=own_rank && offline_pct && ( roll100( v )<offline_pct );
    v->total_stake += v->info[i].stake;
  }

  ulong page_cnt = 24576UL;
  ulong numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "normal" ), page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ), "ag_viz", 0UL );
  FD_TEST( wksp );

  ulong slot_max = 512UL, validator_max = VTR_MAX, blockid_max = 1024UL;
  void * pool_mem = fd_wksp_alloc_laddr( wksp, ag_pool_align(),
                                         ag_pool_footprint( slot_max, validator_max, blockid_max ), 1UL );
  FD_TEST( pool_mem );
  v->pool = ag_pool_join( ag_pool_new( pool_mem, slot_max, validator_max, blockid_max, own_rank,
                                       v->info, nv, v->shred_version, seed, 0UL, NULL ) );
  FD_TEST( v->pool );

  void * ei_mem = fd_wksp_alloc_laddr( wksp, ag_epoch_info_align(), ag_epoch_info_footprint( nv ), 3UL );
  FD_TEST( ei_mem );
  v->epoch_info = ag_epoch_info_join( ag_epoch_info_new( ei_mem, v->info, nv ) );
  FD_TEST( v->epoch_info );

  void * votor_mem = fd_wksp_alloc_laddr( wksp, ag_votor_align(), ag_votor_footprint( slot_max ), 2UL );
  FD_TEST( votor_mem );
  v->votor = ag_votor_join( ag_votor_new( votor_mem, slot_max, (ushort)own_rank,
                                          ag_aggsig_sign_local, &v->sk[ own_rank ],
                                          v->shred_version, seed ) );
  FD_TEST( v->votor );

  signal( SIGINT,  on_signal );
  signal( SIGTERM, on_signal );
  signal( SIGHUP,  on_signal );
  atexit( term_restore );
  term_init();

  long wall0 = fd_log_wallclock();
  v->now             = 0L;
  v->next_slot       = 0L;
  v->next_frame      = 0L;
  v->next_standstill = 0L;
  v->fin_progress    = 0L;

  /* fast-forward so the ladder opens with history */
  for( ulong i=0UL; i<warmup*(ulong)( v->slot_ns/5000000L ) && !g_stop; i++ ) {
    v->now += 5000000L;
    tick( v );
  }
  long virt0 = v->now;

  ulong drawn = 0UL;
  while( !g_stop ) {

    if( g_tty ) {
      long wall = fd_log_wallclock();
      if( !v->paused ) v->now = virt0 + (long)( (double)( wall-wall0 )*speed );
      tick( v );
      handle_keys( v );
      if( v->now>=v->next_frame ) {
        v->next_frame = v->now + v->frame_ns;
        render( v );
        drawn++;
      }
      struct timespec ts = { .tv_sec = 0L, .tv_nsec = 2000000L };
      nanosleep( &ts, NULL );
    } else {
      /* headless: step the virtual clock so a captured run is deterministic */
      long target = v->now + v->frame_ns;
      while( v->now<target ) { v->now += 5000000L; tick( v ); }
      render( v );
      drawn++;
    }

    if( frames && drawn>=frames ) break;
  }

  term_restore();
  fd_halt();
  return 0;
}
