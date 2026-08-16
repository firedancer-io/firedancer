#define _GNU_SOURCE

#include "votor_monitor.h"
#include "../../shared/fd_action.h"

#include "../../../alpenglow/consensus/ag_pool.h"
#include "../../../alpenglow/consensus/ag_votor.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../discof/votor/fd_votor_tile.h"
#include "../../../disco/topo/fd_topo.h"
#include "../../../flamenco/leaders/fd_leaders_base.h"
#include "../../../flamenco/stakes/fd_stake_weight.h"
#include "../../../util/env/fd_env.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* view knobs, stripped by votor_monitor_args */
static ulong viz_fps = 12UL, viz_frames, viz_rows, viz_cols;
static int   viz_ascii, viz_no_color;

void
votor_monitor_args( int *    pargc,
               char *** pargv ) {
  viz_fps      = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--fps",    NULL, 12UL );
  viz_frames   = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--frames", NULL,  0UL );
  viz_rows     = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--rows",   NULL,  0UL );
  viz_cols     = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--cols",   NULL,  0UL );
  viz_ascii    = fd_env_strip_cmdline_contains( pargc, pargv, "--ascii"    );
  viz_no_color = fd_env_strip_cmdline_contains( pargc, pargv, "--no-color" );
}

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



/* ------------------------------------------------------------------ viz */

/* The live view.  Everything drawn is read back out of the running votor
   tile over its votor_out link: the votes and certs it sent, the votes
   and certs it received from peers (the tile echoes those when
   alpenglow_publish_rx is set), the slots replay finished, and the
   finalized / rooted watermarks.  Nothing here is simulated and nothing
   here drives consensus -- it is a viewer.

   Per-slot stake is deduplicated with signer sets rather than summed as
   votes arrive: a validator that notarizes a block and then
   notar-fallbacks the same block must be counted once.  The sets are
   never drawn (a hundred-odd peers do not fit on a terminal); what is
   drawn is the stake each category adds up to, against the 20/40/60/80%
   quorum thresholds consensus actually tests. */

#define VIZ_RX_BUDGET   (8192UL) /* frags drained per frame; see viz_rx_poll */
#define VIZ_ROW_MAX     (48UL)  /* slots kept on the ladder */
#define VIZ_FEED_MAX    (96UL)
#define VIZ_VARIANT_MAX ( 2UL)  /* block versions tracked per slot */

struct viz_feed {
  int  attr;
  char text[ 160 ];
};

struct viz_row {
  ulong     slot;
  int       used;
  fd_hash_t blk[ VIZ_VARIANT_MAX ];
  ulong     blk_cnt;

  /* who voted what -- for exact stake, not for display */
  signer_set_t notar  [ VIZ_VARIANT_MAX ][ signer_set_word_cnt ];
  signer_set_t nfb    [ signer_set_word_cnt ];
  signer_set_t skip   [ signer_set_word_cnt ];
  signer_set_t skip_fb[ signer_set_word_cnt ];
  signer_set_t final  [ signer_set_word_cnt ];

  ulong cert_mask;   /* 1<<AG_CERT_TYPE_*, any provenance        */
  ulong cert_built;  /* subset our own pool aggregated from votes */
  ulong cert_stake;  /* best certified stake seen for this slot  */
  int   we_voted;    /* we cast at least one vote for this slot */
  int   finalized;
  int   rooted;
};

struct viz {
  ag_epoch_info_t * ei;          /* ranked validator set, for rank -> stake */
  ulong             nv;
  ulong             total_stake;
  ushort            own_id;
  int               have_own_id;

  struct viz_row  row[ VIZ_ROW_MAX ];
  struct viz_feed feed[ VIZ_FEED_MAX ];
  ulong           feed_cnt;

  ulong finalized_slot;
  ulong rooted_slot;
  ulong replay_slot;
  ulong hi_slot;       /* highest slot any frag mentioned; anchors the ladder */
  ulong epoch;

  /* counters */
  ulong rx_vote, rx_cert, tx_vote, tx_cert, overrun;
  ulong rx_kind[ 5 ], tx_kind[ 5 ];

  long  now;
  long  frame_ns;
  long  next_frame;
  int   paused;
};

static struct viz g_viz;

static ulong
viz_stake_of( struct viz * v,
              ulong        rank ) {
  if( FD_UNLIKELY( !v->ei || rank>=v->nv ) ) return 0UL;
  return ag_epoch_info_validator( v->ei, rank )->stake;
}

/* set_stake sums the stake of every rank in s */

static ulong
set_stake( struct viz *         v,
           signer_set_t const * s ) {
  ulong t = 0UL;
  for( ulong i=0UL; i<v->nv; i++ ) if( signer_set_test( s, i ) ) t += viz_stake_of( v, i );
  return t;
}

static ulong
viz_pct( struct viz * v,
         ulong        stake ) {
  if( FD_UNLIKELY( !v->total_stake ) ) return 0UL;
  return ( stake*100UL )/v->total_stake;
}

static struct viz_row *
viz_row( struct viz * v,
         ulong        slot ) {
  v->hi_slot = fd_ulong_max( v->hi_slot, slot );
  struct viz_row * r = &v->row[ slot % VIZ_ROW_MAX ];
  if( FD_UNLIKELY( !r->used || r->slot!=slot ) ) {
    memset( r, 0, sizeof(*r) );
    r->slot = slot;
    r->used = 1;
  }
  return r;
}

static ulong
viz_variant( struct viz_row *  r,
             fd_hash_t const * h ) {
  if( FD_UNLIKELY( !h ) ) return ULONG_MAX;
  for( ulong i=0UL; i<r->blk_cnt; i++ ) if( !memcmp( r->blk[i].uc, h->uc, sizeof(fd_hash_t) ) ) return i;
  if( r->blk_cnt>=VIZ_VARIANT_MAX ) return ULONG_MAX;
  r->blk[ r->blk_cnt ] = *h;
  return r->blk_cnt++;
}

static void
viz_feed_push( struct viz * v,
               int          attr,
               char const * fmt, ... ) {
  struct viz_feed * f = &v->feed[ v->feed_cnt % VIZ_FEED_MAX ];
  f->attr = attr;
  va_list ap; va_start( ap, fmt );
  vsnprintf( f->text, sizeof(f->text), fmt, ap );
  va_end( ap );
  v->feed_cnt++;
}

static char const *
viz_vote_name( uint kind ) {
  switch( kind ) {
  case AG_VOTE_TYPE_NOTAR:          return "notar";
  case AG_VOTE_TYPE_FINAL:          return "final";
  case AG_VOTE_TYPE_SKIP:           return "skip";
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return "notar-fb";
  default:                          return "skip-fb";
  }
}

static int
viz_vote_attr( uint kind ) {
  switch( kind ) {
  case AG_VOTE_TYPE_NOTAR:          return A_NOTAR;
  case AG_VOTE_TYPE_FINAL:          return A_FINAL;
  case AG_VOTE_TYPE_SKIP:           return A_SKIP;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return A_NFB;
  default:                          return A_SFB;
  }
}

static void
viz_ingest_vote( struct viz *      v,
                 ag_vote_t const * vote ) {
  ulong slot = ag_vote_slot  ( vote );
  ulong rank = ag_vote_signer( vote );
  int   ours = v->have_own_id && rank==(ulong)v->own_id;

  if( ours ) { v->tx_vote++; if( vote->kind<5U ) v->tx_kind[ vote->kind ]++; }
  else       { v->rx_vote++; if( vote->kind<5U ) v->rx_kind[ vote->kind ]++; }

  struct viz_row * r = viz_row( v, slot );
  if( ours ) {
    r->we_voted = 1;
    viz_feed_push( v, viz_vote_attr( vote->kind ), "we vote %-8s s%lu", viz_vote_name( vote->kind ), slot );
  }
  if( FD_UNLIKELY( rank>=v->nv ) ) return;

  switch( vote->kind ) {
  case AG_VOTE_TYPE_NOTAR: {
    ulong var = viz_variant( r, ag_vote_block_hash( vote ) );
    if( var<VIZ_VARIANT_MAX ) signer_set_insert( r->notar[ var ], rank );
    break;
  }
  case AG_VOTE_TYPE_NOTAR_FALLBACK: signer_set_insert( r->nfb,     rank ); break;
  case AG_VOTE_TYPE_SKIP:           signer_set_insert( r->skip,    rank ); break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  signer_set_insert( r->skip_fb, rank ); break;
  default:                          signer_set_insert( r->final,   rank ); break;
  }
}

/* built==1 when our own pool aggregated this cert out of votes it
   collected, 0 when it arrived ready-made from a peer. */

static void
viz_ingest_cert( struct viz *      v,
                 ag_cert_t const * cert,
                 int               built ) {
  ulong slot = ag_cert_slot( cert );
  struct viz_row * r = viz_row( v, slot );
  /* A cert off the wire has no stake field -- ag_cert_de fills the slot,
     block id, aggregate signature and signer bitmap, and zeroes the rest.
     Recover the stake the way ag_cert_check_threshold does, from the
     bitmap against our copy of the epoch stakes. */
  ulong st = 0UL;
  for( ulong i=0UL; i<v->nv; i++ ) if( ag_cert_is_signer( cert, i ) ) st += viz_stake_of( v, i );

  r->cert_mask |= 1UL<<cert->kind;
  if( built ) r->cert_built |= 1UL<<cert->kind;
  r->cert_stake = fd_ulong_max( r->cert_stake, st );

  if( built ) v->tx_cert++;
  else        v->rx_cert++;
  viz_feed_push( v, built ? A_OWN : A_CERT, "%s %-14s s%-8lu %3lu%%",
                 built ? "built" : "recv ", ag_cert_type_to_string( cert->kind ), slot, viz_pct( v, st ) );
}

/* ------------------------------------------------------------- rendering */

/* bar draws a stake meter with ticks at the quorum thresholds. */

static void
viz_bar( ulong row,
         ulong col,
         ulong w,
         ulong stake,
         ulong total,
         int   attr ) {
  ulong fill = total ? ( stake*w )/total : 0UL;
  if( fill>w ) fill = w;
  for( ulong i=0UL; i<w; i++ ) cv_put( row, col+i, i<fill ? attr : A_DIM, i<fill ? g.full : g.lite );
  /* 20 / 40 / 60 / 80 */
  for( ulong q=1UL; q<=4UL; q++ ) {
    ulong t = ( w*q )/5UL;
    if( t<w && t>=fill ) cv_put( row, col+t, A_TICK, g.tick );
  }
}

static void
viz_render( struct viz * v ) {
  cv_clear();

  ulong w    = g_cols;
  ulong barw = w>96UL ? 40UL : 24UL;

  ulong c0 = cv_text( 0UL, 1UL, A_TITLE, "alpenglow votor -- live" );
  c0 = cv_text( 0UL, c0+2UL, A_DIM, "%lu validators  %lu SOL  rank ",
                v->nv, v->total_stake/1000000000UL );
  if( v->have_own_id ) c0 = cv_text( 0UL, c0, A_OWN,  "v%u", (uint)v->own_id );
  else                 c0 = cv_text( 0UL, c0, A_WARN, "unstaked" );
  if( v->paused )            cv_text( 0UL, c0+2UL, A_WARN, "[PAUSED]" );

  cv_text( 1UL, 1UL, A_HDR,
           "replay s%-10lu finalized s%-10lu rooted s%-10lu",
           v->replay_slot, v->finalized_slot, v->rooted_slot );
  if( FD_UNLIKELY( v->hi_slot>v->replay_slot+16UL ) )
    cv_text( 1UL, 58UL, A_BAD, "  replay tip is %lu slots behind the cluster",
             v->hi_slot - v->replay_slot );
  cv_text( 2UL, 1UL, A_DIM,
           "recv %lu votes / %lu certs    ours %lu votes / %lu certs built    overrun %lu",
           v->rx_vote, v->rx_cert, v->tx_vote, v->tx_cert, v->overrun );

  /* ---- slot ladder ---- */
  ulong r0 = 4UL;
  cv_text( r0, 1UL, A_HDR, "%-10s %-6s %-*s %-6s %s",
           "slot", "voted", (int)barw, "notar / skip / final", "stake", "certs (* = we built it)" );
  r0++;

  ulong hi = v->hi_slot;
  ulong lo = hi>VIZ_ROW_MAX ? hi-VIZ_ROW_MAX+1UL : 0UL;
  ulong rows_left = g_rows>10UL ? g_rows-r0-3UL : 4UL;

  for( ulong slot=hi; slot+1UL>lo && rows_left; slot-- ) {
    struct viz_row * r = &v->row[ slot % VIZ_ROW_MAX ];
    if( !r->used || r->slot!=slot ) { if( !slot ) break; continue; }

    ulong notar = 0UL;
    for( ulong i=0UL; i<r->blk_cnt; i++ ) notar = fd_ulong_max( notar, set_stake( v, r->notar[i] ) );
    ulong nfb   = set_stake( v, r->nfb     );
    ulong skip  = set_stake( v, r->skip    ) + set_stake( v, r->skip_fb );
    ulong final = set_stake( v, r->final   );

    int   lead  = notar+nfb >= skip;
    ulong show  = fd_ulong_max( lead ? notar+nfb : skip, r->cert_stake );

    /* colour the bar by the strongest verdict actually reached, so it
       agrees with the cert labels to its right */
    int attr;
    if(      r->cert_mask & (1UL<<AG_CERT_TYPE_FAST_FINAL) ) attr = A_FAST;
    else if( r->finalized                                  ) attr = A_FINAL;
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_FINAL)      ) attr = A_FINAL;
    else if( r->blk_cnt>1UL                                ) attr = A_FORK;
    else if( r->cert_mask & (1UL<<AG_CERT_TYPE_SKIP)       ) attr = A_SKIP;
    else                                                     attr = lead ? A_NOTAR : A_SKIP;

    ulong c = 1UL;
    c = cv_text( r0, c, r->rooted ? A_FAST : A_NONE, "s%-9lu", slot );
    c = cv_text( r0, c, r->we_voted ? A_OWN : A_DIM, "%-6s", r->we_voted ? "voted" : "-" );
    viz_bar( r0, c, barw, show, v->total_stake, attr );
    c += barw+1UL;
    c = cv_text( r0, c, attr, "%3lu%% ", viz_pct( v, show ) );
    /* fixed width, and reserved even when zero, so the cert labels to the
       right stay in one column */
    if( final ) c = cv_text( r0, c, A_FINAL, "f%3lu%% ", viz_pct( v, final ) );
    else        c = cv_text( r0, c, A_DIM,   "       " );

    /* a cert our pool aggregated itself is drawn in the "own" colour and
       flagged with *; one that arrived ready-made keeps its own colour */
#define CERT_LBL(k,a,t) do {                                                          \
    if( r->cert_mask & (1UL<<(k)) ) {                                                 \
      int _built = !!( r->cert_built & (1UL<<(k)) );                                  \
      c = cv_text( r0, c, _built ? A_OWN : (a), _built ? "*" t " " : t " " );         \
    }                                                                                 \
  } while(0)
    CERT_LBL( AG_CERT_TYPE_NOTAR,          A_CERT,  "NOTAR" );
    CERT_LBL( AG_CERT_TYPE_NOTAR_FALLBACK, A_NFB,   "NFB"   );
    CERT_LBL( AG_CERT_TYPE_SKIP,           A_SKIP,  "SKIP"  );
    CERT_LBL( AG_CERT_TYPE_FINAL,          A_FINAL, "FINAL" );
    CERT_LBL( AG_CERT_TYPE_FAST_FINAL,     A_FAST,  "FAST"  );
#undef CERT_LBL
    if( r->blk_cnt>1UL                                    ) c = cv_text( r0, c, A_FORK,  "FORK "  );

    r0++; rows_left--;
    if( !slot ) break;
  }

  /* ---- event feed ---- */
  ulong fr = g_rows>4UL ? g_rows-4UL : 1UL;
  cv_box( fr, 0UL, g_rows, w, A_DIM, "events" );
  ulong show_cnt = g_rows>fr+3UL ? g_rows-fr-2UL : 1UL;
  for( ulong i=0UL; i<show_cnt; i++ ) {
    if( v->feed_cnt<=i ) break;
    struct viz_feed * f = &v->feed[ ( v->feed_cnt-1UL-i )%VIZ_FEED_MAX ];
    cv_text( fr+show_cnt-i, 1UL, f->attr, "%s", f->text );
  }

  cv_flush();
}

/* viz_epoch installs the validator set from an EPOCH msg, ranked with
   ag_epoch_info_rank exactly as the votor tile ranks it -- so a vote's
   signer rank means the same thing here as it does there.  Taking it off
   the link rather than a file means this works both against the dev
   ingest topology and attached to a real validator. */

static void
viz_epoch( struct viz *                v,
           fd_epoch_info_msg_t const * msg,
           config_t *                  config ) {
  static ag_validator_info_t ranked[ AG_ALPENGLOW_VALIDATOR_MAX ];
  static uchar               ei_mem[ 1UL<<20 ];

  fd_vote_stake_weight_t const * sw  = fd_epoch_info_msg_stake_weights( msg );
  uchar const *                  bls = fd_epoch_info_msg_bls_pubkeys  ( msg );

  ulong nv = ag_epoch_info_rank( ranked, AG_ALPENGLOW_VALIDATOR_MAX, sw, msg->staked_vote_cnt, bls );
  if( FD_UNLIKELY( !nv ) ) return;
  if( FD_UNLIKELY( ag_epoch_info_footprint( nv )>sizeof(ei_mem) ) ) return;

  v->nv          = nv;
  v->ei          = ag_epoch_info_join( ag_epoch_info_new( ei_mem, ranked, nv ) );
  v->total_stake = ag_epoch_info_total_stake( v->ei );
  v->epoch       = msg->epoch;

  /* our rank, so the ladder can mark the slots we voted in */
  v->have_own_id = 0;
  uchar const * id_kp = fd_keyload_load( config->paths.identity_key, /* pubkey only: */ 1 );
  for( ulong r=0UL; r<nv; r++ ) {
    if( memcmp( ranked[r].pubkey.uc, id_kp, 32UL ) ) continue;
    v->own_id      = (ushort)r;
    v->have_own_id = 1;
    break;
  }
  viz_feed_push( v, A_HDR, "epoch %lu validator set: %lu voters", msg->epoch, nv );
}

/* ------------------------------------------------------- votor_out reader */

/* The viewer polls votor_out without being a topology consumer: it can be
   overrun by a busy votor tile, and that is fine -- it is a viewer, and
   an overrun just means a frame missed some frags (counted, and shown).
   Being a real consumer would let a stalled terminal backpressure
   consensus, which is exactly what we do not want. */

struct viz_rx {
  fd_frag_meta_t const * mcache;
  ulong                  depth;
  ulong                  seq;
  fd_wksp_t *            mem;
  ulong                  chunk0;
  ulong                  wmark;
};

static int
viz_rx_join( struct viz_rx * rx,
             fd_topo_t *     topo,
             char const *    link_name ) {
  ulong idx = fd_topo_find_link( topo, link_name, 0UL );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return 0;
  fd_topo_link_t * link = &topo->links[ idx ];

  rx->mcache = link->mcache;
  rx->depth  = fd_mcache_depth( rx->mcache );
  rx->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr_const( rx->mcache ) );
  rx->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  rx->chunk0 = fd_dcache_compact_chunk0( rx->mem, link->dcache );
  rx->wmark  = fd_dcache_compact_wmark ( rx->mem, link->dcache, link->mtu );
  return 1;
}



/* Drains at most budget frags, then returns so the frame can be drawn.
   Unbounded draining livelocks: with alpenglow_publish_rx on and a live
   cluster, votor_out is produced faster than a terminal can consume it,
   so "drain until caught up" never returns and nothing is ever rendered. */

static void
viz_rx_poll( struct viz *    v,
             struct viz_rx * rx,
             ulong           budget,
             int             is_epoch,
             config_t *      config ) {
  for( ulong n=0UL; n<budget; n++ ) {
    fd_frag_meta_t const * mline = rx->mcache + fd_mcache_line_idx( rx->seq, rx->depth );
    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, rx->seq );
    if( FD_UNLIKELY( diff ) ) {
      if( diff<0L ) return;              /* caught up */
      v->overrun += (ulong)diff;         /* lapped; skip ahead */
      rx->seq = seq_found;
      continue;
    }

    /* chunk lives in shared memory and the votor tile rewrites it as it
       laps us, so load it ONCE and bounds check before dereferencing --
       an overrun otherwise hands us an arbitrary offset and the copy
       below walks off the dcache. */
    ulong sig   = FD_VOLATILE_CONST( mline->sig   );
    ulong chunk = FD_VOLATILE_CONST( mline->chunk );
    if( FD_UNLIKELY( chunk<rx->chunk0 || chunk>rx->wmark ) ) {
      v->overrun++;
      rx->seq = fd_seq_inc( rx->seq, 1UL );
      continue;
    }

    /* copy before the seq re-check, then discard if we were overrun */
    static uchar buf[ 1UL<<20 ];
    ulong sz = fd_ulong_min( (ulong)FD_VOLATILE_CONST( mline->sz ), sizeof(buf) );
    memcpy( buf, fd_chunk_to_laddr_const( rx->mem, chunk ), sz );
    if( FD_UNLIKELY( fd_frag_meta_seq_query( mline )!=rx->seq ) ) { v->overrun++; rx->seq = fd_seq_inc( rx->seq, 1UL ); continue; }

    if( is_epoch ) {
      if( FD_LIKELY( sz>=sizeof(fd_epoch_info_msg_t) ) ) viz_epoch( v, (fd_epoch_info_msg_t const *)fd_type_pun_const( buf ), config );
      rx->seq = fd_seq_inc( rx->seq, 1UL );
      continue;
    }
    ag_votor_msg_t cpy = *(ag_votor_msg_t const *)fd_type_pun_const( buf );

    switch( FD_VOTOR_SIG_KIND( sig ) ) {
    case FD_VOTOR_SIG_VOTE: viz_ingest_vote( v, &cpy.vote ); break;
    case FD_VOTOR_SIG_CERT: viz_ingest_cert( v, &cpy.cert, /* built */ !(sig & FD_VOTOR_SIG_RX) ); break;
    case FD_VOTOR_SIG_SLOT: {
      v->replay_slot = fd_ulong_max( v->replay_slot, cpy.slot_done.replay_slot );
      viz_row( v, cpy.slot_done.replay_slot );
      break;
    }
    case FD_VOTOR_SIG_FINALIZED: {
      v->finalized_slot = fd_ulong_max( v->finalized_slot, cpy.finalized.slot );
      viz_row( v, cpy.finalized.slot )->finalized = 1;
      viz_feed_push( v, A_FINAL, "finalized s%lu", cpy.finalized.slot );
      break;
    }
    case FD_VOTOR_SIG_ROOTED: {
      v->rooted_slot = fd_ulong_max( v->rooted_slot, cpy.rooted.slot );
      viz_row( v, cpy.rooted.slot )->rooted = 1;
      viz_feed_push( v, A_FAST, "rooted s%lu", cpy.rooted.slot );
      break;
    }
    case FD_VOTOR_SIG_NOTARFB:
      viz_feed_push( v, A_NFB, "repair notar-fallback s%lu", cpy.notar_fallback.slot );
      break;
    default: break;
    }
    rx->seq = fd_seq_inc( rx->seq, 1UL );
  }
}

/* ------------------------------------------------------------- main loop */

static volatile int g_stop = 0;

static void
on_signal( int sig ) {
  (void)sig;
  g_stop = 1;
}

static void
viz_keys( struct viz * v ) {
  /* term_init only puts the terminal in non-blocking raw mode when we are
     on a tty; off-tty stdin is still canonical, so reading it would block
     the render loop forever. */
  if( !g_tty ) return;

  char c;
  while( read( STDIN_FILENO, &c, 1UL )==1L ) {
    if( c=='q' ) g_stop = 1;
    if( c==' ' ) v->paused = !v->paused;
  }
}

void
votor_monitor_run( config_t * config ) {
  struct viz *  v = &g_viz;
  struct viz_rx rx[1], erx[1];

  memset( v, 0, sizeof(*v) );
  v->frame_ns = 1000000000L/(long)fd_ulong_max( viz_fps, 1UL );

  FD_TEST( viz_rx_join( rx, &config->topo, "votor_out" ) );
  int have_epoch = viz_rx_join( erx, &config->topo, "replay_epoch" );

  g_color = !viz_no_color;
  g_tty   = isatty( STDOUT_FILENO ) && !viz_frames;
  glyphs_init( viz_ascii );
  if( viz_rows ) g_rows = fd_ulong_min( viz_rows, CV_ROWS );
  if( viz_cols ) g_cols = fd_ulong_min( viz_cols, CV_COLS );

  /* NOTICE / WARNING lines would land in the middle of the frame */
  fd_log_level_stderr_set( 4 );

  signal( SIGINT,  on_signal );
  signal( SIGTERM, on_signal );
  signal( SIGHUP,  on_signal );
  atexit( term_restore );
  term_init();

  ulong drawn = 0UL;
  while( !g_stop ) {
    v->now = fd_log_wallclock();
    if( !v->paused ) {
      if( have_epoch ) viz_rx_poll( v, erx, 8UL,             1 /* epoch */, config );
      /**/             viz_rx_poll( v, rx,  VIZ_RX_BUDGET,   0,             config );
    }
    viz_keys( v );

    if( v->now>=v->next_frame ) {
      v->next_frame = v->now + v->frame_ns;
      viz_render( v );
      drawn++;
      if( viz_frames && drawn>=viz_frames ) break;
    }

    struct timespec ts = { .tv_sec = 0L, .tv_nsec = 2000000L };
    nanosleep( &ts, NULL );
  }

  term_restore();
}

/* ---------------------------------------------------------------- action */

/* `firedancer-dev votor-monitor` attaches to an already running validator the
   way `monitor` does: join its workspaces read-only and poll.  It never
   configures or starts anything, so it is safe to attach and detach
   while the validator keeps running.

   For the view to have peer votes and certs to draw, the validator must
   have been started with the votor tile echoing what it receives -- see
   [development.votor_monitor] / --votor-monitor. */

static void
votor_monitor_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args FD_PARAM_UNUSED ) {
  votor_monitor_args( pargc, pargv );
}

static void
votor_monitor_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                   fd_cap_chk_t *   chk    FD_PARAM_UNUSED,
                   config_t const * config FD_PARAM_UNUSED ) {}

/* Joining maps the workspaces but leaves link->mcache / ->dcache
   unresolved; fd_topo_fill walks the objects and sets them, which is
   what `monitor` does too.  Without it the first fd_mcache_depth
   dereferences NULL. */

void
votor_monitor_attach( config_t * config ) {
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );
  votor_monitor_run( config );
}

void
votor_monitor_child( args_t *   args FD_PARAM_UNUSED,
                     config_t * config ) {
  votor_monitor_attach( config );
}

static void
votor_monitor_cmd_fn( args_t *   args,
                      config_t * config ) {
  votor_monitor_child( args, config );
}

action_t fd_action_votor_monitor = {
  .name        = "votor-monitor",
  .args        = votor_monitor_cmd_args,
  .fn          = votor_monitor_cmd_fn,
  .perm        = votor_monitor_cmd_perm,
  .description = "Draw live Alpenglow consensus from a running validator",
};
