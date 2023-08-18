#include "helper.h"

#include <stdio.h>

#include "../../../disco/fd_disco.h"

#define PRINT( ... ) do {                                                        \
    int n = snprintf( *buf, *buf_sz, __VA_ARGS__ );                              \
    if( FD_UNLIKELY( n<0 ) ) FD_LOG_ERR(( "snprintf failed" ));                  \
    if( FD_UNLIKELY( (ulong)n>=*buf_sz ) ) FD_LOG_ERR(( "snprintf truncated" )); \
    *buf += n; *buf_sz -= (ulong)n;                                              \
  } while(0)

void
printf_age( char ** buf,
            ulong * buf_sz,
            long _dt ) {
  if( FD_UNLIKELY( _dt< 0L ) ) { PRINT( "   invalid" ); return; }
  if( FD_UNLIKELY( _dt==0L ) ) { PRINT( "        0s" ); return; }
  ulong rem = (ulong)_dt;
  ulong ns = rem % 1000UL; rem /= 1000UL; if( !rem /*no u*/ ) { PRINT( "      %3lun",           ns                   ); return; }
  ulong us = rem % 1000UL; rem /= 1000UL; if( !rem /*no m*/ ) { PRINT( "  %3lu.%03luu",         us, ns               ); return; }
  ulong ms = rem % 1000UL; rem /= 1000UL; if( !rem /*no s*/ ) { PRINT( "%3lu.%03lu%02lum",      ms, us, ns/10UL      ); return; }
  ulong  s = rem %   60UL; rem /=   60UL; if( !rem /*no m*/ ) { PRINT( "%2lu.%03lu%03lus",      s,  ms, us           ); return; }
  ulong  m = rem %   60UL; rem /=   60UL; if( !rem /*no h*/ ) { PRINT( "%2lu:%02lu.%03lu%1lu",  m,  s,  ms, us/100UL ); return; }
  ulong  h = rem %   24UL; rem /=   24UL; if( !rem /*no d*/ ) { PRINT( "%2lu:%02lu:%02lu.%1lu", h,  m,  s,  ms/100UL ); return; }
  ulong  d = rem %    7UL; rem /=    7UL; if( !rem /*no w*/ ) { PRINT( "  %1lud %2lu:%02lu",    d,  h,  m            ); return; }
  ulong  w = rem;                         if( w<=99UL       ) { PRINT( "%2luw %1lud %2luh",     w,  d,  h            ); return; }
  /* note that this can handle LONG_MAX fine */                 PRINT( "%6luw %1lud",           w,  d                );
}

void
printf_stale( char ** buf,
              ulong * buf_sz,
              long age,
              long expire ) {
  if( FD_UNLIKELY( age>expire ) ) {
    PRINT( TEXT_YELLOW );
    printf_age( buf, buf_sz, age );
    PRINT( TEXT_NORMAL );
    return;
  }
  PRINT( TEXT_GREEN "         -" TEXT_NORMAL );
}

void
printf_heart( char ** buf,
              ulong * buf_sz,
              long hb_now,
              long hb_then ) {
  long dt = hb_now - hb_then;
  PRINT( "%s", (dt>0L) ? (TEXT_GREEN "    -" TEXT_NORMAL) :
               (!dt)   ? (TEXT_RED   " NONE" TEXT_NORMAL) :
                         (TEXT_BLUE  "RESET" TEXT_NORMAL) );
}

char const *
sig_color( ulong sig ) {
  switch( sig ) {
  case FD_CNC_SIGNAL_BOOT: return TEXT_BLUE;   break; /* Blue -> waiting for tile to start */
  case FD_CNC_SIGNAL_HALT: return TEXT_YELLOW; break; /* Yellow -> waiting for tile to process */
  case FD_CNC_SIGNAL_RUN:  return TEXT_GREEN;  break; /* Green -> Normal */
  case FD_CNC_SIGNAL_FAIL: return TEXT_RED;    break; /* Red -> Definitely abnormal */
  default: break; /* Unknown, don't colorize */
  }
  return TEXT_NORMAL;
}

void
printf_sig( char ** buf,
            ulong * buf_sz,
            ulong sig_now,
            ulong sig_then ) {
  char buf0[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
  char buf1[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
  PRINT( "%s%4s" TEXT_NORMAL "(%s%4s" TEXT_NORMAL ")",
         sig_color( sig_now  ), fd_cnc_signal_cstr( sig_now,  buf0 ),
         sig_color( sig_then ), fd_cnc_signal_cstr( sig_then, buf1 ) );
}

void
printf_err_bool( char ** buf,
                 ulong * buf_sz,
                 ulong err_now,
                 ulong err_then ) {
  PRINT( "%5s(%5s)", err_now  ? TEXT_RED "err" TEXT_NORMAL : TEXT_GREEN "  -" TEXT_NORMAL,
                     err_then ? TEXT_RED "err" TEXT_NORMAL : TEXT_GREEN "  -" TEXT_NORMAL );
}

void
printf_err_cnt( char ** buf,
                ulong * buf_sz,
                ulong cnt_now,
                ulong cnt_then ) {
  long delta = (long)(cnt_now - cnt_then);
  char const * color = (!delta)   ? TEXT_GREEN  /* no new error counts */
                     : (delta>0L) ? TEXT_RED    /* new error counts */
                     : (cnt_now)  ? TEXT_YELLOW /* decrease of existing error counts?? */
                     :              TEXT_BLUE;  /* reset of the error counter */
  if(      delta> 99999L ) PRINT( "%10u(%s>+99999" TEXT_NORMAL ")", (uint)cnt_now, color        );
  else if( delta<-99999L ) PRINT( "%10u(%s<-99999" TEXT_NORMAL ")", (uint)cnt_now, color        );
  else                     PRINT( "%10u(%s %+6li"  TEXT_NORMAL ")", (uint)cnt_now, color, delta );
}

void
printf_seq( char ** buf,
            ulong * buf_sz,
            ulong seq_now,
            ulong seq_then ) {
  long delta = (long)(seq_now - seq_then);
  char const * color = (!delta)   ? TEXT_YELLOW /* no sequence numbers published */
                     : (delta>0L) ? TEXT_GREEN  /* new sequence numbers published */
                     : (seq_now)  ? TEXT_RED    /* sequence number went backward */
                     :              TEXT_BLUE;  /* sequence number reset */
  if(      delta> 99999L ) PRINT( "%10lu(%s>+99999" TEXT_NORMAL ")", seq_now, color        );
  else if( delta<-99999L ) PRINT( "%10lu(%s<-99999" TEXT_NORMAL ")", seq_now, color        );
  else                     PRINT( "%10lu(%s %+6li"  TEXT_NORMAL ")", seq_now, color, delta );
}

void
printf_rate( char ** buf,
             ulong * buf_sz,
             double cvt,
             double overhead,
             ulong  cnt_now,
             ulong  cnt_then,
             long   dt  ) {
  if( FD_UNLIKELY( !((0.< cvt     ) & (cvt<=DBL_MAX)) |
                   !((0.<=overhead) & (cvt<=DBL_MAX)) |
                   (cnt_now<cnt_then)                 |
                   (dt<=0L)                           ) ) {
    PRINT( TEXT_RED " invalid" TEXT_NORMAL );
    return;
  }
  double rate = cvt*(overhead+(double)(cnt_now-cnt_then)) / (double)dt;
  if( FD_UNLIKELY( !((0.<=rate) & (rate<=DBL_MAX)) ) ) {
    PRINT( TEXT_RED "overflow" TEXT_NORMAL );
    return;
  }
  /**/          if( rate<=9999.9 ) { PRINT( " %6.1f ", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fK", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fM", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fG", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fT", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fP", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fE", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fZ", rate ); return; }
  rate *= 1e-3; if( rate<=9999.9 ) { PRINT( " %6.1fY", rate ); return; }
  /**/                               PRINT( ">9999.9Y" );
}

void
printf_pct( char ** buf,
            ulong * buf_sz,
            ulong  num_now,
            ulong  num_then,
            double lhopital_num,
            ulong  den_now,
            ulong  den_then,
            double lhopital_den ) {
  if( FD_UNLIKELY( (num_now<num_then)                              |
                   (den_now<den_then)                              |
                   !((0.<=lhopital_num) & (lhopital_num<=DBL_MAX)) |
                   !((0.< lhopital_den) & (lhopital_den<=DBL_MAX)) ) ) {
    PRINT( TEXT_RED " invalid" TEXT_NORMAL );
    return;
  }

  double pct = 100.*(((double)(num_now - num_then) + lhopital_num) / ((double)(den_now - den_then) + lhopital_den));

  if( FD_UNLIKELY( !((0.<=pct) & (pct<=DBL_MAX)) ) ) {
    PRINT( TEXT_RED "overflow" TEXT_NORMAL );
    return;
  }

  if( pct<=999.999 ) { PRINT( " %7.3f", pct ); return; }
  /**/                 PRINT( ">999.999" );
}
