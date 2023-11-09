#ifndef HEADER_fd_src_app_fdctl_monitor_helper_h
#define HEADER_fd_src_app_fdctl_monitor_helper_h

#include "../fdctl.h"

/* TEXT_* are quick-and-dirty color terminal hacks.  Probably should
   do something more robust longer term. */
#define TEXT_NOCURSOR   "\033[?25l"
#define TEXT_CURSOR     "\033[?25h"
#define TEXT_ERASE_LINE "\033[0K"
#define TEXT_NEWLINE    TEXT_ERASE_LINE "\n"

#define TEXT_NORMAL "\033[0m"
#define TEXT_BLUE   "\033[34m"
#define TEXT_GREEN  "\033[32m"
#define TEXT_YELLOW "\033[93m"
#define TEXT_RED    "\033[31m"

/* printf_age prints _dt in ns as an age to stdout, will be exactly 10
   char wide.  Since pretty printing this value will often require
   rounding it, the rounding is in a round toward zero sense. */
void
printf_age( char ** buf,
            ulong * buf_sz,
            long _dt );

/* printf_stale is printf_age with the tweak that ages less than or
   equal to expire (in ns) will be suppressed to limit visual chatter.
   Will be exactly 10 char wide and color coded. */
void
printf_stale( char ** buf,
              ulong * buf_sz,
              long age,
              long expire );

/* printf_heart will print to stdout whether or not a heartbeat was
   detected.  Will be exactly 5 char wide and color coded. */
void
printf_heart( char ** buf,
              ulong * buf_sz,
              long hb_now,
              long hb_then );

char const *
sig_color( ulong sig );

/* printf_sig will print the current and previous value of a cnc signal.
   to stdout.  Will be exactly 10 char wide and color coded. */
void
printf_sig( char ** buf,
            ulong * buf_sz,
            ulong sig_now,
            ulong sig_then );

/* printf_err_bool will print to stdout a boolean flag that indicates
   if error condition was present now and then.  Will be exactly 12 char
   wide and color coded. */
void
printf_err_bool( char ** buf,
                 ulong * buf_sz,
                 ulong err_now,
                 ulong err_then );

void
printf_err_cnt( char ** buf,
                ulong * buf_sz,
                ulong cnt_now,
                ulong cnt_then );

/* printf_seq will print to stdout a 64-bit sequence number and how it
   has changed between now and then.  Will be exactly 25 char wide and
   color coded. */
void
printf_seq( char ** buf,
            ulong * buf_sz,
            ulong seq_now,
            ulong seq_then );

/* printf_rate prints to stdout:

     cvt*((overhead + (cnt_now - cnt_then)) / dt)

   Will be exactly 8 char wide, right justifed with aligned decimal
   point.  Uses standard engineering base 10 suffixes (e.g. 10.0e9 ->
   10.0G) to support wide dynamic range rate diagnostics.  Since pretty
   printing this value will often require rounding it, the rounding is
   roughly in a round toward near even zero sense (this could be
   improved numerically to make it even more strict rounding, e.g.
   rate*=1e-3 used below is not exact, but this is more than adequate
   for a quick-and-dirty low precision diagnostic. */
void
printf_rate( char ** buf,
             ulong * buf_sz,
             double cvt,
             double overhead,
             ulong  cnt_now,
             ulong  cnt_then,
             long   dt  );

void
printf_pct( char ** buf,
            ulong * buf_sz,
            ulong  num_now,
            ulong  num_then,
            double lhopital_num,
            ulong  den_now,
            ulong  den_then,
            double lhopital_den );

#endif /* HEADER_fd_src_app_fdctl_monitor_helper_h */
