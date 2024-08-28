#ifndef HEADER_fd_src_app_fddev_tiles_hist_h
#define HEADER_fd_src_app_fddev_tiles_hist_h

#define HIST_BINS 100UL
#define HIST_MIN  0.00f
#define HIST_MAX  20.0f
#define HIST_INTERVAL 1024
#define HIST_HEIGHT   30

static inline void
bin_hist( float const * vals,
          ulong         val_cnt,
          ulong *       bins,
          ulong         bin_cnt,
          float         min,
          float         max ) {
  float scale = (float)bin_cnt/(max-min);
  memset( bins, '\0', bin_cnt*sizeof(ulong) );
  for( ulong i=0UL; i<val_cnt; i++ ) {
    float v = vals[i];
    ulong bin = fd_ulong_min( (ulong)__builtin_fmaxf( (v-min)*scale, 0.0f ), bin_cnt-1UL );
    bins[bin]++;
  }
}

static inline ulong
draw_hist( ulong const * bins,
           ulong         bin_cnt,
           char        * buffer,
           ulong         buf_sz,
           ulong         height ) {

  buffer[0] = '\0'; 

  char * buf    = buffer;

  ulong val_cnt = 0UL;
  for( ulong i=0UL; i<bin_cnt; i++ ) val_cnt += bins[i];

  #define PRINT( ... ) do {                                                       \
    int n = snprintf( buf, buf_sz, __VA_ARGS__ );                               \
    if( FD_UNLIKELY( n<0 ) ) FD_LOG_ERR(( "snprintf failed" ));                 \
    if( FD_UNLIKELY( (ulong)n>=buf_sz ) ) FD_LOG_ERR(( "snprintf truncated" )); \
    buf += n; buf_sz -= (ulong)n;                                               \
  } while(0)

  for( ulong h=0UL; h<height; h++ ) {
    /* For example, with height==3, if x is the fraction of val_cnt in the
       bucket,
       h = 0 : draw a '.' if  4/6 < x <= 5/6, draw a '#' if 5/6 < x <= 6/6
       h = 1 : draw a '.' if  2/6 < x <= 3/6, draw a '#' if 3/6 < x <= 4/6
       h = 2 : draw a '.' if  0/6 < x <= 1/6, draw a '#' if 1/6 < x <= 2/6. 
       In general, it's
       2*(height-h-1)/(2*height) < x <= (2*(height-h)-1)/(2*height) for a '.'
       and (2*(height-h)-1)/(2*height) < x <= 2*(height-h)/(2*height) for a '#'.

       We'd rather do this as integer arithmetic though.  We need some simple
       facts about floors.  Suppose y and z are non-negative real numbers and n
       is an integer.  Then y<n<=z if and only if floor(y)<n<=floor(z). */
    ulong pound_cutoff = (ulong)( 0.3f*(float)val_cnt*((float)(height-h)-0.5f)/(float)height);
    ulong dot_cutoff   = (ulong)( 0.3f*(float)val_cnt*((float)(height-h-1UL) )/(float)height);
    PRINT( "  |" );
    for( ulong bin=0UL; bin<bin_cnt; bin++ ) {
      char c = fd_char_if( pound_cutoff<bins[bin], '#', fd_char_if( dot_cutoff<bins[bin], '.', ' ' ) );
      *(buf++) = c; buf_sz--;
    }
    *(buf++) = '\n'; buf_sz--;
  }
  PRINT( "  -" );
  for( ulong bin=0UL; bin<bin_cnt; bin++ ) PRINT( "-" );
  PRINT( "\n" );
  const char x_label[] = "Value (lamports/CU)";
  FD_TEST( bin_cnt > strlen( x_label ) );
  ulong spaces = (bin_cnt-strlen( x_label ))/2UL + 1UL;
  for( ulong i=0UL; i<spaces; i++ ) PRINT( " " );
  PRINT( "%s\n", x_label );

  PRINT( "\033[%luF", height+3UL );
  return val_cnt;
}

#endif /* HEADER_fd_src_app_fddev_tiles_hist_h */
