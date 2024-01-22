void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) __attribute__((noreturn)) {
  (void)now; (void)func;
  __CPROVER_printf( "[%d] %s(%d): %s", level, file, line, msg );
}


void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) __attribute__((noreturn)) {
  (void)now; (void)func;
  __CPROVER_printf( "[%d] %s(%d): %s", level, file, line, msg );
  __CPROVER_assert( 0, "Error log used" );
}

long
current_wallclock = 0;

long
fd_log_wallclock( void ) {
  long t;
  __CPROVER_assume(t >= current_wallclock);
  current_wallclock = t;
  return current_wallclock;
}

char const *
fd_log_private_0( char const * fmt, ... ) {
  (void)fmt;
  return "";
}
