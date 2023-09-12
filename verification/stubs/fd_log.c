char const *
fd_log_private_0( char const * fmt, ... ) {
    return (char const *)0;
}

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {
}

long current_wallclock = 0;

long fd_log_wallclock( void ) {
    long t;
    __CPROVER_assume(t >= current_wallclock);
    current_wallclock = t;
    return current_wallclock;
}
