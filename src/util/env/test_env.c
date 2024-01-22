#include "../fd_util.h"

/* FIXME: TEST ENV KEYS AND TEST NULL ENV / NULL CSTR OPTIONS */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char   buf[1024];
  char * _my_argv[ 128 ];

  int     my_argc = 0;
  char ** my_argv = _my_argv;

  char *  p = buf;
# define _(cstr) my_argv[ my_argc++ ] = p; strcpy( p, cstr ); p += strlen( cstr )+1UL
  _( "app"      );
  _( "cstr"     );  _( "zero" );  _( "cstr"   );  _( "one"  );
  _( "char"     );  _( "2345" );  _( "char"   );  _( "6789" );
  _( "schar"    );  _( "-10"  );  _( "schar"  );  _( "-11"  );
  _( "short"    );  _( "-12"  );  _( "short"  );  _( "-13"  );
  _( "int"      );  _( "-14"  );  _( "int"    );  _( "-15"  );
  _( "long"     );  _( "-16"  );  _( "long"   );  _( "-17"  );
  _( "uchar"    );  _( "18"   );  _( "uchar"  );  _( "19"   );
  _( "ushort"   );  _( "20"   );  _( "ushort" );  _( "21"   );
  _( "uint"     );  _( "22"   );  _( "uint"   );  _( "23"   );
  _( "ulong"    );  _( "24"   );  _( "ulong"  );  _( "25"   );
  _( "float"    );  _( "26"   );  _( "float"  );  _( "27"   );
# if FD_HAS_DOUBLE
  _( "double"   );  _( "28"   );  _( "double" );  _( "29"   );
# endif
  _( "leftover" );
# undef _
  my_argv[ my_argc ] = NULL;

  /* Test normal stripping */

  int rem = my_argc;
  char const * cstr = fd_env_strip_cmdline_cstr  ( &my_argc, &my_argv, "cstr",   NULL,          NULL ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && cstr && !strcmp( cstr, "one" ) );
  char         c    = fd_env_strip_cmdline_char  ( &my_argc, &my_argv, "char",   NULL,          'a'  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && c   ==         '6'  );
  schar        sc   = fd_env_strip_cmdline_schar ( &my_argc, &my_argv, "schar",  NULL, (schar) -28   ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && sc  ==(schar) -11   );
  short        s    = fd_env_strip_cmdline_short ( &my_argc, &my_argv, "short",  NULL, (short) -30   ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && s   ==(short) -13   );
  int          i    = fd_env_strip_cmdline_int   ( &my_argc, &my_argv, "int",    NULL,         -32   ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && i   ==        -15   );
  long         l    = fd_env_strip_cmdline_long  ( &my_argc, &my_argv, "long",   NULL,         -34L  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && l   ==        -17L  );
  uchar        uc   = fd_env_strip_cmdline_uchar ( &my_argc, &my_argv, "uchar",  NULL, (uchar)  28U  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && uc  ==(uchar)  19   );
  ushort       us   = fd_env_strip_cmdline_ushort( &my_argc, &my_argv, "ushort", NULL, (ushort) 30U  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && us  ==(ushort) 21   );
  uint         ui   = fd_env_strip_cmdline_uint  ( &my_argc, &my_argv, "uint",   NULL,          32U  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && ui  ==         23   );
  ulong        ul   = fd_env_strip_cmdline_ulong ( &my_argc, &my_argv, "ulong",  NULL,          34UL ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && ul  ==         25   );
  float        f    = fd_env_strip_cmdline_float ( &my_argc, &my_argv, "float",  NULL,          36.f ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && f   ==         27.f );
# if FD_HAS_DOUBLE
  double       d    = fd_env_strip_cmdline_double( &my_argc, &my_argv, "double", NULL,          38.  ); rem-=4; FD_TEST( my_argc==rem && !my_argv[rem] && d   ==         29.  );
# endif
  FD_TEST( rem==2 && !strcmp( my_argv[0], "app" ) && !strcmp( my_argv[1], "leftover" ) );

  /* Test default pass through */

  cstr = fd_env_strip_cmdline_cstr  ( &my_argc, &my_argv, "cstr",   NULL,          buf  ); FD_TEST( my_argc==rem && !my_argv[rem] && cstr==         buf  );
  c    = fd_env_strip_cmdline_char  ( &my_argc, &my_argv, "char",   NULL,          'x'  ); FD_TEST( my_argc==rem && !my_argv[rem] && c   ==         'x'  );
  sc   = fd_env_strip_cmdline_schar ( &my_argc, &my_argv, "schar",  NULL, (schar) -28   ); FD_TEST( my_argc==rem && !my_argv[rem] && sc  ==(schar) -28   );
  s    = fd_env_strip_cmdline_short ( &my_argc, &my_argv, "short",  NULL, (short) -30   ); FD_TEST( my_argc==rem && !my_argv[rem] && s   ==(short) -30   );
  i    = fd_env_strip_cmdline_int   ( &my_argc, &my_argv, "int",    NULL,         -32   ); FD_TEST( my_argc==rem && !my_argv[rem] && i   ==        -32   );
  l    = fd_env_strip_cmdline_long  ( &my_argc, &my_argv, "long",   NULL,         -34L  ); FD_TEST( my_argc==rem && !my_argv[rem] && l   ==        -34L  );
  uc   = fd_env_strip_cmdline_uchar ( &my_argc, &my_argv, "uchar",  NULL, (uchar)  28U  ); FD_TEST( my_argc==rem && !my_argv[rem] && uc  ==(uchar)  28U  );
  us   = fd_env_strip_cmdline_ushort( &my_argc, &my_argv, "ushort", NULL, (ushort) 30U  ); FD_TEST( my_argc==rem && !my_argv[rem] && us  ==(ushort) 30U  );
  ui   = fd_env_strip_cmdline_uint  ( &my_argc, &my_argv, "uint",   NULL,          32U  ); FD_TEST( my_argc==rem && !my_argv[rem] && ui  ==         32U  );
  ul   = fd_env_strip_cmdline_ulong ( &my_argc, &my_argv, "ulong",  NULL,          34UL ); FD_TEST( my_argc==rem && !my_argv[rem] && ul  ==         34UL );
  f    = fd_env_strip_cmdline_float ( &my_argc, &my_argv, "float",  NULL,          36.f ); FD_TEST( my_argc==rem && !my_argv[rem] && f   ==         36.f );
# if FD_HAS_DOUBLE
  d    = fd_env_strip_cmdline_double( &my_argc, &my_argv, "double", NULL,          38.  ); FD_TEST( my_argc==rem && !my_argv[rem] && d   ==         38.  );
# endif
  FD_TEST( !strcmp( my_argv[0], "app" ) && !strcmp( my_argv[1], "leftover" ) );

  /* Test edge cases */

  do {
    my_argc--; rem--; my_argv[my_argc] = NULL;
    cstr = fd_env_strip_cmdline_cstr  ( &my_argc, &my_argv, "cstr",   NULL,          NULL ); FD_TEST( my_argc==rem && !my_argv[rem] && cstr==        NULL  );
    c    = fd_env_strip_cmdline_char  ( &my_argc, &my_argv, "char",   NULL,          '\0' ); FD_TEST( my_argc==rem && !my_argv[rem] && c   ==        '\0'  );
    sc   = fd_env_strip_cmdline_schar ( &my_argc, &my_argv, "schar",  NULL, (schar) -28   ); FD_TEST( my_argc==rem && !my_argv[rem] && sc  ==(schar) -28   );
    s    = fd_env_strip_cmdline_short ( &my_argc, &my_argv, "short",  NULL, (short) -30   ); FD_TEST( my_argc==rem && !my_argv[rem] && s   ==(short) -30   );
    i    = fd_env_strip_cmdline_int   ( &my_argc, &my_argv, "int",    NULL,         -32   ); FD_TEST( my_argc==rem && !my_argv[rem] && i   ==        -32   );
    l    = fd_env_strip_cmdline_long  ( &my_argc, &my_argv, "long",   NULL,         -34L  ); FD_TEST( my_argc==rem && !my_argv[rem] && l   ==        -34L  );
    uc   = fd_env_strip_cmdline_uchar ( &my_argc, &my_argv, "uchar",  NULL, (uchar)  28U  ); FD_TEST( my_argc==rem && !my_argv[rem] && uc  ==(uchar)  28U  );
    us   = fd_env_strip_cmdline_ushort( &my_argc, &my_argv, "ushort", NULL, (ushort) 30U  ); FD_TEST( my_argc==rem && !my_argv[rem] && us  ==(ushort) 30U  );
    ui   = fd_env_strip_cmdline_uint  ( &my_argc, &my_argv, "uint",   NULL,          32U  ); FD_TEST( my_argc==rem && !my_argv[rem] && ui  ==         32U  );
    ul   = fd_env_strip_cmdline_ulong ( &my_argc, &my_argv, "ulong",  NULL,          34UL ); FD_TEST( my_argc==rem && !my_argv[rem] && ul  ==         34UL );
    f    = fd_env_strip_cmdline_float ( &my_argc, &my_argv, "float",  NULL,          36.f ); FD_TEST( my_argc==rem && !my_argv[rem] && f   ==         36.f );
#   if FD_HAS_DOUBLE
    d    = fd_env_strip_cmdline_double( &my_argc, &my_argv, "double", NULL,          38.  ); FD_TEST( my_argc==rem && !my_argv[rem] && d   ==         38.  );
#   endif
  } while( rem );

  cstr = fd_env_strip_cmdline_cstr  ( NULL, NULL, "cstr",   NULL,          p    ); FD_TEST( cstr==        p     );
  c    = fd_env_strip_cmdline_char  ( NULL, NULL, "char",   NULL,          'y'  ); FD_TEST( c   ==        'y'   );
  sc   = fd_env_strip_cmdline_schar ( NULL, NULL, "schar",  NULL, (schar) -28   ); FD_TEST( sc  ==(schar) -28   );
  s    = fd_env_strip_cmdline_short ( NULL, NULL, "short",  NULL, (short) -30   ); FD_TEST( s   ==(short) -30   );
  i    = fd_env_strip_cmdline_int   ( NULL, NULL, "int",    NULL,         -32   ); FD_TEST( i   ==        -32   );
  l    = fd_env_strip_cmdline_long  ( NULL, NULL, "long",   NULL,         -34L  ); FD_TEST( l   ==        -34L  );
  uc   = fd_env_strip_cmdline_uchar ( NULL, NULL, "uchar",  NULL, (uchar)  28U  ); FD_TEST( uc  ==(uchar)  28U  );
  us   = fd_env_strip_cmdline_ushort( NULL, NULL, "ushort", NULL, (ushort) 30U  ); FD_TEST( us  ==(ushort) 30U  );
  ui   = fd_env_strip_cmdline_uint  ( NULL, NULL, "uint",   NULL,          32U  ); FD_TEST( ui  ==         32U  );
  ul   = fd_env_strip_cmdline_ulong ( NULL, NULL, "ulong",  NULL,          34UL ); FD_TEST( ul  ==         34UL );
  f    = fd_env_strip_cmdline_float ( NULL, NULL, "float",  NULL,          36.f ); FD_TEST( f   ==         36.f );
# if FD_HAS_DOUBLE
  d    = fd_env_strip_cmdline_double( NULL, NULL, "double", NULL,          38.  ); FD_TEST( d   ==         38.  );
# endif

  int argc2 = 1;
  char *hello = "--hello";
  char **argv2 = (char*[]){ hello, NULL };
  FD_TEST( !fd_env_strip_cmdline_contains ( &argc2, &argv2, "--hello2" ) );
  FD_TEST( !fd_env_strip_cmdline_contains ( &argc2, &argv2, "hello" ) );
  FD_TEST( argc2 == 1 );
  FD_TEST( fd_env_strip_cmdline_contains ( &argc2, &argv2, "--hello" ) );
  FD_TEST( argc2 == 0 );
  FD_TEST( *argv2 == NULL );

  argc2 = 3;
  char *bye = "--bye";
  argv2 = (char*[]){ hello, bye, hello, NULL };
  FD_TEST( fd_env_strip_cmdline_contains ( &argc2, &argv2, "--hello" ) );
  FD_TEST( argc2 == 1 );
  FD_TEST( !strcmp(*argv2, "--bye") );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

