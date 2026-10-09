#include "fd_cpu_isolation.h"

typedef struct {
  char const * release;
  int          safe;
} kernel_case_t;

static kernel_case_t const cases[] = {
  /* Ubuntu 6.8 (noble, jammy HWE): predates plugging */
  { "6.8.0-142-generic",                     1 },
  { "6.8.0-146-generic",                     1 },
  { "6.8.0-138-generic",                     1 },
  { "6.8.0-137-generic",                     1 },
  { "6.8.0-139-generic",                     1 },
  { "6.8.0-106-generic",                     1 },
  { "6.8.0-90-generic",                      1 },
  { "6.8.0-124-generic",                     1 },
  { "6.8.0-134-generic",                     1 },
  { "6.8.0-136-generic",                     1 },
  { "6.8.0-138-lowlatency",                  1 },
  { "6.8.0-146-lowlatency",                  1 },

  /* Ubuntu 7.0 */
  { "7.0.0-28-generic",                      1 },
  { "7.0.0-30-generic",                      1 },
  { "7.0.0-31-generic",                      1 },
  { "7.0.0-34-generic",                      1 },
  { "7.0.0-38-generic",                      1 },
  { "7.0.0-14-generic",                      1 }, /* first 7.0 final build */
  { "7.0.0-13-generic",                      0 }, /* 7.0-rc7 */
  { "7.0.0-13-lowlatency",                   0 },
  { "7.0.0-6-generic",                       0 }, /* 7.0-rc4 */

  /* RHEL 9 / Rocky / CIQ: plugging backported, no fix */
  { "5.14.0-611.54.1.el9_7.x86_64",          0 },
  { "5.14.0-611.41.1.el9_7.x86_64",          0 },
  { "5.14.0-687.31.1+2.1.el9_8_ciq.x86_64",  0 },
  { "5.14.0-687.39.1+2.1.el9_8_ciq.x86_64",  0 },
  { "5.14.0-687.42.1+2.1.el9_8_ciq.x86_64",  0 },
  { "5.14.0-687.46.1+2.1.el9_8_ciq.x86_64",  0 }, /* incident */
  { "5.14.0-687.49.1+2.1.el9_8_ciq.x86_64",  0 },
  { "5.14.0-687.52.1+2.1.el9_8_ciq.x86_64",  0 },
  { "5.14.0-687.36.1.el9_8.x86_64",          0 },
  { "5.14.0-687.49.1.el9_8.x86_64",          0 },
  { "5.14.0-687.42.1.el9_8.aarch64",         0 },

  /* RHEL 9 before 9.5 (no plugging), RHEL 8, RHEL 10 */
  { "5.14.0-427.42.1.el9_4.x86_64",          1 },
  { "5.14.0-463.el9.x86_64",                 1 },
  { "5.14.0-464.el9.x86_64",                 0 }, /* plugging backported */
  { "5.14.0-503.11.1.el9_5.x86_64",          0 },
  { "5.14.0-757.el9.x86_64",                 0 },
  { "4.18.0-553.172.1.el8_10.x86_64",        1 },
  { "6.12.0-211.28.1.el10_2.x86_64",         0 }, /* Alma 10 */
  { "6.12.0-275.el10.x86_64",                0 },

  /* Oracle UEK: el9 tag but not RHEL's base version */
  { "5.15.0-209.161.7.2.el9uek.x86_64",      1 },
  { "6.12.0-100.28.2.el9uek.x86_64",         0 },

  /* Ubuntu 6.14 / 6.17 HWE: plugging, no fix (6.14.11, 6.17.13) */
  { "6.14.0-37-generic",                     0 },
  { "6.17.0-22-generic",                     0 },
  { "6.17.0-23-generic",                     0 },
  { "6.17.0-35-generic",                     0 },

  /* Other Ubuntu series */
  { "5.15.0-199-generic",                    1 },
  { "6.11.0-29-generic",                     0 },
  { "6.8.0-142-azure",                       1 },
  { "6.9.0-1-generic",                       0 },

  /* Debian */
  { "6.1.0-28-amd64",                        1 },
  { "6.12.48+deb13-amd64",                   0 },
  { "6.12.90+deb13-amd64",                   1 },

  /* Upstream and stable */
  { "6.18.2",                                0 },
  { "6.6.50",                                1 },
  { "6.8.12",                                1 },
  { "6.8.0-rc1",                             1 },
  { "6.9.0",                                 0 },
  { "6.12.81",                               0 },
  { "6.12.82",                               1 },
  { "6.12.90-1-lts",                         1 },
  { "6.12",                                  0 },
  { "6.17.13",                               0 },
  { "6.18.22",                               0 },
  { "6.18.23",                               1 },
  { "6.19.12",                               0 },
  { "6.19.13",                               1 },
  { "7.1.0-rc1",                             1 },
  { "6.12.0-rc7",                            0 },
  { "7.0.0",                                 1 },
  { "7.0.0-rc7",                             0 },
  { "7.0.0-rc7-custom",                      0 },
  { "7.0.0-0.rc7.20260405git.fc45.x86_64",   0 },
  { "7.0.0-070000rc7-generic",               0 }, /* Ubuntu mainline */
  { "7.0.0-070000-generic",                  1 },
  { "6.12.82-061282-generic",                1 },
  { "6.19.0-061900rc7-generic",              0 },
  { "7.0.0-200.fc44.x86_64",                 1 },
  { "7.0.0-arch1-1",                         1 },
  { "7.0.14-300.fc44.x86_64",                1 },
  { "7.1",                                   1 },
  { "8.0.0",                                 1 },

  /* Unparseable */
  { "",                                      0 },
  { "unknown",                               0 },
  { "7",                                     0 },
  { "7.",                                    0 },
  { " 7.0.0",                                0 },
  { "99999999999999999999.0.0",              0 },
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    kernel_case_t const * c = &cases[ i ];
    int safe = fd_cpu_isolation_wq_safe( c->release );
    if( FD_UNLIKELY( safe!=c->safe ) )
      FD_LOG_ERR(( "release \"%s\": got %d expected %d", c->release, safe, c->safe ));
  }

  static fd_config_t config[1];
  strcpy( config->development.cpu_isolation.enabled, "false" );
  FD_TEST( !fd_cpu_isolation_enabled( config ) );
  strcpy( config->development.cpu_isolation.enabled, "true" );
  FD_TEST( fd_cpu_isolation_enabled( config ) );
  strcpy( config->development.cpu_isolation.enabled, "auto" );
  int a = fd_cpu_isolation_enabled( config );
  FD_TEST( fd_cpu_isolation_enabled( config )==a ); /* cached */
  FD_LOG_NOTICE(( "auto gate on this host: %s", a ? "enabled" : "disabled" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
