/* temp test code */

#include <stdio.h>
#include <string.h>

#define FD_LOG_UNPACK(...) __VA_ARGS__
#define FD_LOG_WARNING(STR) \
  do {                                                 \
    char buf[768] = {};                                \
    snprintf( buf, sizeof(buf)-1, FD_LOG_UNPACK STR ); \
    fprintf( stderr, "%s\n", buf );                    \
    fflush( stderr );                                  \
  } while(0)

#define FD_LOG_ERROR(...) FD_LOG_WARNING(__VA_ARGS__)
#define FD_LOG_ERR(...)   FD_LOG_WARNING(__VA_ARGS__)
