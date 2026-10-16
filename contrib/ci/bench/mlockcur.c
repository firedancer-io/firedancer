/* LD_PRELOAD: in bench's forked child (the tile process), fault in + lock every mapping (.bss, .data, heap, stacks) in address order before tiles spawn */
#include <pthread.h>
#include <sys/mman.h>
static void child( void ) { mlockall( MCL_CURRENT ); }
__attribute__((constructor)) static void init( void ) { pthread_atfork( NULL, NULL, child ); }
