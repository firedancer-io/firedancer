/* This files contains a canary that is expected to be found by the canary finder.
   If the script fails to find this canary, it will consider this a failure. 
   
   This is not a unit test but a canary. */

#include "fd_fuzz.h"

static void
do_not_call_me( void ) {
    FD_FUZZ_MUST_BE_COVERED;
}
