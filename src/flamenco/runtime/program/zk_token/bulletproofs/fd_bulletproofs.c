#include "fd_bulletproofs.h"
#include "../merlin/fd_merlin.h"

void
fd_bulletproofs_placeholder( FD_FN_UNUSED void * placeholder ) {
  fd_merlin_transcript_t transcript[1];
  fd_merlin_transcript_init( transcript, "placeholder" );
}
