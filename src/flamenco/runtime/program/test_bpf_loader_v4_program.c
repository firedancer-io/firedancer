#include "fd_bpf_loader_v4_program.h"
#include "../../fd_flamenco.h"


FD_STATIC_ASSERT( offsetof( fd_bpf_loader_v4_state_t, slot           )==0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_bpf_loader_v4_state_t, authority_addr )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_bpf_loader_v4_state_t, status         )==0x28UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_bpf_loader_v4_state_t                 )==0x30UL, layout );


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* More tests can be added here ... */

  FD_LOG_NOTICE(( "pass" ));
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
