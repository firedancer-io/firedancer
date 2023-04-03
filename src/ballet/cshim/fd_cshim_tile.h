#ifndef HEADER_fd_src_ballet_cshim_fd_cshim_tile_h
#define HEADER_fd_src_ballet_cshim_fd_cshim_tile_h

#include "../../disco/fd_disco.h"
#include "../../ballet/pack/fd_pack.h"
#include "../../ballet/fd_ballet.h"

#if FD_HAS_HOSTED && FD_HAS_ALLOCA && FD_HAS_X86

FD_PROTOTYPES_BEGIN

/* fd_cshim_pack_return: sends the output the pack tile to a shim.

   argv[0]: File descriptor no. of shim ctl
   argv[1]: File descriptor no. of shim msg
   argv[2]: Pod address `wkspname:wkspoffset`
   argv[3]: cfg pod name */
int
fd_cshim_pack_return( int     argc,
                      char ** argv );

/* fd_cshim_verify_feeder: feeds the sigverify tiles with untrusted txs.

   argv[0]: File descriptor no. of shim ctl
   argv[1]: File descriptor no. of shim msg
   argv[2]: wkspname:wkspoffset
   argv[3]: cfg pod name
   argv[4]: verifyin sub pod name 1
   argv[5]: verifyin sub pod name 2
   ...
   argv[k]: verifyin sub pod name k-2 */
int
fd_cshim_verify_feeder( int argc, char **  argv );

FD_PROTOTYPES_END

#endif /* FD_HAS_FRANK */

#endif /* HEADER_fd_src_ballet_cshim_fd_cshim_tile_h */
