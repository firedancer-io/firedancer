#ifndef HEADER_fd_src_app_frank_fd_frank_h
#define HEADER_fd_src_app_frank_fd_frank_h

/* FD_HAS_FRANK indicates whether or not the build target supports the
   fd_frank application. */

#define FD_HAS_FRANK FD_HAS_HOSTED && FD_HAS_ALLOCA && FD_HAS_X86

#include "../../disco/fd_disco.h"
#include "../../ballet/fd_ballet.h" /* FIXME: CONSIDER HAVING THIS IN DISCO_BASE */

/* FD_FRANK_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     {HA,SV}_FILT_{CNT,SZ} is frank specific and the number of times a
     transaction was dropped by a verify tile due to failing signature
     verification. */

#define FD_FRANK_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_FRANK_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_FRANK_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_FRANK_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_FRANK_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_FRANK_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

/* A fd_replay_tile will use the fseq and cnc application regions
   to accumulate flow control diagnostics in the standard ways.  It
   additionally will accumulate to the cnc application region the
   following tile specific counters:

     CHUNK_IDX     is the chunk idx where reply tile should start publishing payloads on boot (ignored if not valid on boot)
     PCAP_DONE     is cleared before the tile starts processing the pcap and is set when the pcap processing is done
     PCAP_PUB_CNT  is the number of pcap packets published by the replay
     PCAP_PUB_SZ   is the number of pcap packet payload bytes published by the replay
     PCAP_FILT_CNT is the number of pcap packets filtered by the replay
     PCAP_FILT_SZ  is the number of pcap packet payload bytes filtered by the replay

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at
   tile startup (as such that they can be accumulated over multiple
   runs).  Clearing is up to monitoring scripts. */
#define FD_FRANK_REPLAY_CNC_DIAG_CHUNK_IDX     (6UL) /* On 1st cache line of app region, updated by producer, frequently */
#define FD_FRANK_REPLAY_CNC_DIAG_PCAP_DONE     (7UL) /* ", rarely */
#define FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_CNT  (8UL) /* ", frequently */
#define FD_FRANK_REPLAY_CNC_DIAG_PCAP_PUB_SZ   (9UL) /* ", frequently */
#define FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_CNT (10UL) /* ", frequently */
#define FD_FRANK_REPLAY_CNC_DIAG_PCAP_FILT_SZ  (11UL) /* ", frequently */

#define FD_FRANK_PARSER_CNC_DIAG_PUB_CNT  (6UL) /* ", frequently */

FD_PROTOTYPES_BEGIN

/* fd_frank_{verify,dedup,pack}_task is a fd_tile_task_t compatible
   function whose task is to run a {verify,dedup,pack} tile.  argc is
   ignored, argv[0] points to a cstr with the tile name (for a verify,
   this is also used to find the specific verify configuration in the
   frank instance's configuration), argv[1] points to a cstr with the
   gaddr of the pod containing the frank instance's configuration and
   argv[2] points to a cstr with the path to the frank instance's
   configuration.  The lifetime of these cstr should be longer than the
   tile execution.  The argv array used to pass these cstr will not be
   used after the tile has successfully booted.  Aborts the thread group
   on error.  Returns 0 on success and non-zero on failure (logs
   details, given abortive behavior, only reason for a failure return is
   build target is without FD_HAS_FRANK). */

int
fd_frank_verify_task( int     argc,
                      char ** argv );

int
fd_frank_dedup_task( int     argc,
                     char ** argv );

int
fd_frank_pack_task( int     argc,
                    char ** argv );

int
fd_frank_quic_task( int     argc,
                    char ** argv );

int
fd_frank_replay_task( int     argc,
                      char ** argv );

int
fd_frank_parser_task( int     argc,
                      char ** argv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_frank_fd_frank_h */

