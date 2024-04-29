#ifndef HEADER_fd_src_test_consensus_h
#define HEADER_fd_src_test_consensus_h

#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>

#include "../keyguard/fd_keyguard_client.h"

#include "../../choreo/fd_choreo.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../shred/fd_shred_cap.h"
#include "../tvu/fd_replay.h"

struct fd_tvu_gossip_deliver_arg {
  fd_repair_t * repair;
  fd_bft_t * bft;
  fd_valloc_t valloc;
};
typedef struct fd_tvu_gossip_deliver_arg fd_tvu_gossip_deliver_arg_t;

/* functions for fd_gossip_config_t */
static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg );

static void
gossip_send_packet( uchar const *                 data,
                    size_t                        sz,
                    fd_gossip_peer_addr_t const * addr,
                    void *                        arg );

static void
signer_fun( void *    arg,
            uchar         signature[ static 64 ],
            uchar const * buffer,
            ulong         len );

/* helper functions */
static int
gossip_to_sockaddr( uchar * dst, fd_gossip_peer_addr_t const * src );

static fd_repair_peer_addr_t *
resolve_hostport( const char * str /* host:port */, fd_repair_peer_addr_t * res );

#endif
