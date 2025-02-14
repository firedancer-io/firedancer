#include <linux/if_link.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include "fd_gossip.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <dirent.h>

#define MY_SMAX (1UL << 17) // 128KB
#define MY_DEPTH 64UL
uchar smem[ MY_SMAX ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
ulong fmem[ MY_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

const char * read_path = "/home/rsivakumaran/scratch/gossip/gossip_epoch_msg_dump";

/* Add peer entrypoint.testnet.solana.com */
fd_gossip_peer_addr_t testnet_entrypt_addr = {
    .addr = 0x23cbaa1e, /* 35.203.170.30 */
    .port = __builtin_bswap16( 8001 ), /* big endian! */
    .pad = 0
};

typedef struct{
    int generate_keypair;
} gossip_bench_args_t;

void
deliver_fun( fd_crds_data_t* data, void* arg ) {
    (void)data;
    (void)arg;
}

void
send_packet_fun( uchar const * data, size_t sz, fd_gossip_peer_addr_t const * addr, void * arg ) {
    (void)data;
    (void)sz;
    (void)addr;
    (void)arg;
    static uint cnt = 0;
    char filename[100];
    sprintf(filename, "/home/rsivakumaran/scratch/gossip/fd/epoch_pull_reqs/%u.bin", cnt++);
    FILE * file = fopen(filename, "wb");
    if ( file ) {
        fwrite( data, 1, sz, file );
        fclose( file );
    }
}

static uchar            private_key[32] = {0};
static fd_pubkey_t      public_key  = {0};
static fd_sha512_t      sha512 = {0};

static void
gossip_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ){
  (void)signer_ctx;

  switch (sign_type) {
    case FD_KEYGUARD_SIGN_TYPE_ED25519:
      fd_ed25519_sign(signature, buffer, len, public_key.uc, private_key, &sha512);
      break;
    case FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519:
      {
        uchar hash[32];
        fd_sha256_hash(buffer, len, hash);
        fd_ed25519_sign(signature, hash, 32UL, public_key.uc, private_key, &sha512);
      }
      break;
    default:
      FD_LOG_ERR(("unexpected sign type"));
  }
}

void
setup_gossip_config( fd_gossip_config_t * config, gossip_bench_args_t * args FD_PARAM_UNUSED ) {

    fd_sha512_join( fd_sha512_new( &sha512 ) );

    FD_TEST( 32UL==getrandom( private_key, 32UL, 0 ) );
    FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, &sha512 ) );

    config->private_key = private_key;
    config->public_key  = &public_key;

    config->my_addr.l = 0;
    config->my_version = (fd_gossip_version_v2_t){0};

    config->shred_version = 64475U;

    config->deliver_fun = deliver_fun;
    config->deliver_arg = NULL;
    config->send_fun    = send_packet_fun;
    config->send_arg    = NULL;
    config->sign_fun    = gossip_signer;
    config->sign_arg    = NULL;
}

void
populate_crds( fd_gossip_t * glob ){
    DIR * dir;
    struct dirent * ent;

    dir = opendir( read_path );
    if (dir == NULL) {
        perror("opendir");
        return;
    }

    uint set_wallclock = 0;

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            printf("%s\n", ent->d_name);
            char fullpath[1024];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", read_path, ent->d_name);

            FILE *file = fopen(fullpath, "rb");
            if (file == NULL) {
                perror("fopen");
                continue;
            }
            uchar buf[1232];
            size_t bytes_read = fread(buf, 1, sizeof(buf), file);

            /* We need to extract wallclock and set the glob->now so that these CRDS values
               don't get filtered due to time expiry. This */
            if ( !set_wallclock ) {
                fd_gossip_msg_t gmsg;
                fd_bincode_decode_ctx_t ctx;
                ctx.data    = buf;
                ctx.dataend = buf + bytes_read;
                ctx.valloc = fd_libc_alloc_virtual();
                fd_gossip_msg_decode( &gmsg, &ctx );

                fd_crds_value_t * crd = gmsg.discriminant == fd_gossip_msg_enum_push_msg ? gmsg.inner.push_msg.crds : gmsg.inner.pull_resp.crds;
                ulong wallclock = 0UL;
                switch (crd->data.discriminant) {
                case fd_crds_data_enum_contact_info_v1:
                    wallclock = crd->data.inner.contact_info_v1.wallclock;
                    break;
                case fd_crds_data_enum_vote:
                    wallclock = crd->data.inner.vote.wallclock;
                    break;
                case fd_crds_data_enum_lowest_slot:
                    wallclock = crd->data.inner.lowest_slot.wallclock;
                    break;
                case fd_crds_data_enum_snapshot_hashes:
                    wallclock = crd->data.inner.snapshot_hashes.wallclock;
                    break;
                case fd_crds_data_enum_accounts_hashes:
                    wallclock = crd->data.inner.accounts_hashes.wallclock;
                    break;
                case fd_crds_data_enum_epoch_slots:
                    wallclock = crd->data.inner.epoch_slots.wallclock;
                    break;
                case fd_crds_data_enum_version_v1:
                    wallclock = crd->data.inner.version_v1.wallclock;
                    break;
                case fd_crds_data_enum_version_v2:
                    wallclock = crd->data.inner.version_v2.wallclock;
                    break;
                case fd_crds_data_enum_node_instance:
                    wallclock = crd->data.inner.node_instance.wallclock;
                    break;
                case fd_crds_data_enum_duplicate_shred:
                    wallclock = crd->data.inner.duplicate_shred.wallclock;
                    break;
                case fd_crds_data_enum_incremental_snapshot_hashes:
                    wallclock = crd->data.inner.incremental_snapshot_hashes.wallclock;
                    break;
                case fd_crds_data_enum_contact_info_v2:
                    wallclock = crd->data.inner.contact_info_v2.wallclock;
                    break;
                case fd_crds_data_enum_restart_last_voted_fork_slots:
                    wallclock = crd->data.inner.restart_last_voted_fork_slots.wallclock;
                    break;
                case fd_crds_data_enum_restart_heaviest_fork:
                    wallclock = crd->data.inner.restart_heaviest_fork.wallclock;
                    break;
                }
                fd_gossip_settime( glob, (long)wallclock );
                set_wallclock = 1;
            }

            fd_gossip_recv_packet( glob, buf, bytes_read, &testnet_entrypt_addr );
        }
    }
}


int
main( int argc, char **argv ) {
    (void)argc;
    (void)argv;

    fd_scratch_attach( smem, fmem, MY_SMAX, MY_DEPTH );
    fd_scratch_push();
    fd_valloc_t valloc = fd_libc_alloc_virtual();

    gossip_bench_args_t args;
    // parse_args( &argc, &argv, &args );


    fd_gossip_config_t gconfig;
    fd_memset(&gconfig, 0, sizeof(gconfig));
    setup_gossip_config( &gconfig, &args );

    void * gmem = fd_valloc_malloc( valloc, fd_gossip_align(), fd_gossip_footprint() );
    fd_gossip_t * glob = fd_gossip_join( fd_gossip_new( gmem, 0UL ) );

    if( fd_gossip_set_config( glob, &gconfig ) )
        return -1;


    fd_gossip_add_active_peer( glob, &testnet_entrypt_addr );

    /* Populate value table with some CRDS values */
    populate_crds( glob );

    /* Invoke random pull, which should send packets via send_packet_fun */
    fd_gossip_random_pull( glob, NULL );

    fd_valloc_free(valloc, fd_gossip_delete(fd_gossip_leave(glob)));
    fd_scratch_pop();
    return 0;
}
