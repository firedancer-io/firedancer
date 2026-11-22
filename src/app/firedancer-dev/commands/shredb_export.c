/* The shredb-export command attaches to a running validator's Store
   and writes the rooted blocks held in its on-disk shred ring (shredb)
   to a shredcap (pcapng) file replayable by `firedancer-dev backtest`.
   Output layout matches contrib/blockstore/blockstore2shredcap.c. */

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/store/fd_store.h"
#include "../../../discof/backtest/fd_shredcap.h"
#include "../../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../../flamenco/gossip/fd_gossip_message.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_pcapng.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/pod/fd_pod.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IF_IDX_NET      (0)
#define IF_IDX_SHREDCAP (1)
#define SHRED_PORT      ((ushort)8003)

void
shredb_export_cmd_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  char const * out = fd_env_strip_cmdline_cstr( pargc, pargv, "--out", NULL, NULL );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "usage: shredb-export --out <path> [--start-slot <n>] [--end-slot <n>]" ));
  fd_cstr_ncpy( args->shredb_export.out, out, sizeof(args->shredb_export.out) );
  args->shredb_export.start_slot = fd_env_strip_cmdline_ulong( pargc, pargv, "--start-slot", NULL, 0UL       );
  args->shredb_export.end_slot   = fd_env_strip_cmdline_ulong( pargc, pargv, "--end-slot",   NULL, ULONG_MAX );
  if( FD_UNLIKELY( args->shredb_export.start_slot>args->shredb_export.end_slot ) )
    FD_LOG_ERR(( "--start-slot is greater than --end-slot" ));
}

static void
write_bank_hash( FILE *      pcap,
                 ulong       slot,
                 ulong       shred_cnt,
                 uchar const bank_hash[32] ) {
  struct __attribute__((packed)) {
    uint type;
    fd_shredcap_bank_hash_v0_t bank_hash_rec;
  } packet;
  memset( &packet, 0, sizeof(packet) );

  packet.type                         = FD_SHREDCAP_TYPE_BANK_HASH_V0;
  packet.bank_hash_rec.slot           = slot;
  packet.bank_hash_rec.data_shred_cnt = shred_cnt;
  memcpy( packet.bank_hash_rec.bank_hash, bank_hash, 32UL );

  if( FD_UNLIKELY( !fd_pcapng_fwrite_pkt1( pcap, &packet, sizeof(packet), NULL, 0UL, IF_IDX_SHREDCAP, 0L ) ) )
    FD_LOG_ERR(( "pcap write error (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
write_rooted_slot( FILE * pcap,
                   ulong  slot ) {
  struct __attribute__((packed)) {
    uint type;
    fd_shredcap_root_slot_v0_t root_slot_rec;
  } packet;
  memset( &packet, 0, sizeof(packet) );

  packet.type               = FD_SHREDCAP_TYPE_ROOT_SLOT_V0;
  packet.root_slot_rec.slot = slot;

  if( FD_UNLIKELY( !fd_pcapng_fwrite_pkt1( pcap, &packet, sizeof(packet), NULL, 0UL, IF_IDX_SHREDCAP, 0L ) ) )
    FD_LOG_ERR(( "pcap write error (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
write_shred( FILE *        pcap,
             uchar const * shred,
             ulong         shred_sz ) {
  FD_TEST( shred_sz<=FD_SHRED_MAX_SZ );

  struct __attribute__((packed)) {
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar shred[ FD_SHRED_MAX_SZ ];
  } packet;

  packet.ip4 = (fd_ip4_hdr_t) {
    .verihl       = FD_IP4_VERIHL( 4, 5 ),
    .tos          = 0,
    .net_tot_len  = fd_ushort_bswap( (ushort)( 28+shred_sz ) ),
    .net_id       = 0,
    .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
    .ttl          = 64,
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .check        = 0,
    .saddr        = FD_IP4_ADDR( 127,0,0,1 ),
    .daddr        = FD_IP4_ADDR( 127,0,0,1 ),
  };
  packet.ip4.check = fd_ip4_hdr_check_fast( &packet.ip4 );
  packet.udp = (fd_udp_hdr_t) {
    .net_sport = fd_ushort_bswap( 42424 ),
    .net_dport = fd_ushort_bswap( SHRED_PORT ),
    .net_len   = fd_ushort_bswap( (ushort)( 8+shred_sz ) ),
    .check     = 0,
  };
  fd_memcpy( packet.shred, shred, shred_sz );

  struct __attribute__((packed)) {
    ushort option_type;
    ushort option_sz;
    uint   pen;
    ushort magic;
    ushort gossip_tag;
  } option = {
    .option_type = 2989,   /* Custom Option containing binary octets, copyable */
    .option_sz   = 8,
    .pen         = 31592,  /* Jump Trading, LLC */
    .magic       = 0x4071, /* SOL! */
    .gossip_tag  = FD_GOSSIP_CONTACT_INFO_SOCKET_TVU
  };

  if( FD_UNLIKELY( !fd_pcapng_fwrite_pkt1( pcap, &packet, 28UL+shred_sz, &option, sizeof(option), IF_IDX_NET, 0L ) ) )
    FD_LOG_ERR(( "pcap write error (%i-%s)", errno, fd_io_strerror( errno ) ));
}

/* slot_complete returns 1 if shredb holds every data shred of slot,
   i.e. idx 0 up to a SLOT_COMPLETE shred.  Probes only touch the
   index, so this does not read shred payloads besides the last one. */

static int
slot_complete( fd_store_t const * store,
               int                disk_fd,
               ulong              slot ) {
  uchar buf[ FD_SHRED_MAX_SZ ];
  int sz = fd_store_disk_query_highest( store, disk_fd, slot, 0U, buf );
  if( FD_UNLIKELY( sz<=0 ) ) return 0;
  fd_shred_t const * last = fd_shred_parse( buf, (ulong)sz, FD_SHRED_BLK_MAX );
  if( FD_UNLIKELY( !last || !(last->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) ) ) return 0;
  for( uint idx=0U; idx<last->idx; idx++ ) {
    if( FD_UNLIKELY( !fd_store_disk_probe( store, slot, idx ) ) ) return 0;
  }
  return 1;
}

/* parent_slot returns the parent of slot according to its first shred,
   or ULONG_MAX if that shred is not in shredb. */

static ulong
parent_slot( fd_store_t const * store,
             int                disk_fd,
             ulong              slot ) {
  uchar buf[ FD_SHRED_MAX_SZ ];
  int sz = fd_store_disk_query( store, disk_fd, slot, 0U, buf );
  if( FD_UNLIKELY( sz<=0 ) ) return ULONG_MAX;
  fd_shred_t const * shred = fd_shred_parse( buf, (ulong)sz, FD_SHRED_BLK_MAX );
  if( FD_UNLIKELY( !shred || !fd_shred_is_data( fd_shred_type( shred->variant ) ) ||
                   shred->slot!=slot || !shred->data.parent_off ) ) return ULONG_MAX;
  return slot - shred->data.parent_off;
}

void
shredb_export_cmd_fn( args_t *   args,
                      config_t * config ) {
  fd_topo_t * topo = &config->topo;
  char const * out_path   = args->shredb_export.out;
  ulong        start_slot = args->shredb_export.start_slot;
  ulong        end_slot   = args->shredb_export.end_slot;

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  if( FD_UNLIKELY( store_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "store object not found in topology" ));
  fd_topo_join_workspace( topo, &topo->workspaces[ topo->objs[ store_obj_id ].wksp_id ],
                          FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_store_t const * store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  if( FD_UNLIKELY( !store ) ) FD_LOG_ERR(( "fd_store_join failed (is the validator running?)" ));
  if( FD_UNLIKELY( !fd_store_has_disk( store ) ) ) FD_LOG_ERR(( "shredb is disabled for this validator" ));

  int disk_fd = open( config->paths.shredb, O_RDONLY );
  if( FD_UNLIKELY( disk_fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", config->paths.shredb, errno, fd_io_strerror( errno ) ));

  /* Walk the rooted chain back from the Store root.  Stop at start_slot
     or at the first slot shredb does not fully hold. */

  ulong root = FD_VOLATILE_CONST( store->root );
  if( FD_UNLIKELY( !root ) ) FD_LOG_ERR(( "validator has not published a root yet" ));
  ulong hi = fd_ulong_min( end_slot, root );
  if( FD_UNLIKELY( hi<root ) ) {
    /* end_slot is not necessarily on the rooted chain, find the highest
       rooted ancestor at or below it. */
    ulong slot = root;
    while( slot>hi ) {
      slot = parent_slot( store, disk_fd, slot );
      if( FD_UNLIKELY( slot==ULONG_MAX ) ) FD_LOG_ERR(( "--end-slot %lu is older than shredb retains", end_slot ));
    }
    hi = slot;
  }

  ulong   slot_max = store->disk_max_slots;
  ulong * slots    = malloc( slot_max*sizeof(ulong) );
  if( FD_UNLIKELY( !slots ) ) FD_LOG_ERR(( "out of memory" ));
  ulong slot_cnt = 0UL;
  for( ulong slot=hi; slot!=ULONG_MAX && slot>=start_slot && slot_cnt<slot_max; ) {
    if( FD_UNLIKELY( !slot_complete( store, disk_fd, slot ) ) ) break;
    slots[ slot_cnt++ ] = slot;
    if( FD_UNLIKELY( !slot ) ) break;
    slot = parent_slot( store, disk_fd, slot );
  }
  if( FD_UNLIKELY( !slot_cnt ) ) FD_LOG_ERR(( "shredb holds no complete rooted slot in [%lu,%lu]", start_slot, hi ));
  if( FD_UNLIKELY( start_slot && slots[ slot_cnt-1UL ]>start_slot ) )
    FD_LOG_WARNING(( "shredb only holds rooted slots down to %lu, requested --start-slot %lu", slots[ slot_cnt-1UL ], start_slot ));

  int out_fd = open( out_path, O_WRONLY|O_CREAT|O_EXCL, 0644 );
  if( FD_UNLIKELY( out_fd<0 ) ) FD_LOG_ERR(( "failed to create file %s (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  FILE * out = fdopen( out_fd, "wb" );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "fdopen failed on %s (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));

  {
    fd_pcapng_shb_opts_t shb_opts;
    fd_pcapng_shb_defaults( &shb_opts );
    if( FD_UNLIKELY( !fd_pcapng_fwrite_shb( &shb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
  }
  {
    fd_pcapng_idb_opts_t idb_opts = {
      .name     = "lo",
      .ip4_addr = { 127,0,0,1 }
    };
    if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_IPV4, &idb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
  }
  {
    fd_pcapng_idb_opts_t idb_opts = {
      .name = FD_SHREDCAP_V0_IFNAME,
    };
    if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_USER0, &idb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
  }

  /* Alpenglow blocks carry their bank hash in the block footer, the
     last entry batch of the slot. */

  static uchar batch[ FD_BLOCK_MARKER_SER_MAX ];
  static fd_block_marker_t marker[1];

  ulong shred_cnt_tot = 0UL;
  ulong no_hash_cnt   = 0UL;
  for( ulong i=slot_cnt; i>0UL; i-- ) {
    ulong slot = slots[ i-1UL ];

    ulong     batch_sz      = 0UL;
    int       batch_invalid = 0;
    int       hash_set      = 0;
    fd_hash_t bank_hash;
    ulong     shred_cnt     = 0UL;
    for( uint idx=0U;; idx++ ) {
      uchar raw[ FD_SHRED_MAX_SZ ];
      int sz = fd_store_disk_query( store, disk_fd, slot, idx, raw );
      if( FD_UNLIKELY( sz<=0 ) ) FD_LOG_ERR(( "slot %lu shred %u was evicted during export (err %d), retry with a later --start-slot", slot, idx, sz ));
      fd_shred_t const * shred = fd_shred_parse( raw, (ulong)sz, FD_SHRED_BLK_MAX );
      if( FD_UNLIKELY( !shred || shred->slot!=slot || shred->idx!=idx ) ) FD_LOG_ERR(( "corrupt shred in shredb (slot %lu, idx %u)", slot, idx ));

      write_shred( out, raw, fd_shred_sz( shred ) );
      shred_cnt++;

      ulong payload_sz = fd_shred_payload_sz( shred );
      if( FD_LIKELY( !batch_invalid && batch_sz+payload_sz<=sizeof(batch) ) ) {
        fd_memcpy( batch+batch_sz, fd_shred_data_payload( shred ), payload_sz );
        batch_sz += payload_sz;
      } else {
        batch_invalid = 1; /* too big for a block marker */
      }
      if( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        if( !batch_invalid &&
            !fd_block_marker_de( marker, batch, batch_sz ) &&
            marker->kind==FD_BLOCK_MARKER_KIND_FOOTER ) {
          bank_hash = marker->footer.bank_hash;
          hash_set  = 1;
        }
        batch_sz      = 0UL;
        batch_invalid = 0;
      }

      if( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) break;
    }

    if( FD_LIKELY( hash_set ) ) {
      write_bank_hash( out, slot, shred_cnt, bank_hash.uc );
    } else {
      FD_LOG_WARNING(( "slot %lu has no block footer, backtest will not find a bank hash for it", slot ));
      no_hash_cnt++;
    }
    write_rooted_slot( out, slot );
    shred_cnt_tot += shred_cnt;
  }

  long off = ftell( out );
  if( FD_UNLIKELY( 0!=fclose( out ) ) )
    FD_LOG_ERR(( "fclose failed on %s (%i-%s), output file may be corrupt", out_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( disk_fd ) ) ) FD_LOG_WARNING(( "close(%s) failed (%i-%s)", config->paths.shredb, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "%s: wrote slots [%lu,%lu] (%lu slots, %lu shreds, %lu without bank hash), %ld bytes",
                  out_path, slots[ slot_cnt-1UL ], hi, slot_cnt, shred_cnt_tot, no_hash_cnt, off ));
  free( slots );
}

action_t fd_action_shredb_export = {
  .name           = "shredb-export",
  .args           = shredb_export_cmd_args,
  .fn             = shredb_export_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Export rooted blocks from a running validator's shredb to a backtest shredcap file",
};
