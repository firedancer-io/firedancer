#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rocksdb/c.h>
#include <zstd.h>

#define IF_IDX_NET      (0U)
#define IF_IDX_SHREDCAP (1U)
#define SHRED_PORT      (8003U)

#define SHRED_MAX_SZ              (1228UL)
#define SHRED_MIN_SZ              (1203UL)
#define SHRED_DATA_HEADER_SZ      (0x58UL)
#define SHRED_CODE_HEADER_SZ      (0x59UL)
#define SHRED_TYPE_LEGACY_DATA    ((uint8_t)0xa0)
#define SHRED_TYPE_LEGACY_CODE    ((uint8_t)0x50)
#define SHRED_TYPE_MERKLE_DATA    ((uint8_t)0x80)
#define SHRED_TYPE_MERKLE_CODE    ((uint8_t)0x40)
#define SHRED_TYPE_MERKLE_DATA_CHAINED          ((uint8_t)0x90)
#define SHRED_TYPE_MERKLE_CODE_CHAINED          ((uint8_t)0x60)
#define SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ((uint8_t)0xb0)
#define SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED ((uint8_t)0x70)
#define SHRED_TYPEMASK_DATA       SHRED_TYPE_MERKLE_DATA
#define SHRED_TYPEMASK_CODE       SHRED_TYPE_MERKLE_CODE
#define SHRED_MERKLE_NODE_SZ      (20UL)
#define SHRED_MERKLE_ROOT_SZ      (32UL)
#define SHRED_SIGNATURE_SZ        (64UL)
#define SHRED_BLK_MAX             (1UL << 15UL)

#define SHREDCAP_IFNAME                  "shredcap0"
#define SHREDCAP_TYPE_BANK_HASH_V0       (0x1U)
#define SHREDCAP_TYPE_ROOT_SLOT_V0       (0x2U)

#define PCAPNG_BLOCK_SZ                  (32768UL)
#define PCAPNG_BLOCK_TYPE_SHB            (0x0a0d0d0aU)
#define PCAPNG_BLOCK_TYPE_IDB            (0x00000001U)
#define PCAPNG_BLOCK_TYPE_EPB            (0x00000006U)
#define PCAPNG_BYTE_ORDER_MAGIC          (0x1a2b3c4dU)
#define PCAPNG_LINKTYPE_USER0            (147U)
#define PCAPNG_LINKTYPE_IPV4             (228U)
#define PCAPNG_SHB_OPT_USERAPPL          ((uint16_t)4)
#define PCAPNG_IDB_OPT_NAME              ((uint16_t)2)
#define PCAPNG_IDB_OPT_IPV4_ADDR         ((uint16_t)4)
#define PCAPNG_IDB_OPT_TSRESOL           ((uint16_t)9)
#define PCAPNG_TSRESOL_NS                ((uint8_t)0x09)

#define CF_IDX_DEFAULT    0
#define CF_IDX_CODE_SHRED 1
#define CF_IDX_DATA_SHRED 2
#define CF_IDX_ROOT       3
#define CF_IDX_BANK_HASH  4
#define CF_IDX_DEAD_SLOT  5
#define CF_CNT            6

struct __attribute__((packed)) shred {
  uint8_t  signature[64];
  uint8_t  variant;
  uint64_t  slot;
  uint32_t   idx;
  uint16_t version;
  uint32_t   fec_set_idx;
  union {
    struct __attribute__((packed)) {
      uint16_t parent_off;
      uint8_t  flags;
      uint16_t size;
    } data;
    struct __attribute__((packed)) {
      uint16_t data_cnt;
      uint16_t code_cnt;
      uint16_t idx;
    } code;
  };
};

struct __attribute__((packed)) shredcap_bank_hash_v0 {
  uint64_t slot;
  uint8_t bank_hash[32];
  uint64_t data_shred_cnt;
};

struct __attribute__((packed)) shredcap_root_slot_v0 {
  uint64_t slot;
};

struct rocksdb_src {
  rocksdb_t * db;
  rocksdb_readoptions_t * ro;
  rocksdb_column_family_handle_t * code_shred_cf;
  rocksdb_column_family_handle_t * data_shred_cf;
  rocksdb_column_family_handle_t * root_cf;
  rocksdb_column_family_handle_t * bank_hash_cf;
  rocksdb_column_family_handle_t * dead_slot_cf;
  rocksdb_column_family_handle_t ** all_cfs;
  size_t all_cf_cnt;
  rocksdb_iterator_t * code_shred_iter;
  rocksdb_iterator_t * data_shred_iter;
  rocksdb_iterator_t * root_iter;
  int code_iter_done;
  int data_iter_done;
  int code_slot_done;
  int data_slot_done;
  uint64_t current_slot;
};

struct slot_info {
  uint64_t slot;
  uint8_t bank_hash[32];
  int   bank_hash_set;
  int   rooted;
  int   dead;
};

struct pcap_writer {
  FILE * file;
  ZSTD_CStream * zstd;
  void * zstd_buf;
  size_t zstd_buf_sz;
  uint64_t bytes;
};

static void
die( char const * msg ) {
  fprintf( stderr, "error: %s\n", msg );
  exit( 1 );
}

static void
die_errno( char const * msg,
           char const * path ) {
  fprintf( stderr, "error: %s %s (%d-%s)\n", msg, path, errno, strerror( errno ) );
  exit( 1 );
}

static int
usage( int rc ) {
  fputs(
    "\n"
    "Usage: blockstore2shredcap --rocksdb <path> --out <path> [--zstd]\n"
    "\n"
    "Extract rooted blocks from Agave RocksDB.\n"
    "Produces shredcap 0.1 (pcapng) file containing shreds and bank hashes.\n"
    "\n"
    "  --rocksdb    <path>  Agave RocksDB directory\n"
    "  --out        <path>  File path to new shredcap file (fails if file already exists)\n"
    "  --start-slot <n>     Start slot (inclusive)\n"
    "  --end-slot   <n>     End slot (inclusive)\n"
    "  --zstd               Compress output with zstd\n"
    "\n",
    stderr
  );
  return rc;
}

static uint64_t
min_uint64( uint64_t a,
            uint64_t b ) {
  return a < b ? a : b;
}

static uint64_t
align4( uint64_t x ) {
  return (x + 3UL) & ~3UL;
}

static uint64_t
load_uint64( void const * p ) {
  uint64_t x;
  memcpy( &x, p, sizeof(x) );
  return x;
}

static uint16_t
ip_checksum( uint8_t const * buf,
             uint64_t         sz ) {
  uint32_t sum = 0U;
  for( uint64_t i=0UL; i+1UL<sz; i+=2UL ) sum += (uint32_t)((buf[i] << 8) | buf[i+1UL]);
  if( sz & 1UL ) sum += (uint32_t)(buf[sz-1UL] << 8);
  while( sum >> 16 ) sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)~sum;
}

static uint8_t
shred_type( uint8_t variant ) {
  return (uint8_t)(variant & 0xf0U);
}

static int
shred_is_chained( uint64_t type ) {
  return type==SHRED_TYPE_MERKLE_DATA_CHAINED ||
         type==SHRED_TYPE_MERKLE_CODE_CHAINED ||
         type==SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ||
         type==SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED;
}

static int
shred_is_resigned( uint64_t type ) {
  return type==SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ||
         type==SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED;
}

static uint64_t
shred_header_sz( uint8_t variant ) {
  uint8_t type = shred_type( variant );
  if( type & SHRED_TYPEMASK_DATA ) return SHRED_DATA_HEADER_SZ;
  if( type & SHRED_TYPEMASK_CODE ) return SHRED_CODE_HEADER_SZ;
  return 0UL;
}

static uint32_t
shred_merkle_cnt( uint8_t variant ) {
  uint8_t type = shred_type( variant );
  if( type==SHRED_TYPE_LEGACY_DATA || type==SHRED_TYPE_LEGACY_CODE ) return 0U;
  return (uint32_t)(variant & 0x0fU);
}

static uint64_t
shred_merkle_sz( uint8_t variant ) {
  return (uint64_t)shred_merkle_cnt( variant ) * SHRED_MERKLE_NODE_SZ;
}

static struct shred const *
shred_parse( uint8_t const * buf,
             uint64_t         sz ) {
  if( sz < min_uint64( SHRED_DATA_HEADER_SZ, SHRED_CODE_HEADER_SZ ) ) return NULL;

  struct shred const * shred = (struct shred const *)buf;
  uint8_t variant = shred->variant;
  uint8_t type = shred_type( variant );
  if( type!=SHRED_TYPE_MERKLE_DATA &&
      type!=SHRED_TYPE_MERKLE_CODE &&
      type!=SHRED_TYPE_MERKLE_DATA_CHAINED &&
      type!=SHRED_TYPE_MERKLE_CODE_CHAINED &&
      type!=SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED &&
      type!=SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED &&
      variant!=0xa5U &&
      variant!=0x5aU ) return NULL;

  uint64_t header_sz  = shred_header_sz( variant );
  uint64_t trailer_sz = shred_merkle_sz( variant ) +
                     (shred_is_resigned( type ) ? SHRED_SIGNATURE_SZ : 0UL) +
                     (shred_is_chained ( type ) ? SHRED_MERKLE_ROOT_SZ : 0UL);
  uint64_t payload_sz;
  uint64_t zero_padding_sz;

  if( type & SHRED_TYPEMASK_DATA ) {
    if( shred->data.size < header_sz ) return NULL;
    payload_sz = (uint64_t)shred->data.size - header_sz;
    if( type!=SHRED_TYPE_LEGACY_DATA && sz<SHRED_MIN_SZ ) return NULL;
    uint64_t effective_sz = type==SHRED_TYPE_LEGACY_DATA ? sz : SHRED_MIN_SZ;
    if( effective_sz < header_sz + payload_sz + trailer_sz ) return NULL;
    zero_padding_sz = effective_sz - header_sz - payload_sz - trailer_sz;
  } else if( type & SHRED_TYPEMASK_CODE ) {
    zero_padding_sz = 0UL;
    if( header_sz + trailer_sz > SHRED_MAX_SZ ) return NULL;
    payload_sz = SHRED_MAX_SZ - header_sz - trailer_sz;
  } else {
    return NULL;
  }

  if( sz < header_sz + payload_sz + zero_padding_sz + trailer_sz ) return NULL;

  if( type & SHRED_TYPEMASK_DATA ) {
    uint64_t parent_off = (uint64_t)shred->data.parent_off;
    uint64_t slot       = shred->slot;
    if( (shred->data.flags & 0xc0U)==0x80U ) return NULL;
    if( parent_off > slot ) return NULL;
    if( ((slot!=0UL) && (parent_off==0UL)) || ((slot>1UL) && (parent_off==slot)) ) return NULL;
    if( shred->idx < shred->fec_set_idx ) return NULL;
    if( shred->idx >= SHRED_BLK_MAX ) return NULL;
  } else {
    if( shred->code.idx >= shred->code.code_cnt ) return NULL;
    if( shred->code.idx > shred->idx ) return NULL;
    if( !shred->code.data_cnt || !shred->code.code_cnt ) return NULL;
    if( shred->code.code_cnt > 256U ) return NULL;
    if( (uint64_t)shred->code.data_cnt + (uint64_t)shred->code.code_cnt > 256UL ) return NULL;
    if( shred->idx >= SHRED_BLK_MAX ) return NULL;
    if( (uint64_t)shred->fec_set_idx + (uint64_t)shred->code.data_cnt - 1UL >= SHRED_BLK_MAX ) return NULL;
    if( (uint64_t)(shred->idx - shred->code.idx) + (uint64_t)shred->code.code_cnt - 1UL >= SHRED_BLK_MAX ) return NULL;
  }

  return shred;
}

static uint64_t
shred_sz( struct shred const * shred ) {
  uint8_t type = shred_type( shred->variant );
  if( type & SHRED_TYPEMASK_CODE ) return SHRED_MAX_SZ;
  if( type==SHRED_TYPE_LEGACY_DATA ) return shred->data.size;
  return SHRED_MIN_SZ;
}

static void
write_file_bytes( FILE *      file,
                  void const * data,
                  size_t       sz ) {
  if( sz && fwrite( data, sz, 1UL, file )!=1UL ) die( "pcapng write failed" );
}

static void
write_bytes( struct pcap_writer * writer,
             void const *         data,
             uint64_t             sz ) {
  if( !sz ) return;
  writer->bytes += sz;
  if( !writer->zstd ) {
    write_file_bytes( writer->file, data, (size_t)sz );
    return;
  }

  ZSTD_inBuffer input = { data, (size_t)sz, 0UL };
  while( input.pos < input.size ) {
    ZSTD_outBuffer output = { writer->zstd_buf, writer->zstd_buf_sz, 0UL };
    size_t zstd_res = ZSTD_compressStream2( writer->zstd, &output, &input, ZSTD_e_continue );
    if( ZSTD_isError( zstd_res ) ) {
      fprintf( stderr, "error: zstd compression failed: %s\n", ZSTD_getErrorName( zstd_res ) );
      exit( 1 );
    }
    write_file_bytes( writer->file, writer->zstd_buf, output.pos );
  }
}

static void
pcap_writer_finish( struct pcap_writer * writer ) {
  if( !writer->zstd ) return;
  for(;;) {
    ZSTD_outBuffer output = { writer->zstd_buf, writer->zstd_buf_sz, 0UL };
    size_t zstd_res = ZSTD_compressStream2( writer->zstd, &output, &(ZSTD_inBuffer){0}, ZSTD_e_end );
    if( ZSTD_isError( zstd_res ) ) {
      fprintf( stderr, "error: zstd finish failed: %s\n", ZSTD_getErrorName( zstd_res ) );
      exit( 1 );
    }
    write_file_bytes( writer->file, writer->zstd_buf, output.pos );
    if( zstd_res==0UL ) break;
  }
}

static void
pcapng_write_opt( uint8_t *      buf,
                  uint64_t *      cursor,
                  uint16_t       type,
                  void const * value,
                  uint64_t        sz ) {
  uint64_t sz_align = align4( sz );
  if( *cursor + 4UL + sz_align > PCAPNG_BLOCK_SZ ) die( "oversized pcapng block" );
  memcpy( buf + *cursor, &type, sizeof(type) );
  *cursor += 2UL;
  uint16_t sz16 = (uint16_t)sz;
  memcpy( buf + *cursor, &sz16, sizeof(sz16) );
  *cursor += 2UL;
  if( sz ) memcpy( buf + *cursor, value, sz );
  memset( buf + *cursor + sz, 0, sz_align - sz );
  *cursor += sz_align;
}

static void
pcapng_end_opts( uint8_t * buf,
                 uint64_t * cursor ) {
  if( *cursor + 4UL > PCAPNG_BLOCK_SZ ) die( "oversized pcapng block" );
  memset( buf + *cursor, 0, 4UL );
  *cursor += 4UL;
}

static void
pcapng_write_shb( struct pcap_writer * writer ) {
  uint8_t buf[PCAPNG_BLOCK_SZ];
  memset( buf, 0, sizeof(buf) );

  uint32_t block_type = PCAPNG_BLOCK_TYPE_SHB;
  uint32_t magic      = PCAPNG_BYTE_ORDER_MAGIC;
  uint16_t major    = 1U;
  uint16_t minor    = 0U;
  uint64_t section_sz = UINT64_MAX;
  uint64_t cursor = 0UL;
  memcpy( buf + cursor, &block_type, 4UL ); cursor += 4UL;
  cursor += 4UL; /* block size */
  memcpy( buf + cursor, &magic,      4UL ); cursor += 4UL;
  memcpy( buf + cursor, &major,      2UL ); cursor += 2UL;
  memcpy( buf + cursor, &minor,      2UL ); cursor += 2UL;
  memcpy( buf + cursor, &section_sz, 8UL ); cursor += 8UL;

  char const userappl[] = "blockstore2shredcap";
  pcapng_write_opt( buf, &cursor, PCAPNG_SHB_OPT_USERAPPL, userappl, strlen( userappl ) );
  pcapng_end_opts( buf, &cursor );

  uint32_t block_sz = (uint32_t)(cursor + 4UL);
  memcpy( buf + 4UL, &block_sz, 4UL );
  memcpy( buf + cursor, &block_sz, 4UL );
  cursor += 4UL;
  write_bytes( writer, buf, cursor );
}

static void
pcapng_write_idb( struct pcap_writer * writer,
                  uint32_t             link_type,
                  char const *         name,
                  uint8_t const        ip4_addr[4] ) {
  uint8_t buf[PCAPNG_BLOCK_SZ];
  memset( buf, 0, sizeof(buf) );

  uint32_t block_type = PCAPNG_BLOCK_TYPE_IDB;
  uint16_t link_type16 = (uint16_t)link_type;
  uint32_t snap_len = 0U;
  uint64_t cursor = 0UL;
  memcpy( buf + cursor, &block_type, 4UL ); cursor += 4UL;
  cursor += 4UL; /* block size */
  memcpy( buf + cursor, &link_type16, 2UL ); cursor += 2UL;
  cursor += 2UL; /* reserved */
  memcpy( buf + cursor, &snap_len, 4UL ); cursor += 4UL;

  uint8_t tsresol = PCAPNG_TSRESOL_NS;
  pcapng_write_opt( buf, &cursor, PCAPNG_IDB_OPT_TSRESOL, &tsresol, 1UL );
  if( name && name[0] ) pcapng_write_opt( buf, &cursor, PCAPNG_IDB_OPT_NAME, name, strnlen( name, 16UL ) );
  if( ip4_addr && (ip4_addr[0] || ip4_addr[1] || ip4_addr[2] || ip4_addr[3]) )
    pcapng_write_opt( buf, &cursor, PCAPNG_IDB_OPT_IPV4_ADDR, ip4_addr, 4UL );
  pcapng_end_opts( buf, &cursor );

  uint32_t block_sz = (uint32_t)(cursor + 4UL);
  memcpy( buf + 4UL, &block_sz, 4UL );
  memcpy( buf + cursor, &block_sz, 4UL );
  cursor += 4UL;
  write_bytes( writer, buf, cursor );
}

static void
pcapng_write_epb( struct pcap_writer * writer,
                  void const *         payload,
                  uint64_t             payload_sz,
                  void const *         options,
                  uint64_t             options_sz,
                  uint32_t             if_idx ) {
  uint32_t block_type = PCAPNG_BLOCK_TYPE_EPB;
  uint32_t block_sz   = (uint32_t)(28UL + align4( payload_sz ) + options_sz + 4UL + 4UL);
  uint32_t zero       = 0U;
  uint32_t cap_len    = (uint32_t)payload_sz;
  uint8_t pad[4]    = {0};

  write_bytes( writer, &block_type, 4UL );
  write_bytes( writer, &block_sz,   4UL );
  write_bytes( writer, &if_idx,     4UL );
  write_bytes( writer, &zero,       4UL );
  write_bytes( writer, &zero,       4UL );
  write_bytes( writer, &cap_len,    4UL );
  write_bytes( writer, &cap_len,    4UL );
  write_bytes( writer, payload, payload_sz );
  write_bytes( writer, pad, align4( payload_sz ) - payload_sz );
  write_bytes( writer, options, options_sz );
  write_bytes( writer, pad, 4UL );
  write_bytes( writer, &block_sz, 4UL );
}

static void
write_bank_hash( struct pcap_writer * pcap,
                 uint64_t             slot,
                 uint64_t             shred_cnt,
                 uint8_t const        bank_hash[32] ) {
  struct __attribute__((packed)) {
    uint32_t type;
    struct shredcap_bank_hash_v0 bank_hash_rec;
  } packet;
  memset( &packet, 0, sizeof(packet) );
  packet.type = SHREDCAP_TYPE_BANK_HASH_V0;
  packet.bank_hash_rec.slot = slot;
  packet.bank_hash_rec.data_shred_cnt = shred_cnt;
  memcpy( packet.bank_hash_rec.bank_hash, bank_hash, 32UL );
  pcapng_write_epb( pcap, &packet, sizeof(packet), NULL, 0UL, IF_IDX_SHREDCAP );
}

static void
write_rooted_slot( struct pcap_writer * pcap,
                   uint64_t             slot ) {
  struct __attribute__((packed)) {
    uint32_t type;
    struct shredcap_root_slot_v0 root_slot_rec;
  } packet;
  memset( &packet, 0, sizeof(packet) );
  packet.type = SHREDCAP_TYPE_ROOT_SLOT_V0;
  packet.root_slot_rec.slot = slot;
  pcapng_write_epb( pcap, &packet, sizeof(packet), NULL, 0UL, IF_IDX_SHREDCAP );
}

static void
write_shred( struct pcap_writer * pcap,
             void const *         raw_shred,
             uint64_t             raw_shred_sz ) {
  uint8_t packet[20UL + 8UL + SHRED_MAX_SZ];
  memset( packet, 0, sizeof(packet) );

  uint16_t ip_tot_len = htons( (uint16_t)(20UL + 8UL + raw_shred_sz) );
  uint16_t ip_frag    = htons( (uint16_t)0x4000U );
  packet[0] = 0x45U;
  memcpy( packet + 2UL, &ip_tot_len, 2UL );
  memcpy( packet + 6UL, &ip_frag,    2UL );
  packet[8]  = 64U;
  packet[9]  = 17U;
  packet[12] = 127U;
  packet[15] = 1U;
  packet[16] = 127U;
  packet[19] = 1U;
  uint16_t csum = ip_checksum( packet, 20UL );
  uint16_t net_csum = htons( csum );
  memcpy( packet + 10UL, &net_csum, 2UL );

  uint16_t sport = htons( 42424U );
  uint16_t dport = htons( SHRED_PORT );
  uint16_t udp_len = htons( (uint16_t)(8UL + raw_shred_sz) );
  memcpy( packet + 20UL, &sport,   2UL );
  memcpy( packet + 22UL, &dport,   2UL );
  memcpy( packet + 24UL, &udp_len, 2UL );
  memcpy( packet + 28UL, raw_shred, raw_shred_sz );

  struct __attribute__((packed)) {
    uint16_t option_type;
    uint16_t option_sz;
    uint32_t   pen;
    uint16_t magic;
    uint16_t gossip_tag;
  } option = {
    .option_type = 2989U,
    .option_sz   = 8U,
    .pen         = 31592U,
    .magic       = 0x4071U,
    .gossip_tag  = 10U
  };

  pcapng_write_epb( pcap, packet, 28UL + raw_shred_sz, &option, sizeof(option), IF_IDX_NET );
}

static void
make_slot_key( uint64_t slot,
               char  key[8] ) {
  uint64_t be = htobe64( slot );
  memcpy( key, &be, sizeof(be) );
}

static uint64_t
iter_cur_slot( rocksdb_iterator_t * iter ) {
  size_t key_sz = 0UL;
  char const * key = rocksdb_iter_key( iter, &key_sz );
  if( !key || key_sz < sizeof(uint64_t) ) die( "corrupt RocksDB: invalid iterator key" );
  return be64toh( load_uint64( key ) );
}

static struct rocksdb_src *
rocksdb_src_create( char const * path ) {
  static char const * cf_names[CF_CNT] = {
    [CF_IDX_DEFAULT]    = "default",
    [CF_IDX_CODE_SHRED] = "code_shred",
    [CF_IDX_DATA_SHRED] = "data_shred",
    [CF_IDX_ROOT]       = "root",
    [CF_IDX_BANK_HASH]  = "bank_hashes",
    [CF_IDX_DEAD_SLOT]  = "dead_slots"
  };

  rocksdb_options_t * options = rocksdb_options_create();
  if( !options ) die( "rocksdb_options_create failed" );

  char * err = NULL;
  size_t all_cf_cnt = 0UL;
  char ** all_cf_names = rocksdb_list_column_families( options, path, &all_cf_cnt, &err );
  if( !all_cf_names ) {
    fprintf( stderr, "warning: rocksdb_list_column_families failed: %s\n", err ? err : "(unknown)" );
    rocksdb_free( err );
    rocksdb_options_destroy( options );
    return NULL;
  }

  rocksdb_options_t const ** cf_options = calloc( all_cf_cnt, sizeof(rocksdb_options_t const *) );
  rocksdb_column_family_handle_t ** cfs = calloc( all_cf_cnt, sizeof(rocksdb_column_family_handle_t *) );
  if( !cf_options || !cfs ) die( "out of memory" );
  for( size_t i=0UL; i<all_cf_cnt; i++ ) cf_options[i] = options;

  rocksdb_t * db = rocksdb_open_for_read_only_column_families(
      options,
      path,
      (int)all_cf_cnt,
      (char const * const *)all_cf_names,
      cf_options,
      cfs,
      0,
      &err );
  rocksdb_options_destroy( options );
  free( cf_options );

  if( !db ) {
    fprintf( stderr, "warning: rocksdb_open_for_read_only_column_families failed: %s\n", err ? err : "(unknown)" );
    rocksdb_free( err );
    rocksdb_list_column_families_destroy( all_cf_names, all_cf_cnt );
    free( cfs );
    return NULL;
  }

  rocksdb_column_family_handle_t * named[CF_CNT] = {0};
  for( size_t i=0UL; i<all_cf_cnt; i++ ) {
    for( size_t j=0UL; j<CF_CNT; j++ ) {
      if( strcmp( all_cf_names[i], cf_names[j] )==0 ) named[j] = cfs[i];
    }
  }
  rocksdb_list_column_families_destroy( all_cf_names, all_cf_cnt );

  for( size_t j=0UL; j<CF_CNT; j++ ) {
    if( !named[j] ) {
      fprintf( stderr, "warning: column family \"%s\" not found in %s\n", cf_names[j], path );
      for( size_t i=0UL; i<all_cf_cnt; i++ ) if( cfs[i] ) rocksdb_column_family_handle_destroy( cfs[i] );
      free( cfs );
      rocksdb_close( db );
      return NULL;
    }
  }

  rocksdb_readoptions_t * ro = rocksdb_readoptions_create();
  if( !ro ) die( "rocksdb_readoptions_create failed" );

  struct rocksdb_src * src = calloc( 1UL, sizeof(struct rocksdb_src) );
  if( !src ) die( "out of memory" );

  rocksdb_iterator_t * code_shred_iter = rocksdb_create_iterator_cf( db, ro, named[CF_IDX_CODE_SHRED] );
  rocksdb_iterator_t * data_shred_iter = rocksdb_create_iterator_cf( db, ro, named[CF_IDX_DATA_SHRED] );
  rocksdb_iterator_t * root_iter       = rocksdb_create_iterator_cf( db, ro, named[CF_IDX_ROOT] );
  if( !code_shred_iter || !data_shred_iter || !root_iter ) die( "rocksdb_create_iterator_cf failed" );

  rocksdb_iter_seek_to_first( code_shred_iter );
  rocksdb_iter_seek_to_first( data_shred_iter );
  rocksdb_iter_seek_to_first( root_iter );

  src->db = db;
  src->ro = ro;
  src->code_shred_cf = named[CF_IDX_CODE_SHRED];
  src->data_shred_cf = named[CF_IDX_DATA_SHRED];
  src->root_cf       = named[CF_IDX_ROOT];
  src->bank_hash_cf  = named[CF_IDX_BANK_HASH];
  src->dead_slot_cf  = named[CF_IDX_DEAD_SLOT];
  src->all_cfs = cfs;
  src->all_cf_cnt = all_cf_cnt;
  src->code_shred_iter = code_shred_iter;
  src->data_shred_iter = data_shred_iter;
  src->root_iter = root_iter;
  src->code_iter_done = 1;
  src->data_iter_done = 0;
  src->code_slot_done = 1;
  src->data_slot_done = 0;
  src->current_slot = UINT64_MAX;
  return src;
}

static void
rocksdb_src_destroy( struct rocksdb_src * src ) {
  if( !src ) return;
  rocksdb_iter_destroy( src->code_shred_iter );
  rocksdb_iter_destroy( src->data_shred_iter );
  rocksdb_iter_destroy( src->root_iter );
  for( size_t i=0UL; i<src->all_cf_cnt; i++ ) rocksdb_column_family_handle_destroy( src->all_cfs[i] );
  free( src->all_cfs );
  rocksdb_readoptions_destroy( src->ro );
  rocksdb_close( src->db );
  free( src );
}

static uint64_t
rocksdb_src_shred( struct rocksdb_src * src,
                   uint8_t *              buf,
                   uint64_t                buf_sz ) {
  for(;;) {
    if( src->current_slot==UINT64_MAX ) {
      if( !rocksdb_iter_valid( src->root_iter ) ) {
        src->data_iter_done = 1;
        src->code_iter_done = 1;
        return UINT64_MAX;
      }
      src->current_slot = iter_cur_slot( src->root_iter );
    }

    if( !src->data_slot_done ) {
      rocksdb_iterator_t * iter = src->data_shred_iter;
      if( !rocksdb_iter_valid( iter ) ) {
        src->data_slot_done = 1;
        src->data_iter_done = 1;
        continue;
      }
      uint64_t found_slot = iter_cur_slot( iter );
      if( found_slot > src->current_slot ) {
        src->data_slot_done = 1;
        continue;
      }
      if( found_slot < src->current_slot ) {
        char key[8];
        make_slot_key( src->current_slot, key );
        rocksdb_iter_seek( iter, key, sizeof(key) );
        continue;
      }
      size_t value_sz = 0UL;
      char const * value = rocksdb_iter_value( iter, &value_sz );
      uint64_t sz = min_uint64( (uint64_t)value_sz, buf_sz );
      memcpy( buf, value, sz );
      rocksdb_iter_next( iter );
      return sz;
    }

    if( !src->code_slot_done ) {
      rocksdb_iterator_t * iter = src->code_shred_iter;
      if( !rocksdb_iter_valid( iter ) ) {
        src->code_slot_done = 1;
        src->code_iter_done = 1;
        continue;
      }
      uint64_t found_slot = iter_cur_slot( iter );
      if( found_slot > src->current_slot ) {
        src->code_slot_done = 1;
        continue;
      }
      if( found_slot < src->current_slot ) {
        char key[8];
        make_slot_key( src->current_slot, key );
        rocksdb_iter_seek( iter, key, sizeof(key) );
        continue;
      }
      size_t value_sz = 0UL;
      char const * value = rocksdb_iter_value( iter, &value_sz );
      uint64_t sz = min_uint64( (uint64_t)value_sz, buf_sz );
      memcpy( buf, value, sz );
      rocksdb_iter_next( iter );
      return sz;
    }

    if( src->data_iter_done && src->code_iter_done ) return UINT64_MAX;
    if( src->current_slot!=UINT64_MAX ) {
      char key[8];
      make_slot_key( src->current_slot + 1UL, key );
      rocksdb_iter_seek( src->root_iter, key, sizeof(key) );
    }
    src->current_slot = UINT64_MAX;
    src->code_slot_done = 1;
    src->data_slot_done = 0;
  }
}

static struct slot_info *
rocksdb_src_slot_info( struct rocksdb_src * src,
                       struct slot_info *   out,
                       uint64_t                slot ) {
  char key[8];
  make_slot_key( slot, key );
  memset( out, 0, sizeof(*out) );
  out->slot = slot;

  char * err = NULL;
  size_t root_val_len = 0UL;
  char * root_val = rocksdb_get_cf( src->db, src->ro, src->root_cf, key, sizeof(key), &root_val_len, &err );
  if( err ) {
    fprintf( stderr, "error: rocksdb_get_cf(root) failed: %s\n", err );
    rocksdb_free( err );
    exit( 1 );
  }

  size_t bank_hash_len = 0UL;
  char * bank_hash_val = rocksdb_get_cf( src->db, src->ro, src->bank_hash_cf, key, sizeof(key), &bank_hash_len, &err );
  if( err ) {
    fprintf( stderr, "error: rocksdb_get_cf(bank_hashes) failed: %s\n", err );
    rocksdb_free( err );
    exit( 1 );
  }

  size_t dead_slot_len = 0UL;
  char * dead_slot_val = rocksdb_get_cf( src->db, src->ro, src->dead_slot_cf, key, sizeof(key), &dead_slot_len, &err );
  if( err ) {
    fprintf( stderr, "error: rocksdb_get_cf(dead_slots) failed: %s\n", err );
    rocksdb_free( err );
    exit( 1 );
  }

  if( bank_hash_val && bank_hash_len>=36UL ) {
    memcpy( out->bank_hash, bank_hash_val + 4UL, 32UL );
    out->bank_hash_set = 1;
  }
  if( root_val && root_val_len>=1UL ) out->rooted = !!root_val[0];
  if( dead_slot_val && dead_slot_len>=1UL ) out->dead = !!dead_slot_val[0];

  rocksdb_free( root_val );
  rocksdb_free( bank_hash_val );
  rocksdb_free( dead_slot_val );
  return out;
}

static void
maybe_write_bank_hash( struct pcap_writer * pcap,
                       struct rocksdb_src * src,
                       uint64_t               slot,
                       uint64_t               shred_cnt ) {
  struct slot_info info;
  rocksdb_src_slot_info( src, &info, slot );
  if( !info.bank_hash_set ) return;
  write_bank_hash( pcap, slot, shred_cnt, info.bank_hash );
  if( info.rooted ) write_rooted_slot( pcap, slot );
}

static int
parse_uint64_arg( char const * name,
                 char const * val,
                 uint64_t *      out ) {
  if( !val || !val[0] ) {
    fprintf( stderr, "error: %s requires a value\n", name );
    return -1;
  }
  errno = 0;
  char * end = NULL;
  unsigned long long x = strtoull( val, &end, 0 );
  if( errno || !end || *end ) {
    fprintf( stderr, "error: invalid %s value: %s\n", name, val );
    return -1;
  }
  *out = (uint64_t)x;
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  char const * rocksdb_path = NULL;
  char const * out_path = NULL;
  uint64_t start_slot = 0UL;
  uint64_t end_slot = UINT64_MAX;
  int zstd = 0;

  static struct option const opts[] = {
    { "help",       no_argument,       NULL, 'h' },
    { "rocksdb",    required_argument, NULL, 'r' },
    { "out",        required_argument, NULL, 'o' },
    { "o",          required_argument, NULL, 'o' },
    { "start-slot", required_argument, NULL, 's' },
    { "end-slot",   required_argument, NULL, 'e' },
    { "zstd",       no_argument,       NULL, 'z' },
    { NULL,         0,                 NULL,  0  }
  };

  opterr = 0;
  for(;;) {
    int opt = getopt_long( argc, argv, "ho:", opts, NULL );
    if( opt==-1 ) break;
    switch( opt ) {
    case 'h': return usage( 0 );
    case 'r': rocksdb_path = optarg; break;
    case 'o': out_path = optarg; break;
    case 'z': zstd = 1; break;
    case 's':
      if( parse_uint64_arg( "--start-slot", optarg, &start_slot ) ) return usage( 1 );
      break;
    case 'e':
      if( parse_uint64_arg( "--end-slot", optarg, &end_slot ) ) return usage( 1 );
      break;
    default:
      fprintf( stderr, "error: unknown or malformed argument: %s\n", argv[optind-1] );
      return usage( 1 );
    }
  }
  if( optind<argc ) {
    fprintf( stderr, "error: unexpected positional argument: %s\n", argv[optind] );
    return usage( 1 );
  }

  if( !rocksdb_path ) {
    fputs( "error: --rocksdb not specified\n", stderr );
    return usage( 1 );
  }
  if( !out_path ) {
    fputs( "error: --out not specified\n", stderr );
    return usage( 1 );
  }
  if( start_slot > end_slot ) die( "--start-slot is greater than --end-slot" );

  struct rocksdb_src * src = rocksdb_src_create( rocksdb_path );
  if( !src ) {
    fprintf( stderr, "error: failed to open RocksDB at %s\n", rocksdb_path );
    return 1;
  }

  int out_fd = open( out_path, O_WRONLY|O_CREAT|O_EXCL, 0644 );
  if( out_fd<0 ) die_errno( "failed to create file", out_path );
  FILE * out = fdopen( out_fd, "wb" );
  if( !out ) die_errno( "fdopen failed on", out_path );
  struct pcap_writer writer = { .file = out };
  if( zstd ) {
    writer.zstd = ZSTD_createCStream();
    if( !writer.zstd ) die( "ZSTD_createCStream failed" );
    size_t zstd_res = ZSTD_CCtx_setParameter( writer.zstd, ZSTD_c_compressionLevel, ZSTD_CLEVEL_DEFAULT );
    if( ZSTD_isError( zstd_res ) ) {
      fprintf( stderr, "error: zstd init failed: %s\n", ZSTD_getErrorName( zstd_res ) );
      return 1;
    }
    writer.zstd_buf_sz = ZSTD_CStreamOutSize();
    writer.zstd_buf = malloc( writer.zstd_buf_sz );
    if( !writer.zstd_buf ) die( "out of memory" );
  }

  pcapng_write_shb( &writer );
  uint8_t lo_ip4[4] = {127,0,0,1};
  pcapng_write_idb( &writer, PCAPNG_LINKTYPE_IPV4, "lo", lo_ip4 );
  pcapng_write_idb( &writer, PCAPNG_LINKTYPE_USER0, SHREDCAP_IFNAME, NULL );

  uint64_t slot_cnt = 0UL;
  uint64_t cur_slot = UINT64_MAX;
  uint64_t buf_cnt  = 0UL;
  uint8_t raw[SHRED_MAX_SZ];

  for(;;) {
    uint64_t sz = rocksdb_src_shred( src, raw, sizeof(raw) );
    if( sz==UINT64_MAX ) break;
    if( sz==0UL ) continue;

    struct shred const * shred = shred_parse( raw, sz );
    if( !shred ) {
      fputs( "warning: skipping unparseable shred\n", stderr );
      continue;
    }

    uint64_t slot = shred->slot;
    if( slot!=cur_slot ) {
      if( cur_slot!=UINT64_MAX && cur_slot>=start_slot && cur_slot<=end_slot && buf_cnt>0UL ) {
        maybe_write_bank_hash( &writer, src, cur_slot, buf_cnt );
        slot_cnt++;
      }
      cur_slot = slot;
      buf_cnt = 0UL;
    }

    if( slot>end_slot ) break;
    if( slot<start_slot ) continue;

    write_shred( &writer, raw, shred_sz( shred ) );
    buf_cnt++;
  }

  if( cur_slot!=UINT64_MAX && cur_slot>=start_slot && cur_slot<=end_slot && buf_cnt>0UL ) {
    maybe_write_bank_hash( &writer, src, cur_slot, buf_cnt );
    slot_cnt++;
  }

  pcap_writer_finish( &writer );
  fprintf( stderr, "%s: wrote %" PRIu64 " slots, %" PRIu64 " bytes%s\n", out_path, slot_cnt, writer.bytes, zstd ? " (zstd compressed)" : "" );

  rocksdb_src_destroy( src );
  if( writer.zstd ) ZSTD_freeCStream( writer.zstd );
  free( writer.zstd_buf );
  if( fclose( out ) ) die_errno( "fclose failed on", out_path );
  return 0;
}
