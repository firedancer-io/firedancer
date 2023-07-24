#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_proto_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_proto_h

#include "../fd_flamenco_base.h"

/* fd_solcap provides APIs for Solana runtime capture data.
   Byte order is little endian. */

/* TODO allow storing account data separately */

/* fd_solcap_fhdr is the file header of a capture file */

#define FD_SOLCAP_MAGIC (0x805fe7580b1da4b7UL)

struct fd_solcap_fhdr_v0 {
  ulong slot0;
  ulong slot_cnt;

  ulong bank_hash_off;
  ulong bank_preimage_off;
};

typedef struct fd_solcap_fhdr_v0 fd_solcap_fhdr_v0_t;

struct fd_solcap_fhdr {
  ulong magic;    /* ==FD_SOLCAP_MAGIC */
  ulong version;  /* ==0UL */
  ulong total_sz;

  union {
    fd_solcap_fhdr_v0_t v0;
  };
};

typedef struct fd_solcap_fhdr fd_solcap_fhdr_t;

struct fd_solcap_bank_hash {
  uchar hash[ 32 ];
};

typedef struct fd_solcap_bank_hash fd_solcap_bank_hash_t;

/* Convert this to Protobuf */

struct fd_solcap_bank_preimage {
  /* 0x00 */ uchar prev_bank_hash[ 32 ];
  /* 0x20 */ uchar account_delta_hash[ 32 ];
  /* 0x40 */ uchar poh_hash[ 32 ];
  /* 0x60 */ ulong signature_cnt;

  /* 0x68 */ ulong account_cnt;
  /* 0x70 */ ulong account_off;
  /* 0x78 */ uchar skipped_slot;
  /* 0x79 */ uchar _pad78[ 7 ];
  /* 0x80 */
};

typedef struct fd_solcap_bank_preimage fd_solcap_bank_preimage_t;

struct fd_solcap_account {
  /* 0x00 */ ulong footprint;
  /* 0x08 */ ulong lamports;
  /* 0x10 */ ulong slot;
  /* 0x18 */ ulong rent_epoch;

  /* 0x20 */ uchar key  [ 32 ];
  /* 0x40 */ uchar owner[ 32 ];
  /* 0x60 */ uchar hash [ 32 ];

  /* 0x80 */ char  executable;
  /* 0x81 */ uchar _pad61[7];

  /* 0x88 */
  /* Variable-length data follows */
};

typedef struct fd_solcap_account fd_solcap_account_t;

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_proto_h */
