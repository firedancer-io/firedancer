#ifndef HEADER_fd_src_ballet_shred_fd_shred_h
#define HEADER_fd_src_ballet_shred_fd_shred_h

#include "../bmtree/fd_bmtree.h"

/* Shreds form the on-wire representation of Solana block data
   optimized for transmission over unreliable links/WAN.

   ### Layout

   Each shred is 1228 bytes long.

      +------------------------+
      | Common Shred Header    | 83 bytes
      +------------------------+
      | Data Header            | 5 bytes
      | or Coding Header       | or 6 bytes
      +------------------------+
      |                        | variable
      | Payload                | length
      |                        |
      +------------------------+

       for Merkle shreds, followed by:

      +------------------------+
      | (Chained merkle root)  | 32 bytes
      +------------------------+
      +------------------------+
      | Merkle node #0 (root)  | 20 bytes
      +------------------------+
      | Merkle node #1         | 20 bytes
      ..........................

       for resigned shreds, followed by:

      +------------------------+
      | signature              | 64 bytes
      ..........................

   ### Shredding

   For a given input data blob (usually an entry batch),
   data shreds are derived by simply splitting up the blob into subslices.

   Each shred is sized such that it fits into a single UDP packet,
   i.e. currently bound by the generally accepted IPv6 MTU of 1280 bytes.

   ### Forward Error Correction

   Coding shreds implement Reed-Solomon error correction to provide tolerance against packet loss.

   Each data shred is first assigned an FEC set.
   For the vector of data shreds in each set, a corresponding vector of coding shreds contains parity data.

   FEC sets and entry batches do not necessarily align.

   ### Merkle Inclusion Proofs

   Data and coding shreds come in two variants respectively: legacy and merkle.
   Merkle shreds extend legacy shreds by adding FEC set inclusion proofs.

   It allows the block producer to commit to the vector of shreds that make up an FEC set.
   The inclusion proof is used to verify whether a shred is part of the FEC set commitment.

   The length of the inclusion proof is indicated by the variant field.

   ### resigned shreds

   Resigned shreds allow for an additional signature to be added on to lock down
   the retransmitter for turbine propagation

   ### Authentication

   Shreds are signed by the block producer.
   Consequentially, only the block producer is able to create valid shreds for any given block. */

#include "../fd_ballet.h"

/* FD_SHRED_MAX_SZ: The max byte size of a shred.
   This limit derives from the IPv6 MTU of 1280 bytes, minus 48 bytes
   for the UDP/IPv6 headers and another 4 bytes for good measure.  Most
   shreds are this size, but Merkle data shreds may be smaller. */
#define FD_SHRED_MAX_SZ (1228UL)
/* FD_SHRED_MIN_SZ: The minimum byte size of a shred.
   A code shred of the max size covers a data shred of the minimum size
   with no padding. */
#define FD_SHRED_MIN_SZ (1203UL)
/* FD_SHRED_DATA_HEADER_SZ: size of all headers for data type shreds. */
#define FD_SHRED_DATA_HEADER_SZ (0x58UL)
/* FD_SHRED_CODE_HEADER_SZ: size of all headers for coding type shreds. */
#define FD_SHRED_CODE_HEADER_SZ (0x59UL)
/* This is a conservative bound.
   It's possible for a modified validator to create a data shred with
   this much payload.
   A validator that follows the default shredding policy should have
   payloads of no more than 1015 bytes.
   In general, shreds that are chained or resigned should have smaller
   payloads and a tigher bound. */
#define FD_SHRED_DATA_PAYLOAD_MAX (FD_SHRED_MIN_SZ-FD_SHRED_DATA_HEADER_SZ)

/* FD_SHRED_TYPE_* identifies the type of a shred.
   It is located at the four high bits of byte 0x40 (64) of the shred header
   and can be extracted using the fd_shred_type() function. */
/* FD_SHRED_TYPE_LEGACY_DATA: A shred carrying raw binary data. */
#define FD_SHRED_TYPE_LEGACY_DATA ((uchar)0xA0)
/* FD_SHRED_TYPE_LEGACY_CODE: A shred carrying Reed-Solomon ECC. */
#define FD_SHRED_TYPE_LEGACY_CODE ((uchar)0x50)
/* FD_SHRED_TYPE_MERKLE_DATA: A shred carrying raw binary data and a merkle inclusion proof. */
#define FD_SHRED_TYPE_MERKLE_DATA ((uchar)0x80)
/* FD_SHRED_TYPE_MERKLE_CODE: A shred carrying Reed-Solomon ECC and a merkle inclusion proof. */
#define FD_SHRED_TYPE_MERKLE_CODE ((uchar)0x40)
/* FD_SHRED_TYPE_MERKLE_DATA_CHAINED: A shred carrying raw binary data and a chained merkle inclusion proof. */
#define FD_SHRED_TYPE_MERKLE_DATA_CHAINED ((uchar)0x90)
/* FD_SHRED_TYPE_MERKLE_CODE_CHAINED: A shred carrying Reed-Solomon ECC and a chained merkle inclusion proof. */
#define FD_SHRED_TYPE_MERKLE_CODE_CHAINED ((uchar)0x60)

/* FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED: A shred carrying raw binary data and a chained merkle inclusion proof and resigned. */
#define FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ((uchar)0xB0)
/* FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED: A shred carrying Reed-Solomon ECC and a chained merkle inclusion proof and resigned. */
#define FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED ((uchar)0x70)

/* FD_SHRED_TYPEMASK_DATA: bitwise AND with type matches data shred */
#define FD_SHRED_TYPEMASK_DATA FD_SHRED_TYPE_MERKLE_DATA
/* FD_SHRED_TYPEMASK_CODE: bitwise AND with type matches code shred */
#define FD_SHRED_TYPEMASK_CODE FD_SHRED_TYPE_MERKLE_CODE

/* FD_SHRED_MERKLE_ROOT_SZ: the size of a merkle tree root in bytes. */
#define FD_SHRED_MERKLE_ROOT_SZ (32UL)
/* FD_SHRED_MERKLE_NODE_SZ: the size of a merkle inclusion proof node in bytes. */
#define FD_SHRED_MERKLE_NODE_SZ (20UL)
/* FD_SHRED_MERKLE_LAYER_CNT: the count of inclusion proof layers in the binary merkle tree. */
#define FD_SHRED_MERKLE_LAYER_CNT (10UL)
/* FD_SHRED_SIGNATURE_SZ: the size of a signature in a shred. */
#define FD_SHRED_SIGNATURE_SZ (64UL)
/* A merkle inclusion proof node. */
typedef uchar fd_shred_merkle_t[FD_SHRED_MERKLE_NODE_SZ];

FD_STATIC_ASSERT( sizeof(fd_bmtree_node_t) == FD_SHRED_MERKLE_ROOT_SZ, update FD_SHRED_MERKLE_ROOT_SZ );

/* Constants relating to the data shred "flags" field. */

/* Mask of the "reference tick"    field in shred.data.flags */
#define FD_SHRED_DATA_REF_TICK_MASK      ((uchar)0x3f)
/* Mask of the "slot complete"       bit in shred.data.flags
   Indicates the last shred in a slot. */
#define FD_SHRED_DATA_FLAG_SLOT_COMPLETE ((uchar)0x80)
/* Mask of the "data batch complete" bit in shred.data.flags */
#define FD_SHRED_DATA_FLAG_DATA_COMPLETE ((uchar)0x40)

/* Maximum number of data shreds in a slot, also maximum number of parity shreds in a slot */
#define FD_SHRED_BLK_MAX (1 << 15UL) /* 32,768 shreds */
#define FD_SHRED_IDX_MAX (FD_SHRED_BLK_MAX - 1)

/* Many static bounds are specified around the assumption that this is a
   protocol limit on the max number of shreds in a slot. If this limit
   changes, all the relevant usages in other areas of the Firedancer
   codebase should be updated before modifying this assertion. */

FD_STATIC_ASSERT( FD_SHRED_BLK_MAX == 32768, check all usages before changing this limit! );

/* Many static bounds are specified around the assumption that this is a
   protocol limit on the max number of shreds in a slot. If this limit
   changes, all the relevant usages in other areas of the Firedancer
   codebase should be updated before modifying this assertion. */

FD_STATIC_ASSERT( FD_SHRED_BLK_MAX == 32768, check all usages before changing this limit! );

/* 36,536,320 bytes per slot */
#define FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT (FD_SHRED_DATA_PAYLOAD_MAX * FD_SHRED_BLK_MAX)

/* 32,856 bytes per slot */
#define FD_SHRED_DATA_HEADER_MAX_PER_SLOT (FD_SHRED_DATA_HEADER_SZ * FD_SHRED_BLK_MAX)

/* Offset of the shred variant. Used for parsing. */
#define FD_SHRED_VARIANT_OFF 0x40

/* Firedancer-specific internal error codes.

   These are not part of the Solana protocol. */

#define FD_SHRED_EBATCH  0x4000 /* End of batch reached (success)
                                   no more shreds and found FD_SHRED_DATA_FLAG_DATA_COMPLETE */
#define FD_SHRED_ESLOT   0x8000 /* End of slot reached (success)
                                   no more shreds and found FD_SHRED_DATA_FLAG_SLOT_COMPLETE */
#define FD_SHRED_ENOMEM      12 /* Error: Target buffer too small */
#define FD_SHRED_EINVAL      22 /* Error: Invalid shred data */
#define FD_SHRED_EPIPE       32 /* Error: Expected data in source buffer, got EOF */

/* Primary shred data structure.
   Relies heavily on packed fields and unaligned memory accesses. */
struct __attribute__((packed)) fd_shred {
  /* Ed25519 signature over the shred

     For legacy type shreds, signs over content of the shred structure past this signature field.
     For merkle type shreds, signs over the first node of the inclusion proof (merkle root). */
  /* 0x00 */ fd_ed25519_sig_t signature;

  /* Shred variant specifier
     Consists of two four bit fields. (Deliberately not using bit fields here)

     The high four bits indicate the shred type:
     - 0101: legacy code
     - 1010: legacy data
     - 0100: merkle code
     - 0110: merkle code (chained)
     - 0111: merkle code (chained resigned)
     - 1000: merkle data
     - 1001: merkle data (chained)
     - 1011: merkle data (chained resigned)

     For legacy type shreds, the low four bits are set to static patterns.
     For merkle type shreds, the low four bits are set to the number of non-root nodes in the inclusion proof.
     For merkle code type shreds, the 3rd highest bit represents if the merkle tree is chained.
     For merkle data type shreds, the 4th highest bit represents if the merkle tree is chained.
     For merkle code type shreds, the 4th highest bit represents if the shred is resigned.
     For merkle data type shreds, the 3th highest bit represents if the shred is resigned.
*/
  /* 0x40 */ uchar  variant;

  /* Slot number that this shred is part of */
  /* 0x41 */ ulong  slot;

  /* Index of this shred within the slot */
  /* 0x49 */ uint   idx;

  /* Hash of the genesis version and historical hard forks of the current chain */
  /* 0x4d */ ushort version;

  /* Index into the vector of FEC sets for this slot. For data shreds, fec_set_idx<=idx. */
  /* 0x4f */ uint   fec_set_idx;

  union {
    /* Common data shred header */
    struct __attribute__((packed)) {
      /* Slot number difference between this block and the parent block.
         parent_off <= slot.
         Always greater than zero, except for slot 0, in which case the
         previous invariant forces this to be 0. */
      /* 0x53 */ ushort parent_off;

      /* Bit field (MSB first)
         See FD_SHRED_DATA_FLAG_*

          [XX.. ....] Block complete?       0b00=no 0b01=no 0b11=yes (implies Entry batch complete)
          [.X.. ....] Entry batch complete?  0b0=no  0b1=yes
          [..XX XXXX] Reference tick number */
      /* 0x55 */ uchar  flags;

      /* Shred size: size of data shred headers (88 bytes) + payload length */
      /* 0x56 */ ushort size;
    } data;

    /* Common coding shred header */
    struct __attribute__((packed)) {
      /* Total number of data shreds in FEC set. Must be positive <= FD_REEDSOL_DATA_SHREDS_MAX. */
      /* 0x53 */ ushort data_cnt;

      /* Total number of coding shreds in FEC set. Must be positive <= FD_REEDSOL_CODE_SHREDS_MAX. */
      /* 0x55 */ ushort code_cnt;

      /* Index within the vector of coding shreds in slot. In [0,
         code_cnt).  Also, shred.code.idx <= shred.idx. */
      /* 0x57 */ ushort idx;
    } code;
  };
};
typedef struct fd_shred fd_shred_t;

FD_PROTOTYPES_BEGIN

/* fd_shred_parse: Parses and validates an untrusted shred stored in
   bytes buf[i] for i in [0, sz).  sz must be at least FD_SHRED_MIN_SZ
   bytes.  Allows trailing data.

   The returned pointer either equals the input pointer or is NULL if
   the given shred is malformed or violates any invariants described
   above. */
FD_FN_PURE fd_shred_t const *
fd_shred_parse( uchar const * buf,
                ulong         sz );

/* fd_shred_type: Returns the value of the shred's type field. (FD_SHRED_TYPE_*) */
FD_FN_CONST static inline uchar
fd_shred_type( uchar variant ) {
  return variant & 0xf0;
}

/* fd_shred_variant: Returns the encoded variant field
   given the shred type and merkle proof length. */
FD_FN_CONST static inline uchar
fd_shred_variant( uchar type,
                  uchar merkle_cnt ) {
  if( FD_LIKELY( type==FD_SHRED_TYPE_LEGACY_DATA ) )
    merkle_cnt = 0x05;
  if( FD_LIKELY( type==FD_SHRED_TYPE_LEGACY_CODE ) )
    merkle_cnt = 0x0a;
  return (uchar)(type | merkle_cnt);
}

FD_FN_PURE static inline ulong
fd_shred_sz( fd_shred_t const * shred ) {
  uchar type = fd_shred_type( shred->variant );
  return fd_ulong_if(
    type & FD_SHRED_TYPEMASK_CODE,
    FD_SHRED_MAX_SZ,
    fd_ulong_if( type==FD_SHRED_TYPE_LEGACY_DATA, shred->data.size, FD_SHRED_MIN_SZ)
  ); /* Legacy data */
}

/* fd_shred_header_sz: Returns the header size of a shred.
   Returns zero if the shred has an invalid variant.

   Accesses offsets up to FD_SHRED_HEADER_MIN_SZ. */
FD_FN_CONST static inline ulong
fd_shred_header_sz( uchar variant ) {
  uchar type = fd_shred_type( variant );
  if( FD_LIKELY( type & FD_SHRED_TYPEMASK_DATA ) )
    return FD_SHRED_DATA_HEADER_SZ;
  if( FD_LIKELY( type & FD_SHRED_TYPEMASK_CODE ) )
    return FD_SHRED_CODE_HEADER_SZ;
  return 0;
}

/* fd_shred_merkle_cnt: Returns number of nodes in the merkle inclusion
   proof.  Note that this excludes the root.  Returns zero if the given
   shred is not a merkle variant. */
FD_FN_CONST static inline uint
fd_shred_merkle_cnt( uchar variant ) {
  uchar type = fd_shred_type( variant );
  if( FD_UNLIKELY( ( type == FD_SHRED_TYPE_LEGACY_DATA ) | ( type == FD_SHRED_TYPE_LEGACY_CODE ) ) )
    return 0;
  return (variant&0xfU);
}

/* fd_shred_merkle_sz: Returns the size in bytes of the merkle inclusion proof.
   Returns zero if the given shred is not a merkle variant.  */
FD_FN_CONST static inline ulong
fd_shred_merkle_sz( uchar variant ) {
  return fd_shred_merkle_cnt( variant ) * FD_SHRED_MERKLE_NODE_SZ;
}


/* fd_shred_is_chained: Returns true if the shred is a chained merkle data or code shred. */
FD_FN_CONST static inline uchar
fd_shred_is_chained( ulong type ) {
  return (uchar)(
         ( type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED )
       | ( type == FD_SHRED_TYPE_MERKLE_CODE_CHAINED )
       | ( type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED )
       | ( type == FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED ) );
}

/* fd_shred_is_resigned: Returns true if the shred is resigned by the retransmitter */
FD_FN_CONST static inline uchar
fd_shred_is_resigned( ulong type ) {
  return ( type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED )
       | ( type == FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED );
}

/* fd_shred_is_{data,code} return 1 if the provided shred type is one of
   the data (or code, respectively) types, and 0 if not.  The value
   provided for type must be a valid shred type (one of the
   FD_SHRED_TYPE_* values).  For the purposes of these functions,
   properties beyond data/code are ignored; e.g. a chained resigned
   Merkle data shred is considered a data shred. */
FD_FN_CONST static inline uchar fd_shred_is_data( ulong type ) { return (type & 0xC0UL)==0x80UL; }
FD_FN_CONST static inline uchar fd_shred_is_code( ulong type ) { return (type & 0xC0UL)==0x40UL; }

/* fd_shred_swap_type: changes data into code or vice versa without
   affecting leagacy, merkle, chained, or resigned status.  For example,
   fd_shred_swap_type( chained resigned data ) == chained resigned code.
   fd_shred_swap_type( merkle code ) == merkle data. */
FD_FN_CONST static inline uchar
fd_shred_swap_type( ulong type ) {
  /* Swap bits 4 and 5. Swap bits 6 and 7. */
  return (uchar)(((type & 0x50UL)<<1) | ((type&0xA0UL)>>1));
}

/* fd_shred_payload_sz: Returns the payload size of a shred.
   Undefined behavior if the shred has not passed `fd_shred_parse`. */
FD_FN_PURE static inline ulong
fd_shred_payload_sz( fd_shred_t const * shred ) {
  ulong type = fd_shred_type( shred->variant );
  if( FD_LIKELY( type & FD_SHRED_TYPEMASK_DATA ) ) {
    return shred->data.size - FD_SHRED_DATA_HEADER_SZ;
  } else {
    return fd_shred_sz( shred ) - FD_SHRED_CODE_HEADER_SZ
      - fd_shred_merkle_sz( shred->variant )
      - fd_ulong_if( fd_shred_is_chained( type ), FD_SHRED_MERKLE_ROOT_SZ, 0 )
      - fd_ulong_if( fd_shred_is_resigned( type ), FD_SHRED_SIGNATURE_SZ, 0 );
  }
}

/* fd_shred_merkle_off: Returns the byte offset of the merkle inclusion proof of a shred.

   The provided shred must have passed validation in fd_shred_parse(). */
FD_FN_PURE static inline ulong
fd_shred_merkle_off( fd_shred_t const * shred ) {
  ulong type = fd_shred_type( shred->variant );
  return fd_shred_sz( shred )
    - fd_shred_merkle_sz( shred->variant )
    - fd_ulong_if( fd_shred_is_resigned( type ), FD_SHRED_SIGNATURE_SZ, 0 );
}

/* fd_shred_merkle_nodes: Returns a pointer to the shred's merkle proof data.

   The provided shred must have passed validation in fd_shred_parse(). */
FD_FN_PURE static inline fd_shred_merkle_t const *
fd_shred_merkle_nodes( fd_shred_t const * shred ) {
  uchar const * ptr = (uchar const *)shred;
  ptr += fd_shred_merkle_off( shred );
  return (fd_shred_merkle_t const *)ptr;
}

/* fd_shred_merkle_root: Assuming that `shred` is a Merkle variant,
   reconstructs the merkle root from a shred and populates it in
   root_out.  Returns 1 on success, 0 on failure.  The output value must
   be ignored if a failure is returned.  U.B. if the shred is not a
   merkle variant. */
FD_FN_PURE int
fd_shred_merkle_root( fd_shred_t const * shred, void * bmtree_mem, fd_bmtree_node_t * root_out );

/* fd_shred_data_payload: Returns a pointer to a data shred payload.

  The provided shred must have passed validation in fd_shred_parse(),
  and must satisfy `type&FD_SHRED_TYPEMASK_DATA`
  where `uchar type = fd_shred_type( shred->variant )`. */
FD_FN_CONST static inline uchar const *
fd_shred_data_payload( fd_shred_t const * shred ) {
  return (uchar const *)shred + FD_SHRED_DATA_HEADER_SZ;
}

/* fd_shred_code_payload: Returns a pointer to a coding shred payload.

  The provided shred must have passed validation in fd_shred_parse(),
  and must satisfy `type&FD_SHRED_TYPEMASK_CODE`
  where `uchar type = fd_shred_type( shred->variant )`. */
FD_FN_CONST static inline uchar const *
fd_shred_code_payload( fd_shred_t const * shred ) {
  return (uchar const *)shred + FD_SHRED_CODE_HEADER_SZ;
}

/* fd_shred_chain_offset: Assuming that `shred` is a chained Merkle
   variant, compute the offset from the start of the shred to the start
   of the chained Merkle root.  U.B. if the shred is not a chained
   variant. */
FD_FN_CONST static inline ulong
fd_shred_chain_off( uchar variant ) {
  ulong type = fd_shred_type( variant );
  return fd_ulong_if( type & FD_SHRED_TYPEMASK_CODE, FD_SHRED_MAX_SZ, FD_SHRED_MIN_SZ )
    - FD_SHRED_MERKLE_ROOT_SZ
    - fd_shred_merkle_sz( variant )
    - fd_ulong_if( fd_shred_is_resigned( type ), FD_SHRED_SIGNATURE_SZ, 0 );
}

/* fd_shred_retrasmitter_sig_off: Assuming that `shred` is a resigned
   variant, compute the offset from the start of the shred to the start
   of the retransmitter signature.  U.B if the shred is not a resigned
   chained type. */
FD_FN_PURE static inline ulong
fd_shred_retransmitter_sig_off( fd_shred_t const * shred ) {
  return fd_shred_sz( shred )-FD_SHRED_SIGNATURE_SZ;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_shred_fd_shred_h */
