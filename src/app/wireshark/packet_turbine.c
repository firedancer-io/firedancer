/* packet-turbine.c
 * Routines for Solana Turbine protocol dissection
 * Copyright 2022 Firedancer Contributors <firedancer-devs [AT] jumptrading.com>
 *
 * Plugin for Wireshark - Network traffic analyzer
 *
 * SPDX-License-Identifier: Apache-2.0 */

/* Firedancer libraries */
#include "../../ballet/fd_ballet.h"
#include "../../util/fd_util_base.h"

/* Wireshark libraries */
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <wsutil/str_util.h>

/* This Wireshark plugin is part of Firedancer, a high-performance Solana node implementation.

   Firedancer uses the Bazel build system instead of CMake.
   This required some breaking changes in plugin bootstrapping,
   such as explicitly defining plugin default exported symbols.

   This plugin is only compatible with LP64 C language data model.
   Therefore, it will only run on Unix-like systems.
   Win64 is not supported (however, Cygwin64 is).

   Another notable difference is the use of unaligned memory accesses.
   This plugin only runs on architectures that support such, e.g. x86_64 and armv8.

   Refer to //src/util:fd_util_base.h for more info on target assumptions. */

/* Exported symbols expected by the plugin loader
   This is used to ensure that this plugin is compatible with the host Wireshark. */
WS_DLL_PUBLIC char const plugin_version[];
WS_DLL_PUBLIC int  const plugin_want_major;
WS_DLL_PUBLIC int  const plugin_want_minor;

/* plugin_register: Entrypoint called by plugin loader */
WS_DLL_PUBLIC void plugin_register(void);

/* Re-export constants from <ws_version.h> */
char const plugin_version[]  = "0.1.0";
int  const plugin_want_major = WIRESHARK_VERSION_MAJOR;
int  const plugin_want_minor = WIRESHARK_VERSION_MINOR;

/***************************************************************************************************
 *                                                                                                 *
 *                                     SOLANA TURBINE PROTOCOL                                     *
 *                        as of mainnet-beta epoch 385 (Solana Labs v1.13)                         *
 *                                                                                                 *
 ***************************************************************************************************

  Solana Turbine is the data availability layer of the Solana network.
  It is used to distribute ledger data within large peer-to-peer networks over WAN.

  The protocol defines two domains:
   - The *Ledger Domain* operates on **blocks**:
     Streams of transactions with sequentially-consistent ordering. Serialized to binary blobs.
   - The *Wire Domain* operates on **shreds**:
     Authenticated UDP packets supporting distribution over peer-to-peer networks.
     Forward error correction to account for packet loss.

  Both domains converge over the concept of entry batches (and consequentially, blocks):
  A vector of entry batches (ledger domain) can be expressed by a vector of shreds (wire domain).
  Detailed information can be found below.

  This plugin does not yet implement the packet reassembly algorithm
  required to recover ledger data from the wire domain.

  ### Wire Domain

  The wire domain primarily consists of **shreds**.
  For details, refer to //src/ballet:fd_shred.h

  For the purposes of packet analysis, we will ignore erasure coding shreds and focus on data shreds.

  Each shred is transmitted as a single UDP packet of at least 1228 bytes.
  IP fragmentation of shreds is rare in the wild, and is unsupported by the Firedancer implementation.
  If the shred size is smaller than the packet size, the rest is padded with zeros.

  A vector of data shreds is created by fragmenting a serialized entry batch.
  Data shreds do not overlap over multiple entry batches.

  Each data shred header contains the following fields of interest:

      FT_UINT16  shred.version            Identifier of the hard fork
      FT_UINT64  shred.slot               Slot number (local block identifier within a chain)
      FT_UINT16  shred.data.parent_off    Slot difference between current and parent block;
                                          Helps identify sort forks
      FT_UINT32  shred.index              Incrementing fragment number within block (starts at 0)
      FT_BOOLEAN shred.data.end_of_batch  Marks the last shred of an entry batch

  When deploying Solana Turbine over a globally dispersed set of peers, shreds will arrive out-of-order.
  Consequentially, the naive approach of joining shreds in order will not work.

  Reassembly requires identifying sequences of fragments.
  In Turbine's terminology: The batch that each data shred belongs to, and ordering within the batch.

  These sequences can also be described by the set of non-overlapping contiguous shred index ranges within a slot.
  Shreds do not specify an explicit sequence identifier, so we derive a virtual sequence key instead.

  Recall that the end of an entry batch is marked by a shred with the `shred.data.end_of_batch` bit set.
  To find the start of the entry batch, we look at the end of the immediate predecessor entry batch.
  Thus, recovering the bounds of an entry batch that ends in index `i` requires knowing all shreds in index range [0;i].

***************************************************************************************************/

/* SHRED_REASSEMBLY_MAX_IDX: Max permitted shred index for reassembly
   Reassembly attempts for shreds with indices above this value are skipped.

   This value controls the max memory consumption per slot.
   During reassembly, each slot occupies 16 bytes per shred.
   A Turbine stream of 1 Gbps requires about 50k shreds per slot. */
#define SHRED_REASSEMBLY_MAX_IDX (131072U)

/* SHRED_REASSEMBLY_MIN_BUF_CNT: Min item capacity of per-slot shred buffer */
#define SHRED_REASSEMBLY_MIN_BUF_CNT (128U)
_Static_assert( __builtin_popcount( SHRED_REASSEMBLY_MIN_BUF_CNT )==1, "must be 2^x" );

/* Handles: Protocols */
static int proto_turbine = -1;
/* Handles: Protocol subtree handles */
static int ett_shred = -1;
/* Handles: Common header fields */
static int hf_sig           = -1;
static int hf_type          = -1;
static int hf_merkle_len    = -1;
static int hf_slot          = -1;
static int hf_idx           = -1;
static int hf_shred_version = -1;
static int hf_fec_set_idx   = -1;
/* Handles: Data shred fields */
static int hf_data_parent_off   = -1;
static int hf_data_flags        = -1;
static int hf_data_ref_tick     = -1;
static int hf_data_end_of_batch = -1;
static int hf_data_end_of_slot  = -1;
static int hf_data_size         = -1;
static int hf_data_payload      = -1;
/* Handles: Coding shred fields */
static int hf_code_data_cnt = -1;
static int hf_code_code_cnt = -1;
static int hf_code_idx      = -1;
static int hf_code_payload  = -1;

/* shred_type_vals: Lookup table for shred types (shred.variant>>4) */
static value_string const shred_type_vals[] = {
  { FD_SHRED_TYPE_LEGACY_DATA, "Legacy Data" },
  { FD_SHRED_TYPE_LEGACY_CODE, "Legacy Code" },
  { FD_SHRED_TYPE_MERKLE_DATA, "Merkle Data" },
  { FD_SHRED_TYPE_MERKLE_CODE, "Merkle Code" },
  { 0, NULL }
};

/* proto_register_turbine: Register protocols, element trees, items */
void
proto_register_turbine(void) {
  /* Header fields */
  static hf_register_info hf[] = {
    /* p_id                                 name                                       abbrev                              type         display    strings               bitmask blurb ...     */
    { &hf_sig,                            { "Signature",                               "shred.signature",                  FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_type,                           { "Type",                                    "shred.type",                       FT_UINT8,    BASE_HEX,  VALS(shred_type_vals),  0xF0, NULL, HFILL } },
    { &hf_merkle_len,                     { "Merkle Proof Len",                        "shred.merkle_len",                 FT_UINT8,    BASE_HEX,  NULL,                   0x0F, NULL, HFILL } },
    { &hf_slot,                           { "Slot",                                    "shred.slot",                       FT_UINT64,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_idx,                            { "Index",                                   "shred.index",                      FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_shred_version,                  { "Shred Version",                           "shred.version",                    FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_fec_set_idx,                    { "FEC Set Index",                           "shred.fec_set_idx",                FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },

    { &hf_data_parent_off,                { "Parent Slot Offset",                      "shred.data.parent_off",            FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_flags,                     { "Flags",                                   "shred.data.flags",                 FT_UINT8,    BASE_HEX,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_end_of_slot,               { "Last shred in slot",                      "shred.data.end_of_slot",           FT_BOOLEAN,  8,         NULL,                   0x80, NULL, HFILL } },
    { &hf_data_end_of_batch,              { "Last shred in entry batch",               "shred.data.end_of_batch",          FT_BOOLEAN,  8,         NULL,                   0x40, NULL, HFILL } },
    { &hf_data_ref_tick,                  { "Reference Tick",                          "shred.data.ref_tick",              FT_UINT8,    BASE_DEC,  NULL,                   0x3f, NULL, HFILL } },
    { &hf_data_size,                      { "Shred Size",                              "shred.data.size",                  FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_payload,                   { "Data Payload",                            "shred.data.payload",               FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },

    { &hf_code_data_cnt,                  { "Data Shred Count",                        "shred.code.data_cnt",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_code_cnt,                  { "Code Shred Count",                        "shred.code.code_cnt",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_idx,                       { "Code Shred Index",                        "shred.code.code_idx",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_payload,                   { "Code Payload",                            "shred.code.payload",               FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },
  };

  static gint * ett[] = {
    &ett_shred,
  };

  proto_turbine = proto_register_protocol( "Solana Turbine Shred",
                                           "Solana Turbine",
                                           "solana_turbine" );
  proto_register_field_array( proto_turbine, hf, array_length( hf ) );
  proto_register_subtree_array( ett, array_length( ett ) );
}

/* dissect_turbine: Dissects a Solana turbine shred packet. */
static gboolean
dissect_turbine( tvbuff_t    * tvb,
                 packet_info * pinfo,
                 proto_tree  * tree,
                 void        * data __attribute__((unused)) ) {
  /* Turbine packets are always at least 1228 bytes long. */
  uint packet_sz = tvb_captured_length( tvb );
  if( packet_sz<FD_SHRED_SZ ) return 0;

  col_set_str( pinfo->cinfo, COL_PROTOCOL, "Turbine" );
  col_clear  ( pinfo->cinfo, COL_INFO );

  proto_item * ti     = proto_tree_add_item( tree, proto_turbine, tvb, 0, -1, ENC_NA );
  proto_tree * tshred = proto_item_add_subtree( ti, ett_shred );

  /* Add common shred header fields */
  proto_tree_add_item( tshred, hf_sig,           tvb, offsetof( fd_shred_t, signature   ), 64, ENC_NA            );
  proto_tree_add_item( tshred, hf_type,          tvb, offsetof( fd_shred_t, variant     ),  1, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_slot,          tvb, offsetof( fd_shred_t, slot        ),  8, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_idx,           tvb, offsetof( fd_shred_t, idx         ),  4, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_shred_version, tvb, offsetof( fd_shred_t, version     ),  2, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_fec_set_idx,   tvb, offsetof( fd_shred_t, fec_set_idx ),  4, ENC_LITTLE_ENDIAN );

  /* Detect type and size of shred */
  uchar variant = tvb_get_guint8( tvb, offsetof( fd_shred_t, variant ) );
  uchar type    = fd_shred_type( variant );

  uint header_sz = (uint)fd_shred_header_sz( variant ) + (uint)fd_shred_merkle_sz( variant );

  /* Merkle proof length. */
  if( type==FD_SHRED_TYPE_MERKLE_CODE || type==FD_SHRED_TYPE_MERKLE_DATA ) {
    proto_tree_add_item( tshred, hf_merkle_len, tvb, offsetof( fd_shred_t, variant ), 1, ENC_LITTLE_ENDIAN );
  }

  /* Add shred type specific items */
  switch( type ) {
  case FD_SHRED_TYPE_LEGACY_DATA:
  case FD_SHRED_TYPE_MERKLE_DATA: {
    /* Data shred headers */
    proto_tree_add_item( tshred, hf_data_parent_off,   tvb, offsetof( fd_shred_t, data.parent_off ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_end_of_slot,  tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_end_of_batch, tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_ref_tick,     tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_size,         tvb, offsetof( fd_shred_t, data.size       ), 2, ENC_LITTLE_ENDIAN );

    /* Bounds checks pre-reassembly */
    if( FD_UNLIKELY( header_sz>packet_sz ) ) return 0;
    uint actual_sz = tvb_get_letohs( tvb, offsetof( fd_shred_t, data.size ) );
    if( FD_UNLIKELY( actual_sz>packet_sz ) ) return 0;
    if( FD_UNLIKELY( actual_sz<header_sz ) ) return 0;

    col_add_fstr( pinfo->cinfo, COL_INFO, "Data Shred slot=%lu", tvb_get_letoh64( tvb, offsetof( fd_shred_t, slot ) ) );

    /* Register PDU item for fragment */
    int payload_sz = (int)(actual_sz - header_sz);
    proto_tree_add_bytes_format( tshred, hf_data_payload, tvb, FD_SHRED_DATA_HEADER_SZ,
                                 payload_sz, NULL,
                                 "Data Slice (%d byte%s)", payload_sz, plurality( payload_sz, "", "s" ) );

    return 1;
  }
  case FD_SHRED_TYPE_LEGACY_CODE:
  case FD_SHRED_TYPE_MERKLE_CODE: {
    /* Coding shred headers */
    proto_tree_add_item( tshred, hf_code_data_cnt, tvb, offsetof( fd_shred_t, code.data_cnt ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_code_code_cnt, tvb, offsetof( fd_shred_t, code.code_cnt ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_code_idx,      tvb, offsetof( fd_shred_t, code.idx      ), 2, ENC_LITTLE_ENDIAN );

    /* Bounds checks */
    int payload_sz = (int)(packet_sz - header_sz);
    if( FD_UNLIKELY( header_sz>packet_sz ) ) return 0;
    if( FD_UNLIKELY( payload_sz<0        ) ) return 0;

    col_add_fstr( pinfo->cinfo, COL_INFO, "Code Shred slot=%lu", tvb_get_letoh64( tvb, offsetof( fd_shred_t, slot ) ) );

    /* Add fragment to tree.
       Reassembly for now unsupported. */
    proto_tree_add_bytes_format( tshred, hf_code_payload, tvb, FD_SHRED_CODE_HEADER_SZ,
                                 payload_sz, NULL,
                                 "Reed-Solomon Parity Bits (%d byte%s)", payload_sz, plurality( payload_sz, "", "s" ) );
    return 1;
  }
  default:
    return 0;
  }
}

/* Registers the Turbine dissector functions with the protocol handle. */
void
proto_reg_handoff_turbine(void) {
  static dissector_handle_t turbine_handle FD_FN_UNUSED;

  /* Register dissector for unknown UDP port.
     The Turbine-assigned ports differ for each Solana node and are usually discovered via gossip. */
  turbine_handle = create_dissector_handle( dissect_turbine, proto_turbine );
  dissector_add_for_decode_as( "udp.port", turbine_handle );
}

/* This is the entrypoint called by the Wireshark host.
   Registers all protocols defined by this plugin. */
void
plugin_register( void ) {
  static proto_plugin plugin_turbine;
  plugin_turbine.register_protoinfo = proto_register_turbine;
  plugin_turbine.register_handoff   = proto_reg_handoff_turbine;
  proto_register_plugin( &plugin_turbine );
}
