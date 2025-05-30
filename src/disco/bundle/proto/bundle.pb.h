/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.9.1 */

#ifndef PB_BUNDLE_BUNDLE_PB_H_INCLUDED
#define PB_BUNDLE_BUNDLE_PB_H_INCLUDED
#include "../../../ballet/nanopb/pb_firedancer.h"
#include "packet.pb.h"
#include "shared.pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef struct _bundle_Bundle {
    bool has_header;
    shared_Header header;
    pb_callback_t packets;
} bundle_Bundle;

typedef PB_BYTES_ARRAY_T(128) bundle_BundleUuid_uuid_t;
typedef struct _bundle_BundleUuid {
    bool has_bundle;
    bundle_Bundle bundle;
    bundle_BundleUuid_uuid_t uuid;
} bundle_BundleUuid;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define bundle_Bundle_init_default               {false, shared_Header_init_default, {{NULL}, NULL}}
#define bundle_BundleUuid_init_default           {false, bundle_Bundle_init_default, {0, {0}}}
#define bundle_Bundle_init_zero                  {false, shared_Header_init_zero, {{NULL}, NULL}}
#define bundle_BundleUuid_init_zero              {false, bundle_Bundle_init_zero, {0, {0}}}

/* Field tags (for use in manual encoding/decoding) */
#define bundle_Bundle_header_tag                 2
#define bundle_Bundle_packets_tag                3
#define bundle_BundleUuid_bundle_tag             1
#define bundle_BundleUuid_uuid_tag               2

/* Struct field encoding specification for nanopb */
#define bundle_Bundle_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, MESSAGE,  header,            2) \
X(a, CALLBACK, REPEATED, MESSAGE,  packets,           3)
#define bundle_Bundle_CALLBACK pb_default_field_callback
#define bundle_Bundle_DEFAULT NULL
#define bundle_Bundle_header_MSGTYPE shared_Header
#define bundle_Bundle_packets_MSGTYPE packet_Packet

#define bundle_BundleUuid_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, MESSAGE,  bundle,            1) \
X(a, STATIC,   SINGULAR, BYTES,    uuid,              2)
#define bundle_BundleUuid_CALLBACK NULL
#define bundle_BundleUuid_DEFAULT NULL
#define bundle_BundleUuid_bundle_MSGTYPE bundle_Bundle

extern const pb_msgdesc_t bundle_Bundle_msg;
extern const pb_msgdesc_t bundle_BundleUuid_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define bundle_Bundle_fields &bundle_Bundle_msg
#define bundle_BundleUuid_fields &bundle_BundleUuid_msg

/* Maximum encoded size of messages (where known) */
/* bundle_Bundle_size depends on runtime parameters */
/* bundle_BundleUuid_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
