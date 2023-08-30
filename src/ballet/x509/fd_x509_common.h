/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */
#ifndef HEADER_fd_src_ballet_x509_fd_x509_common_h
#define HEADER_fd_src_ballet_x509_fd_x509_common_h

#include "fd_x509_utils.h"

typedef enum {
  CLASS_UNIVERSAL        = 0x00,
  CLASS_APPLICATION      = 0x01,
  CLASS_CONTEXT_SPECIFIC = 0x02,
  CLASS_PRIVATE          = 0x03
} tag_class;

typedef enum {
  ASN1_TYPE_BOOLEAN         = 0x01,
  ASN1_TYPE_INTEGER         = 0x02,
  ASN1_TYPE_BIT_STRING      = 0x03,
  ASN1_TYPE_OCTET_STRING    = 0x04,
  ASN1_TYPE_NULL            = 0x05,
  ASN1_TYPE_OID             = 0x06,
  ASN1_TYPE_ENUMERATED      = 0x0a,
  ASN1_TYPE_SEQUENCE        = 0x10,
  ASN1_TYPE_SET             = 0x11,
  ASN1_TYPE_PrintableString = 0x13,
  ASN1_TYPE_T61String       = 0x14,
  ASN1_TYPE_IA5String       = 0x16,
  ASN1_TYPE_UTCTime         = 0x17,
  ASN1_TYPE_GeneralizedTime = 0x18,
} asn1_type;


typedef enum {
  HASH_ALG_UNKNOWN =  0,
  HASH_ALG_SHA512  = 13,
} hash_alg_id;


/*
 * For a given signature algorithm, optional parameters specific to the
 * algorithm may be given inside the AlgorithmIdentfier structure. Below,
 * we map each signature algorithm OID to a simple identifier and a
 * specific structure we use to export the info we parsed.
 */
typedef enum {
  SIG_ALG_UNKNOWN  =  0,
  SIG_ALG_ED25519  =  4,
} sig_alg_id;


typedef enum {
  SPKI_ALG_UNKNOWN = 0,
  SPKI_ALG_ED25519 = 2,
  SPKI_ALG_X25519  = 4,
} spki_alg_id;


typedef enum {
  CURVE_UNKNOWN  =  0,
  CURVE_WEI25519 = 30,
} curve_id;


typedef struct {
  const uchar *alg_name;
  const uchar *alg_printable_oid;
  const uchar *alg_der_oid;
  const uint alg_der_oid_len;
  hash_alg_id hash_id;
} _hash_alg;

typedef struct {
  const uchar *crv_name;
  const uchar *crv_printable_oid;
  const uchar *crv_der_oid;
  const uint crv_der_oid_len;
  const uint crv_order_bit_len;
  curve_id crv_id;
} _curve;


/*
 *                           SPKI
 *
 * Now, we need some specific structure to export information
 * extracted from SPKI for the various kind of subject public
 * key we support. We define a structure per type, and put
 * everything in a spki_params union.
 */

typedef struct { /* SPKI_ALG_ED25519 */
  curve_id curve;
  uint curve_order_bit_len;

  uint ed25519_raw_pub_off;
  uint ed25519_raw_pub_len;
} spki_ed25519_params;

typedef struct { /* SPKI_ALG_X25519 */
  curve_id curve;
  uint curve_order_bit_len;

  uint x25519_raw_pub_off;
  uint x25519_raw_pub_len;
} spki_x25519_params;

typedef union {
  spki_ed25519_params ed25519;  /* SPKI_ALG_ED25519        */
  spki_x25519_params  x25519;   /* SPKI_ALG_X25519        */
} spki_params;


typedef struct { /* SIG_ALG_ED25519 */
  uint r_raw_off;
  uint r_raw_len; /* expects 32 */
  uint s_raw_off;
  uint s_raw_len; /* expects 32 */
} sig_ed25519_params;

typedef union {
  sig_ed25519_params ed25519; /* SIG_ALG_ED25519 */
} sig_params;

/* Signature and sig alg parameters parsing functions */
int parse_sig_ed25519(sig_params *params, const uchar *cert, uint off, uint len, uint *eaten);

int parse_algoid_sig_params_eddsa(sig_params *params, hash_alg_id *hash_alg, const uchar *cert, uint off, uint len);
int parse_algoid_sig_params_none(sig_params *params, hash_alg_id *hash_alg, const uchar *cert, uint off, uint ATTRIBUTE_UNUSED len);
int parse_algoid_params_none(const uchar *cert, uint off, uint len);


typedef struct {
  const uchar *alg_name;
  const uchar *alg_printable_oid;
  const uchar *alg_der_oid;
  const uint alg_der_oid_len;

  sig_alg_id sig_id;
  hash_alg_id hash_id;

  int (*parse_algoid_sig_params)(sig_params *params, hash_alg_id *hash_alg, const uchar *cert, uint off, uint len);
  int (*parse_sig)(sig_params *params, const uchar *cert, uint off, uint len, uint *eaten);
} _sig_alg;

extern const _sig_alg *known_sig_algs[];
extern const ushort num_known_sig_algs;

extern const _curve *known_curves[];

const _sig_alg * find_sig_alg_by_oid(const uchar *buf, uint len);
const _hash_alg * find_hash_by_oid(const uchar *buf, uint len);
const _curve * find_curve_by_oid(const uchar *buf, uint len);


int get_length(const uchar *buf, uint len,
         uint *adv_len, uint *eaten);

int parse_id_len(const uchar *buf, uint len,
     tag_class exp_class, uint exp_type,
     uint *parsed, uint *content_len);

int parse_explicit_id_len(const uchar *buf, uint len,
        uint exp_ext_type,
        tag_class exp_int_class, uint exp_int_type,
        uint *parsed, uint *data_len);

int parse_null(const uchar *buf, uint len,
         uint *parsed);

int parse_OID(const uchar *buf, uint len,
        uint *parsed);

int parse_integer(const uchar *buf, uint len,
      tag_class exp_class, uint exp_type,
      uint *hdr_len, uint *data_len);

int parse_non_negative_integer(const uchar *buf, uint len,
             tag_class exp_class, uint exp_type,
             uint *hdr_len, uint *data_len);

int parse_boolean(const uchar *buf, uint len, uint *eaten);




int parse_generalizedTime(const uchar *buf, uint len, uint *eaten,
        ushort *year, uchar *month, uchar *day,
        uchar *hour, uchar *min, uchar *sec);

#define NAME_TYPE_rfc822Name     0x81
#define NAME_TYPE_dNSName        0x82
#define NAME_TYPE_URI            0x86
#define NAME_TYPE_iPAddress      0x87
#define NAME_TYPE_registeredID   0x88
#define NAME_TYPE_otherName      0xa0
#define NAME_TYPE_x400Address    0xa3
#define NAME_TYPE_directoryName  0xa4
#define NAME_TYPE_ediPartyName   0xa5

int parse_GeneralName(const uchar *buf, uint len, uint *eaten, int *empty);

int parse_SerialNumber(const uchar *cert, uint off, uint len,
           tag_class exp_class, uint exp_type,
           uint *eaten);

int verify_correct_time_use(uchar time_type, ushort yyyy);

int parse_Time(const uchar *buf, uint len, uchar *t_type, uint *eaten,
         ushort *year, uchar *month, uchar *day,
         uchar *hour, uchar *min, uchar *sec);

int verify_correct_time_use(uchar time_type, ushort yyyy);

int parse_AKICertSerialNumber(const uchar *cert, uint off, uint len,
            tag_class exp_class, uint exp_type,
            uint *eaten);

int parse_crldp_reasons(const uchar *buf, uint len, uint exp_type, uint *eaten);

int parse_DistributionPoint(const uchar *buf, uint len,
          int *crldp_has_all_reasons, uint *eaten);

int parse_AIA(const uchar *cert, uint off, uint len, int critical);

int parse_ia5_string(const uchar *buf, uint len, uint lb, uint ub);

int parse_x509_Name(const uchar *buf, uint len, uint *eaten, int *empty);

int parse_DisplayText(const uchar *buf, uint len, uint *eaten);

int parse_nine_bit_named_bit_list(const uchar *buf, uint len, ushort *val);

int parse_GeneralName(const uchar *buf, uint len, uint *eaten, int *empty);

int parse_GeneralNames(const uchar *buf, uint len, tag_class exp_class,
           uint exp_type, uint *eaten);

ulong time_components_to_comparable_u64(ushort na_year, uchar na_month, uchar na_day,
              uchar na_hour, uchar na_min, uchar na_sec);

#endif /* HEADER_fd_src_ballet_x509_fd_x509_common_h */
