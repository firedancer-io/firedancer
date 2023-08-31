/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */

#include "fd_x509_cert_parser.h"

#define X509_FILE_NUM 2 /* See x509-utils.h for rationale */

/* subject public key and spki params parsing functions */
static int parse_pubkey_ed25519(cert_parsing_ctx *ctx, const uchar *cert, uint off, uint len);
static int parse_pubkey_x25519(cert_parsing_ctx *ctx, const uchar *cert, uint off, uint len);

static int parse_algoid_pubkey_params_ed25519(cert_parsing_ctx *ctx, const uchar *cert, uint off, uint len);
static int parse_algoid_pubkey_params_x25519(cert_parsing_ctx *ctx, const uchar *cert, uint off, uint len);

/********************************************************************
 * Subject public key algs
 ********************************************************************/

typedef struct {
  const uchar *alg_name;
  const uchar *alg_printable_oid;
  const uchar *alg_der_oid;
  const uint alg_der_oid_len;

  spki_alg_id pubkey_id;

  int (*parse_algoid_pubkey_params)(cert_parsing_ctx FD_FN_UNUSED *ctx, const uchar *cert, uint off, uint len);
  int (*parse_pubkey)(cert_parsing_ctx FD_FN_UNUSED *ctx, const uchar *cert, uint off, uint len);
} _pubkey_alg;

#define DECL_PUBKEY_ALG(TTalg, XXtype, YYparse_pubkey, ZZparse_algoid, UUname, VVoid, WWoidbuf) \
static const uchar _##TTalg##_pubkey_name[] = UUname;            \
static const uchar _##TTalg##_pubkey_printable_oid[] = VVoid;    \
static const uchar _##TTalg##_pubkey_der_oid[] = WWoidbuf;       \
                    \
static const _pubkey_alg _##TTalg##_pubkey_alg = {            \
  .alg_name = _##TTalg##_pubkey_name,                   \
  .alg_printable_oid = _##TTalg##_pubkey_printable_oid, \
  .alg_der_oid = _##TTalg##_pubkey_der_oid,             \
  .alg_der_oid_len = sizeof(_##TTalg##_pubkey_der_oid), \
  .pubkey_id = (XXtype),              \
  .parse_pubkey = (YYparse_pubkey),          \
  .parse_algoid_pubkey_params = (ZZparse_algoid),        \
}

/*
 *------------------------------------------+----------------------------+--------------------------------+-----------------------------------------------+----------------------------------+------------------------------+----------------------------------...
 *              struct name                 | pubkey alg                 | pubkey parsing func            | pubkey alg oid params parsing func            | pretty name for pubkey alg       | printable OID                | OID in DER format
 *------------------------------------------+----------------------------+--------------------------------+-----------------------------------------------+----------------------------------+------------------------------+----------------------------------...
 */
DECL_PUBKEY_ALG(x25519                      , SPKI_ALG_X25519            , parse_pubkey_x25519            , parse_algoid_pubkey_params_x25519             , "X25519"                         , "1.3.101.110"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x6e }));
DECL_PUBKEY_ALG(ed25519                     , SPKI_ALG_ED25519           , parse_pubkey_ed25519           , parse_algoid_pubkey_params_ed25519            , "Ed25519"                        , "1.3.101.112"                , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x70 }));


static const _pubkey_alg FD_FN_UNUSED *known_pubkey_algs[] = {
  &_ed25519_pubkey_alg,
  &_x25519_pubkey_alg,
};

const ushort num_known_pubkey_algs = (sizeof(known_pubkey_algs) / sizeof(known_pubkey_algs[0]));



/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \forall integer k; 0 <= k < num_known_pubkey_algs ==> \valid_read(&(known_pubkey_algs[k]->alg_der_oid_len));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < num_known_pubkey_algs && \result == known_pubkey_algs[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
const _pubkey_alg * find_pubkey_alg_by_oid(const uchar *buf, uint len)
{
  const _pubkey_alg *found = NULL;
  const _pubkey_alg *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ loop unroll num_known_pubkey_algs;
    @ loop invariant 0 <= k <= num_known_pubkey_algs;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (num_known_pubkey_algs - k);
    @*/
  for (k = 0; k < num_known_pubkey_algs; k++) {
    int ret;

    cur = known_pubkey_algs[k];

    /*@ assert cur == known_pubkey_algs[k]; */
    if (cur->alg_der_oid_len != len) {
      continue;
    }

    /*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
    ret = !bufs_differ(cur->alg_der_oid, buf, cur->alg_der_oid_len);
    if (ret) {
      found = cur;
      break;
    }
  }

out:
  return found;
}

/*
 * The implementation is based on 4.1 and 4.1.2.1 of RFC5280 + Section
 * 8.3 of X.690. The version field is mandatory and it is encoded as
 * an integer. As we only limit ourselves to version 3 certificates
 * (i.e. a value of 0x02 for the integer encoding the version) and the
 * version field is marked EXPLICIT in the definition for the certificate,
 * this makes things pretty simple. Note that CRL also have a Version
 * field but the field is not explicit and parsing not is done with this
 * function.
 *
 * version         [0]  EXPLICIT Version DEFAULT v1,
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (version != NULL) ==> \valid(version);
  @ requires \separated(eaten, cert+(..), version);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (version == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(version);
  @
  @ assigns *eaten, *version;
  @*/
static int parse_x509_cert_Version(const uchar *cert, uint off, uint len, uchar *version, uint *eaten)
{
  const uchar *buf = cert + off;
  uint data_len = 0;
  uint hdr_len = 0;
  int ret;

  if ((cert == NULL) || (version == NULL) || (len == 0) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */
  ret = parse_explicit_id_len(buf, len, 0,
            CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
            &hdr_len, &data_len);
  if (ret) {
    ret = X509_PARSER_ERROR_VERSION_ABSENT;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;

  /*
   * As the value we expect for the integer is 0x02 (version 3),
   * data_len must be 1.
   */
  if (data_len != 1) {
    ret = X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *version = buf[0];
  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}


/* Specification version for main serial number field of certificate */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&ctx->serial_start) && \initialized(&ctx->serial_len);
  @
  @ assigns *eaten, ctx->serial_start, ctx->serial_len;
  @*/
static int parse_CertSerialNumber(cert_parsing_ctx *ctx,
          const uchar *cert, uint off, uint len,
          tag_class exp_class, uint exp_type,
          uint *eaten)
{
  int ret;

  if ((cert == NULL) || (len == 0) || (eaten == NULL) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_SerialNumber(cert, off, len, exp_class, exp_type, eaten);
  if (ret) {
         ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
         goto out;
  }

  ctx->serial_start = off + 2; /* 2 bytes long hdr for a valid SN */
  ctx->serial_len = *eaten - 2;

out:
  return ret;
}


/*
 * RFC 8410 defines Agorithm Identifiers for Ed25519 and Ed448
 *
 * subject public key encoding:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm         AlgorithmIdentifier,
 *      subjectPublicKey  BIT STRING
 * }
 *
 *
 *  The fields in SubjectPublicKeyInfo have the following meanings:
 *
 *  o  algorithm is the algorithm identifier and parameters for the
 *     public key (see above).
 *
 *  o  subjectPublicKey contains the byte stream of the public key.  The
 *     algorithms defined in this document always encode the public key
 *     as an exact multiple of 8 bits.
 *
 * OID are 1.3.101.112 for Ed25519 and 1.3.101.113 for Ed448.
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (raw_pub_off != NULL) ==> \valid(raw_pub_off);
  @ requires (raw_pub_len != NULL) ==> \valid(raw_pub_len);
  @ requires \separated(cert+(..),raw_pub_off, raw_pub_len);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *raw_pub_off, *raw_pub_len;
  @*/
static int parse_pubkey_eddsa(const uchar *cert, uint off, uint len,
            uint exp_pub_len, uint *raw_pub_off, uint *raw_pub_len)
{
  uint remain, hdr_len = 0, data_len = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) ||
      (raw_pub_off == NULL) || (raw_pub_len == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * We expect the bitstring data to contain at least the initial
   * octet encoding the number of unused bits in the final
   * subsequent octet of the bistring.
   * */
  if (data_len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;

  /*
   * We expect the initial octet to encode a value of 0
   * indicating that there are no unused bits in the final
   * subsequent octet of the bitstring.
   */
  if (buf[0] != 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 1;
  remain = data_len - 1;

  if (remain != exp_pub_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;
  *raw_pub_off = off + hdr_len + 1;
  *raw_pub_len = exp_pub_len;
out:
  return ret;
}

#define ED25519_PUB_LEN 32
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.ed25519.ed25519_raw_pub_off,
      ctx->spki_alg_params.ed25519.ed25519_raw_pub_len;
  @*/
static int parse_pubkey_ed25519(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len)
{
  return parse_pubkey_eddsa(cert, off, len, ED25519_PUB_LEN,
          &ctx->spki_alg_params.ed25519.ed25519_raw_pub_off,
          &ctx->spki_alg_params.ed25519.ed25519_raw_pub_len);
}

#define X25519_PUB_LEN ED25519_PUB_LEN
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.x25519.x25519_raw_pub_off,
      ctx->spki_alg_params.x25519.x25519_raw_pub_len;
  @*/
static int parse_pubkey_x25519(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len)
{
  return parse_pubkey_eddsa(cert, off, len, X25519_PUB_LEN,
          &ctx->spki_alg_params.x25519.x25519_raw_pub_off,
          &ctx->spki_alg_params.x25519.x25519_raw_pub_len);
}


/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.ed25519.curve,
      ctx->spki_alg_params.ed25519.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_ed25519(cert_parsing_ctx *ctx,
                const uchar *cert, uint FD_FN_UNUSED off, uint len)
{
  int ret;

  if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->spki_alg_params.ed25519.curve = CURVE_WEI25519;
  ctx->spki_alg_params.ed25519.curve_order_bit_len = 256;

  ret = 0;

out:
  return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.x25519.curve,
      ctx->spki_alg_params.x25519.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_x25519(cert_parsing_ctx *ctx,
                const uchar *cert, uint FD_FN_UNUSED off, uint len)
{
  int ret;

  if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->spki_alg_params.x25519.curve = CURVE_WEI25519;
  ctx->spki_alg_params.x25519.curve_order_bit_len = 256;

  ret = 0;

out:
  return ret;
}


/*
 * The algorithmIdentifier structure is used at different location
 * in a certificate for different kind of algorithms:
 *
 *  - in signature and signatureAlgorithm fields, it describes a
 *    signature algorithm.
 *  - in subjectPublicKeyInfo, it describes a public key
 *    algorithm.
 *
 * It has the following structure:
 *
 * AlgorithmIdentifier. Used for signature field.
 *
 *    AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * In the parser, we define currently define two functions:
 *
 *  - one for parsing tbsCertificate.signature algoid field
 *  - one for parsing spki algoid field
 *
 * Parsing of certificate signatureAlgorithm field is not performed.
 * as it must exactly match the content of tbsCertificate.signature
 * field. A simple comparison is performed for that purpose.
 */

/*
 * This function parses tbsCertificate.signature field and populate ctx with useful
 * information on success.
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (alg != NULL) ==> \valid(alg);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(cert+(..),alg,ctx,eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \valid_read(*alg);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->hash_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start == off;
  @ ensures (\result == 0) ==> \exists integer x; 0 <= x < num_known_sig_algs && *alg == known_sig_algs[x];
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @
  @ assigns *alg, *eaten, *ctx;
  @*/
static int parse_x509_tbsCert_sig_AlgorithmIdentifier(cert_parsing_ctx *ctx,
                  const uchar *cert, uint off, uint len,
                  const _sig_alg **alg,
                  uint *eaten)
{
  const _sig_alg *talg = NULL;
  const uchar *buf = cert + off;
  uint saved_off = off;
  uint parsed = 0;
  uint hdr_len = 0;
  uint data_len = 0;
  uint param_len;
  uint oid_len = 0;
  int ret;

  if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  parsed = hdr_len + data_len;
  /*@ assert (1 < parsed <= len); */

  buf += hdr_len;
  off += hdr_len;

  /* The first thing we should find in the sequence is an OID */
  ret = parse_OID(buf, data_len, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's now see if that OID is one associated w/ an alg we support */
  talg = find_sig_alg_by_oid(buf, oid_len);
  /*@ assert (talg != NULL) ==> \exists integer i ; 0 <= i < num_known_sig_algs && talg == known_sig_algs[i]; */
  if (talg == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert \exists integer i ; 0 <= i < num_known_sig_algs && talg == known_sig_algs[i]; */
  /*@ assert \valid_read(talg); */

  /*
   * Record position of spki alg oid. Also keep track of
   * the signature mechanism alg identifier and possibly
   * the associated hash identifier if it was explicit in
   * the mechanism. Otherwise, we will temporarily inherit
   * from HASH_ALG_UNKNOWN and possibly get the hash during
   * the parsing of alg oid sig parameters just below.
   */
  ctx->tbs_sig_alg_oid_start = off;
  ctx->tbs_sig_alg_oid_len = oid_len;
  ctx->sig_alg = talg->sig_id;
  ctx->hash_alg = talg->hash_id;

  buf += oid_len;
  off += oid_len;
  param_len = data_len - oid_len;

  /*@ assert talg->parse_algoid_sig_params \in {
      parse_algoid_sig_params_eddsa,
      parse_algoid_sig_params_none }; @*/
  /*@ calls parse_algoid_sig_params_eddsa,
      parse_algoid_sig_params_none,; @*/
  ret = talg->parse_algoid_sig_params(&ctx->sig_alg_params, &ctx->hash_alg, cert, off, param_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * parsing went ok; we have verified that nothing remains behind, i.e.
   * that 'param_len' was indeed the length of the parameters.
   */
  ctx->tbs_sig_alg_oid_params_start = off;
  ctx->tbs_sig_alg_oid_params_len = param_len;

  /*@ assert \exists integer i ; 0 <= i < num_known_sig_algs && talg == known_sig_algs[i]; */
  *alg = talg;
  *eaten = parsed;
  ctx->tbs_sig_alg_start = saved_off;
  ctx->tbs_sig_alg_len = parsed;

  ret = 0;

out:
  return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (alg != NULL) ==> \valid(alg);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(cert+(..),alg,eaten,ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> \exists integer i ; 0 <= i < num_known_pubkey_algs && *alg == known_pubkey_algs[i];
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \valid_read(*alg);
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_oid_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_oid_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_bign ==> ctx->spki_alg_params.bign.curve_order_bit_len <= 571;
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_ec ==> ctx->spki_alg_params.ecpubkey.curve_order_bit_len <= 571;
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve));
  @
  @ assigns *alg, *eaten, *ctx;
  @*/
static int parse_x509_pubkey_AlgorithmIdentifier(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len,
             const _pubkey_alg **alg,
             uint *eaten)
{
  const _pubkey_alg *talg = NULL;
  const uchar *buf = cert + off;
  uint saved_off = off;
  uint parsed = 0;
  uint hdr_len = 0;
  uint data_len = 0;
  uint param_len;
  uint oid_len = 0;
  int ret;

  if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert 1 < (hdr_len + data_len) <= len; */
  buf += hdr_len;
  off += hdr_len;

  /* The first thing we should find in the sequence is an OID */
  ret = parse_OID(buf, data_len, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* record position of spki alg oid */
  ctx->spki_alg_oid_start = off;
  ctx->spki_alg_oid_len = oid_len;

  /* Let's see if that OID is one associated w/ a pubkey alg we support */
  talg = find_pubkey_alg_by_oid(buf, oid_len);
  if (talg == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert \exists integer i ; 0 <= i < num_known_pubkey_algs && talg == known_pubkey_algs[i]; */
  /*@ assert \valid_read(talg); */

  buf += oid_len;
  off += oid_len;
  param_len = data_len - oid_len;

  /*@ assert talg->parse_algoid_pubkey_params \in {
       parse_algoid_pubkey_params_ecPublicKey,
       parse_algoid_pubkey_params_ed25519,
       parse_algoid_pubkey_params_x25519,
       parse_algoid_pubkey_params_none,
       parse_algoid_pubkey_params_bign}; @*/
  /*@ calls parse_algoid_pubkey_params_ecPublicKey,
       parse_algoid_pubkey_params_ed25519,
       parse_algoid_pubkey_params_x25519,
       parse_algoid_pubkey_params_none,
       parse_algoid_pubkey_params_bign; @*/
  ret = talg->parse_algoid_pubkey_params(ctx, cert, off, param_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->spki_alg_oid_params_start = off;
  ctx->spki_alg_oid_params_len = param_len;

  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_bign ==> ctx->spki_alg_params.bign.curve_order_bit_len <= 571; */
  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */

  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_ecPublicKey ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_ecPublicKey ==> ctx->spki_alg_params.ecpubkey.curve_order_bit_len <= 571; */
  /*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_ecPublicKey ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

  /*@ assert talg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
  /*@ assert talg->parse_pubkey == parse_pubkey_bign ==> ctx->spki_alg_params.bign.curve_order_bit_len <= 571; */
  /*@ assert talg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */

  /*@ assert talg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
  /*@ assert talg->parse_pubkey == parse_pubkey_ec ==> ctx->spki_alg_params.ecpubkey.curve_order_bit_len <= 571; */
  /*@ assert talg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

  parsed = hdr_len + data_len;
  /*@ assert 1 < parsed <= len; */
  *alg = talg;
  /*@ assert (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
  /*@ assert (*alg)->parse_pubkey == parse_pubkey_bign ==> ctx->spki_alg_params.bign.curve_order_bit_len <= 571; */
  /*@ assert (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */

  /*@ assert (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
  /*@ assert (*alg)->parse_pubkey == parse_pubkey_ec ==> ctx->spki_alg_params.ecpubkey.curve_order_bit_len <= 571; */
  /*@ assert (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */
  *eaten = parsed;
  /*@ assert 1 < *eaten <= len; */
  ctx->spki_alg = talg->pubkey_id;
  ctx->spki_alg_oid_start = saved_off;
  ctx->spki_alg_oid_len = parsed;

  ret = 0;

out:
  return ret;
}


/*
 * Verify Validity by checking it is indeed a sequence of two
 * valid UTCTime elements. Note that the function only perform
 * syntaxic checks on each element individually and does not
 * compare the two values together (e.g. to verify notBefore
 * is indeed before notAfter, etc).
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns *eaten, ctx->not_before, ctx->not_after;
  @*/
static int parse_x509_Validity(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len, uint *eaten)
{
  const uchar *buf = cert + off;
  int ret;
  uint hdr_len = 0;
  uint remain = 0;
  uint data_len = 0;
  uint nb_len = 0, na_len = 0;
  ushort na_year = 0, nb_year = 0;
  uchar na_month = 0, na_day = 0, na_hour = 0, na_min = 0, na_sec = 0;
  uchar nb_month = 0, nb_day = 0, nb_hour = 0, nb_min = 0, nb_sec = 0;
  uchar t_type = 0;
  ulong not_after, not_before;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain = data_len;

  /* Parse notBefore */
  ret = parse_Time(buf, remain, &t_type, &nb_len, &nb_year, &nb_month,
       &nb_day, &nb_hour, &nb_min, &nb_sec);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check valid time type was used for year value */
  ret = verify_correct_time_use(t_type, nb_year);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= nb_len;
  buf += nb_len;

  /* Parse notAfter */
  ret = parse_Time(buf, remain, &t_type, &na_len, &na_year, &na_month,
       &na_day, &na_hour, &na_min, &na_sec);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check valid time type was used for year value */
  ret = verify_correct_time_use(t_type, na_year);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= na_len;
  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * To export time to context we do not bother converting to unix
   * but encode all the components on a u64 in the following way.
   * this makes resulting not_after and not_before values comparable.
   */

  /*@ assert na_year <= 9999; */
  /*@ assert na_month <= 12; */
  /*@ assert na_day <= 31; */
  /*@ assert na_hour <= 23; */
  /*@ assert na_min <= 59; */
  /*@ assert na_sec <= 59; */
  not_after = time_components_to_comparable_u64(na_year, na_month, na_day,
                  na_hour, na_min, na_sec);


  /*@ assert nb_year <= 9999; */
  /*@ assert nb_month <= 12; */
  /*@ assert nb_day <= 31; */
  /*@ assert nb_hour <= 23; */
  /*@ assert nb_min <= 59; */
  /*@ assert nb_sec <= 59; */
  not_before = time_components_to_comparable_u64(nb_year, nb_month, nb_day,
                   nb_hour, nb_min, nb_sec);

  if (not_before >= not_after) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->not_before = not_before;
  ctx->not_after = not_after;
  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}

/* SubjectPublicKeyInfo,
 *
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *         algorithm            AlgorithmIdentifier,
 *         subjectPublicKey     BIT STRING  }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_subjectPublicKeyInfo(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len,
             uint *eaten)
{
  uint hdr_len = 0, data_len = 0, parsed = 0, remain = 0;
  uint saved_off = off;
  const uchar *buf = cert + off;
  const _pubkey_alg *alg = NULL;
  int ret;

  if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain = data_len;
  off += hdr_len;

  ret = parse_x509_pubkey_AlgorithmIdentifier(ctx, cert, off, remain,
                &alg, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert alg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
  /*@ assert alg->parse_pubkey == parse_pubkey_ec ==> ctx->spki_alg_params.bign.curve_order_bit_len <= 571; */
  /*@ assert alg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */
  /*@ assert alg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
  /*@ assert alg->parse_pubkey == parse_pubkey_ec ==> ctx->spki_alg_params.ecpubkey.curve_order_bit_len <= 571; */
  /*@ assert alg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

  buf += parsed;
  remain -= parsed;
  off += parsed;

  /*
   * Let's now check if subjectPublicKey is ok based on the
   * algorithm and parameters we found.
   */
  if (!alg->parse_pubkey) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert alg->parse_pubkey \in {
      parse_pubkey_ed25519,
      parse_pubkey_x25519,
      parse_pubkey_ec,
      parse_pubkey_bign } ; @*/
  /*@ calls parse_pubkey_ed25519,
      parse_pubkey_x25519,
      parse_pubkey_ec,
      parse_pubkey_bign ; @*/
  ret = alg->parse_pubkey(ctx, cert, off, remain);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->spki_pub_key_start = off;
  ctx->spki_pub_key_len = remain;
  ctx->spki_start = saved_off;
  ctx->spki_len = hdr_len + data_len;
  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}


/*
 * Extensions -- optional
 */


#if 0
/* WIP! */

/*
 * RFC 5280 has "When the subjectAltName extension contains a domain name
 * system label, the domain name MUST be stored in the dNSName (an
 * IA5String). The name MUST be in the "preferred name syntax", as
 * specified by Section 3.5 of [RFC1034] and as modified by Section 2.1
 * of [RFC1123]. In addition, while the string " " is a legal domain name,
 * subjectAltName extensions with a dNSName of " " MUST NOT be used."
 *                                                              |
 * This function implements that checks, namely:                |
 *                                                              |
 * From 3.5 of RFC 1034:                                        |
 *                                                              |
 *    <domain> ::= <subdomain> | " "          " " not allowed --+
 *
 *    <subdomain> ::= <label> | <subdomain> "." <label>
 *
 *    <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
 *
 *    <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
 *
 *    <let-dig-hyp> ::= <let-dig> | "-"
 *
 *    <let-dig> ::= <letter> | <digit>
 *
 *    <letter> ::= any one of the 52 alphabetic characters A through Z in
 *    upper case and a through z in lower case
 *
 *    <digit> ::= any one of the ten digits 0 through 9
 *
 *    Note that while upper and lower case letters are allowed in domain
 *    names, no significance is attached to the case.  That is, two names with
 *    the same spelling but different case are to be treated as if identical.
 *
 *    The labels must follow the rules for ARPANET host names.  They must
 *    start with a letter, end with a letter or digit, and have as interior
 *    characters only letters, digits, and hyphen.  There are also some
 *    restrictions on the length.  Labels must be 63 characters or less.
 *
 * From 2.1 of RFC 1123:
 *
 *    The syntax of a legal Internet host name was specified in RFC-952
 *    [DNS:4].  One aspect of host name syntax is hereby changed: the
 *    restriction on the first character is relaxed to allow either a
 *    letter or a digit.  Host software MUST support this more liberal
 *    syntax.
 *
 *    Host software MUST handle host names of up to 63 characters and
 *    SHOULD handle host names of up to 255 characters.
 *
 *    Whenever a user inputs the identity of an Internet host, it SHOULD
 *    be possible to enter either (1) a host domain name or (2) an IP
 *    address in dotted-decimal ("#.#.#.#") form.  The host SHOULD check
 *    the string syntactically for a dotted-decimal number before
 *    looking it up in the Domain Name System.
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_prefered_name_syntax(const uchar *buf, uint len)
{

  /* FIXME! */

  ret = 0;

out:
  return ret;
}
#endif




/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (critical != 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_AIA(cert_parsing_ctx FD_FN_UNUSED *ctx,
       const uchar *cert, uint off, uint len, int critical)
{
  int ret;

  if (ctx == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_AIA(cert, off, len, critical);
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

out:
  return ret;
}


/* 4.2.1.1. Authority Key Identifier
 *
 * The identification MAY be based on either the key identifier (the subject
 * key identifier in the issuer's certificate) or the issuer name and serial
 * number.
 *
 *   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *      -- authorityCertIssuer and authorityCertSerialNumber MUST both
 *      -- be present or both be absent
 *
 *   KeyIdentifier ::= OCTET STRING
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->aki_has_keyIdentifier,
      ctx->aki_keyIdentifier_start,
      ctx->aki_keyIdentifier_len,
      ctx->aki_has_generalNames_and_serial,
      ctx->aki_generalNames_start,
      ctx->aki_generalNames_len,
      ctx->aki_serial_start,
      ctx->aki_serial_len,
      ctx->has_aki;
  @*/
static int parse_ext_AKI(cert_parsing_ctx *ctx,
       const uchar *cert, uint off, uint len, int critical)
{
  uint hdr_len = 0, data_len = 0;
  const uchar *buf = cert + off;
  uint key_id_hdr_len = 0, key_id_data_len = 0, key_id_data_off = 0;
  uint gen_names_off = 0, gen_names_len = 0;
  uint cert_serial_off = 0, cert_serial_len = 0;
  uint remain;
  uint parsed = 0;
  int ret, has_keyIdentifier = 0, has_gen_names_and_serial = 0;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * As specified in section 4.2.1.1. of RFC 5280, it is recommended
   * for conforming CA not to set the critical bit for AKI extension
   */
  if (critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check we are indeed dealing w/ a sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * We should now find a KeyIdentifier or/and a couple of
   * (GeneralNames, and CertificateSerialNumber).
   */

  /*
   * First, the KeyIdentifier if present (KeyIdentifier ::= OCTET STRING)
   */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
         &key_id_hdr_len, &key_id_data_len);
  if (!ret) {
    /* An empty KeyIdentifier does not make any sense. Drop it! */
    if (!key_id_data_len) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    key_id_data_off = off + key_id_hdr_len;
    buf += key_id_hdr_len + key_id_data_len;
    off += key_id_hdr_len + key_id_data_len;
    remain -= key_id_hdr_len + key_id_data_len;
    has_keyIdentifier = 1;
  }


  /*
   * See if a (GeneralNames, CertificateSerialNumber) couple follows.
   * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName. We do
   * not accept one w/o the other.
   */
  ret = parse_GeneralNames(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
         &parsed);
  if (!ret) {
    gen_names_off = off;
    gen_names_len = parsed;

    buf += parsed;
    off += parsed;
    remain -= parsed;

    /* CertificateSerialNumber ::= INTEGER */
    ret = parse_AKICertSerialNumber(cert, off, remain,
            CLASS_CONTEXT_SPECIFIC, 2,
            &cert_serial_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert cert_serial_len > 2; */

    has_gen_names_and_serial = 1;
    cert_serial_off = off;

    buf += cert_serial_len;
    off += cert_serial_len;
    remain -= cert_serial_len;
  }

  /* Nothing should remain behind */
  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Only populate context when we know everything is ok. */
  ctx->aki_has_keyIdentifier = has_keyIdentifier;
  /*@ assert \initialized(&ctx->aki_has_keyIdentifier); */
  if (ctx->aki_has_keyIdentifier) {
    ctx->aki_keyIdentifier_start = key_id_data_off;
    /*@ assert \initialized(&ctx->aki_keyIdentifier_start); */
    ctx->aki_keyIdentifier_len = key_id_data_len;
    /*@ assert \initialized(&ctx->aki_keyIdentifier_len); */
  }
  ctx->aki_has_generalNames_and_serial = has_gen_names_and_serial;
  /*@ assert \initialized(&ctx->aki_has_generalNames_and_serial); */
  if (ctx->aki_has_generalNames_and_serial) {
    ctx->aki_generalNames_start = gen_names_off;
    /*@ assert \initialized(&ctx->aki_generalNames_start); */
    ctx->aki_generalNames_len = gen_names_len;
    /*@ assert \initialized(&ctx->aki_generalNames_len); */
    ctx->aki_serial_start = cert_serial_off + 2;  /* 2 bytes long hdr for a valid SN */
    /*@ assert \initialized(&ctx->aki_serial_start); */
    ctx->aki_serial_len = cert_serial_len - 2;
    /*@ assert \initialized(&ctx->aki_serial_len); */
  }
  ctx->has_aki = 1;
  /*@ assert \initialized(&ctx->has_aki); */
  ret = 0;

out:
  return ret;
}

/*
 * 4.2.1.2. Subject Key Identifier
 *
 * SubjectKeyIdentifier ::= KeyIdentifier
 * KeyIdentifier ::= OCTET STRING
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx,cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_ski,
      ctx->ski_start,
      ctx->ski_len;
  @*/
static int parse_ext_SKI(cert_parsing_ctx *ctx,
       const uchar *cert, uint off, uint len, int critical)
{
  uint key_id_hdr_len = 0, key_id_data_len = 0;
  const uchar *buf = cert + off;
  uint remain;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  remain = len;

  /*
   * As specified in section 4.2.1.1. of RFC 5280, conforming CA
   * must mark this extension as non-critical.
   */
#ifdef TEMPORARY_LAXIST_SKI_CRITICAL_FLAG_SET
  (void)critical;
#else
  if (critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
#endif

  ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
         &key_id_hdr_len, &key_id_data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len != (key_id_hdr_len + key_id_data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* An empty KeyIdentifier does not make any sense. Drop it! */
  if (!key_id_data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= key_id_hdr_len + key_id_data_len;
  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->has_ski = 1;
  ctx->ski_start = off + key_id_hdr_len;
  ctx->ski_len = key_id_data_len;
  ret = 0;

out:
  return ret;
}


/* 4.2.1.3. Key Usage
 *
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 *
 * KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1), -- recent editions of X.509 have
 *                           -- renamed this bit to contentCommitment
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 *
 */

/*
 * Masks for keyusage bits. Those masks are only usable on values
 * returned by parse_nine_bit_named_bit_list(), i.e. reversed
 * bits. Those not already used in the code are commented to avoid
 * unused macros and make clang compiler happy.
 */
//#define KU_digitalSignature  0x0001
//#define KU_nonRepudiation    0x0002
//#define KU_keyEncipherment   0x0004
//#define KU_dataEncipherment  0x0008
#define KU_keyAgreement      0x0010
#define KU_keyCertSign       0x0020
#define KU_cRLSign           0x0040
#define KU_encipherOnly      0x0080
#define KU_decipherOnly      0x0100

/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_keyUsage,
      ctx->keyCertSign_set,
      ctx->cRLSign_set;
  @*/
static int parse_ext_keyUsage(cert_parsing_ctx *ctx,
            const uchar *cert, uint off, uint len,
            int FD_FN_UNUSED critical)
{
  uint hdr_len = 0, data_len = 0;
  ushort val = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

       /*
   * As specified in section 4.2.1.3 of RFC 5280, when the extension
   * is present, "conforming CAs SHOULD mark this extension as
   * critical." For that reason, and because various CA emit certificates
   * with critical bit not set, we do not enforce critical bit value.
   */

  /* Check we are indeed dealing w/ a bit string */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
           &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  len -= hdr_len;

  /*
   * As expected in section 4.2.1.3 of RFC 5280, the function will
   * enforce that at least one bit is set : "When the keyUsage extension
   * appears in a certificate, at least one of the bits MUST be set to 1"
   */
  ret = parse_nine_bit_named_bit_list(buf, data_len, &val);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Section 4.2.1.3 of RFC 5280 has: "The meaning of the decipherOnly
   * bit is undefined in the absence of the keyAgreement bit". We
   * consider it invalid to have the former but not the latter.
   */
  if ((val & KU_decipherOnly) && !(val & KU_keyAgreement)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Section 4.2.1.3 of RFC 5280 has: "The meaning of the decipherOnly
   * bit is undefined in the absence of the keyAgreement bit". We
   * consider it invalid to have the former but not the latter.
   */
  if ((val & KU_encipherOnly) && !(val & KU_keyAgreement)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->has_keyUsage = 1;
  ctx->keyCertSign_set = !!(val & KU_keyCertSign);
  ctx->cRLSign_set = !!(val & KU_cRLSign);

  ret = 0;

out:
  return ret;
}

/* CPSuri ::= IA5String */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_CPSuri(const uchar *buf, uint len, uint *eaten)
{
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_ia5_string(buf, len, 1, 65534);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = len;

  ret = 0;

out:
  return ret;
}


/*
 *     NoticeReference ::= SEQUENCE {
 *          organization     DisplayText,
 *          noticeNumbers    SEQUENCE OF INTEGER }
 *
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_NoticeReference(const uchar *buf, uint len, uint *eaten)
{
  uint remain, parsed = 0, saved_len = 0, hdr_len = 0, data_len = 0;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = len;

  /* NoticeReference is a sequence */
  ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  saved_len = hdr_len + data_len;
  remain = data_len;
  buf += hdr_len;

  /*
   * First element of the sequence is the organization (of type
   * DisplayText)
   */
  ret = parse_DisplayText(buf, remain, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= parsed;
  buf += parsed;

  /*
   * Second element is the noticeNumbers, i.e. a sequence of
   * integers.
   */
  ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= hdr_len;
  buf += hdr_len;

  /* Advertised data in the sequence must exactly match what remains */
  if (remain != data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* The sequence contains integers */
  /*@
    @ loop assigns ret, buf, remain, parsed, hdr_len, data_len;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    /* Verify the integer is encoded as it should */
    ret = parse_integer(buf, remain,
            CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
            &hdr_len, &data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    parsed = hdr_len + data_len;
    remain -= parsed;
    buf += parsed;
  }

  *eaten = saved_len;

  ret = 0;

out:
  return ret;
}

/*
 *     UserNotice ::= SEQUENCE {
 *          noticeRef        NoticeReference OPTIONAL,
 *          explicitText     DisplayText OPTIONAL }
 *
 *     NoticeReference ::= SEQUENCE {
 *          organization     DisplayText,
 *          noticeNumbers    SEQUENCE OF INTEGER }
 *
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_UserNotice(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0, data_len = 0, remain = 0, parsed = 0;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = len;

  /* USerNotice is a sequence */
  ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= hdr_len;
  buf += hdr_len;

  /* Having an empty sequence is considered invalid */
  if (!data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* First element (if present) is a noticeRef of type NoticeReference */
  ret = parse_NoticeReference(buf, remain, &parsed);
  if (!ret) {
    remain -= parsed;
    buf += parsed;
  }

  /* Second element (if present) is an explicitText of type DisplayText */
  ret = parse_DisplayText(buf, remain, &parsed);
  if (!ret) {
    remain -= parsed;
    buf += parsed;
  }

  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}

/*
 *   PolicyQualifierInfo ::= SEQUENCE {
 *        policyQualifierId  PolicyQualifierId,
 *        qualifier          ANY DEFINED BY policyQualifierId }
 *
 *   -- policyQualifierIds for Internet policy qualifiers
 *
 *   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 *   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 *   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *
 *   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_policyQualifierInfo(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0, data_len = 0, oid_len = 0, remain = 0;
  uchar id_qt_cps_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
             0x07, 0x02, 0x01 };
  uchar id_qt_unotice_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
           0x07, 0x02, 0x02 };
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* It's a sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = data_len;
  buf += hdr_len;

  /*
   * First element of the sequence (policyQualifierId) is an OID
   * which can either take a value of id-qt-cps or id-qt-unotice.
   */
  ret = parse_OID(buf, remain, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if ((oid_len == sizeof(id_qt_cps_oid)) &&
      !bufs_differ(buf, id_qt_cps_oid, oid_len)) { /* id-qt-cps */
    uint cpsuri_len = 0;

    buf += oid_len;
    remain -= oid_len;

    ret = parse_CPSuri(buf, remain, &cpsuri_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= cpsuri_len;
    buf += cpsuri_len;

  } else if ((oid_len == sizeof(id_qt_unotice_oid)) &&
      !bufs_differ(buf, id_qt_unotice_oid, oid_len)) { /* id-qt-unotice */
    uint cpsunotice_len = 0;

    buf += oid_len;
    remain -= oid_len;

    ret = parse_UserNotice(buf, remain, &cpsunotice_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= cpsunotice_len;
    buf += cpsunotice_len;

  } else {                                        /* unsupported! */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}

/*
 *   PolicyInformation ::= SEQUENCE {
 *        policyIdentifier   CertPolicyId,
 *        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                                PolicyQualifierInfo OPTIONAL }
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_PolicyInformation(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0, data_len = 0, oid_len = 0, saved_pi_len, remain;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  saved_pi_len = hdr_len + data_len;

  remain = data_len;
  buf += hdr_len;

  /* policyIdentifier is a CertPolicyId, i.e. an OID */
  ret = parse_OID(buf, remain, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain -= oid_len;
  buf += oid_len;

  /* policyQualifiers is optional */
  if (remain) {
    /* policyQualifiers is a sequence */
    ret = parse_id_len(buf, remain,
           CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
           &hdr_len, &data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= hdr_len;
    buf += hdr_len;

    /* Nothing should remain after policyQualifiers */
    if (remain != data_len) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * Let's parse each PolicyQualifierInfo in the
     * policyQualifiers sequence
     */
    /*@
      @ loop assigns ret, buf, remain;
      @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
      @ loop variant remain;
      @ */
    while (remain) {
      uint pqi_len = 0;

      ret = parse_policyQualifierInfo(buf, remain, &pqi_len);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      remain -= pqi_len;
      buf += pqi_len;
    }
  }

  *eaten = saved_pi_len;

  /*
   * FIXME! At that point, we should verify we know the OID
   * (policyIdentifier) and the associated optional
   * content is indeed valid.
   */

  ret = 0;

out:
  return ret;
}


/* 4.2.1.4. Certificate Policies
 *
 * id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
 *
 *   anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
 *
 *   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 *   PolicyInformation ::= SEQUENCE {
 *        policyIdentifier   CertPolicyId,
 *        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                                PolicyQualifierInfo OPTIONAL }
 *
 *   CertPolicyId ::= OBJECT IDENTIFIER
 *
 *   PolicyQualifierInfo ::= SEQUENCE {
 *        policyQualifierId  PolicyQualifierId,
 *        qualifier          ANY DEFINED BY policyQualifierId }
 *
 *   -- policyQualifierIds for Internet policy qualifiers
 *
 *   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 *   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 *   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *
 *   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 *
 *   Qualifier ::= CHOICE {
 *        cPSuri           CPSuri,
 *        userNotice       UserNotice }
 *
 *   CPSuri ::= IA5String
 *
 *   UserNotice ::= SEQUENCE {
 *        noticeRef        NoticeReference OPTIONAL,
 *        explicitText     DisplayText OPTIONAL }
 *
 *   NoticeReference ::= SEQUENCE {
 *        organization     DisplayText,
 *        noticeNumbers    SEQUENCE OF INTEGER }
 *
 *   DisplayText ::= CHOICE {
 *        ia5String        IA5String      (SIZE (1..200)),
 *        visibleString    VisibleString  (SIZE (1..200)),
 *        bmpString        BMPString      (SIZE (1..200)),
 *        utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_certPolicies(cert_parsing_ctx FD_FN_UNUSED *ctx,
          const uchar *cert, uint off, uint len,
          int FD_FN_UNUSED critical)
{
  uint remain = 0, data_len = 0, hdr_len = 0, eaten = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * FIXME!
   *
   * This one will be a pain to deal with if we decide
   * to support the full version, i.e. non empty sequence
   * for policyQualifiersOID. RFC 5280 has:
   *
   *  To promote interoperability, this profile RECOMMENDS that policy
   *  information terms consist of only an OID.   Where an OID alone is
   *  insufficient, this profile strongly recommends that the use of
   *  qualifiers be limited to those identified in this section.  When
   *  qualifiers are used with the special policy anyPolicy, they MUST be
   *  limited to the qualifiers identified in this section.  Only those
   *  qualifiers returned as a result of path validation are considered.
   *
   */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's now check each individual PolicyInformation sequence */
  /*@
    @ loop assigns ret, buf, remain, eaten, off;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop invariant (off + remain) <= UINT_MAX;
    @ loop variant remain;
    @ */
  while (remain) {
    ret = parse_PolicyInformation(buf, remain, &eaten);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= eaten;
    off += eaten;
    buf += eaten;
  }

  ret = 0;

out:
  return ret;
}

/*
 * 4.2.1.5. Policy Mappings
 *
 * id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }
 *
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx,cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_policyMapping(cert_parsing_ctx FD_FN_UNUSED *ctx,
           const uchar *cert, uint off, uint len,
           int critical)
{
  uint remain = 0, data_len = 0, hdr_len = 0, eaten = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * As specified in section 4.2.1.5. of RFC 5280, "conforming CAs
   * SHOULD mark this extension as critical".
   */
  if (!critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's now check each sequence of {issuer,subject}DomainPolicy pair */
  /*@
    @ loop assigns ret, buf, remain, hdr_len, data_len, eaten, off;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop invariant (off + remain) <= UINT_MAX;
    @ loop variant remain;
    @ */
  while (remain) {
    ret = parse_id_len(buf, remain,
           CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
           &hdr_len, &data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += hdr_len;
    off += hdr_len;
    remain -= hdr_len;

    /* issuerDomainPolicy (an OID)*/
    ret = parse_OID(buf, data_len, &eaten);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += eaten;
    off += eaten;
    remain -= eaten;
    data_len -= eaten;

    /* subjectDomainPolicy (an OID) */
    ret = parse_OID(buf, data_len, &eaten);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    data_len -= eaten;
    if (data_len) {
      /*
       * Nothing should follow the two OIDs
       * in the sequence.
       */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += eaten;
    off += eaten;
    remain -=  eaten;
  }

  ret = 0;

out:
  return ret;
}


/*  4.2.1.6. Subject Alternative Name
 *
 *   id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
 *
 *   SubjectAltName ::= GeneralNames
 *
 *   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 *   GeneralName ::= CHOICE {
 *        otherName                       [0]     OtherName,
 *        rfc822Name                      [1]     IA5String,
 *        dNSName                         [2]     IA5String,
 *        x400Address                     [3]     ORAddress,
 *        directoryName                   [4]     Name,
 *        ediPartyName                    [5]     EDIPartyName,
 *        uniformResourceIdentifier       [6]     IA5String,
 *        iPAddress                       [7]     OCTET STRING,
 *        registeredID                    [8]     OBJECT IDENTIFIER }
 *
 *   OtherName ::= SEQUENCE {
 *        type-id    OBJECT IDENTIFIER,
 *        value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *   EDIPartyName ::= SEQUENCE {
 *        nameAssigner            [0]     DirectoryString OPTIONAL,
 *        partyName               [1]     DirectoryString }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_san,
      ctx->san_critical;
  @*/
static int parse_ext_SAN(cert_parsing_ctx *ctx,
       const uchar *cert, uint off, uint len,
       int critical)
{
  uint data_len = 0, hdr_len = 0, remain = 0, eaten = 0;
  const uchar *buf = cert + off;
  int ret, empty_gen_name;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * As specified in section 4.2.1.6. of RFC 5280, "if the subjectAltName
   * extension is present, the sequence MUST contain at least one entry.
   */
  if (!data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop assigns ret, buf, remain, eaten, empty_gen_name;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    empty_gen_name = 0;
    ret = parse_GeneralName(buf, remain, &eaten, &empty_gen_name);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * Section 4.2.16 of RFC 5280 has "Unlike the subject field,
     * conforming CAs MUST NOT issue certificates with
     * subjectAltNames containing empty GeneralName fields.
     */
    if (empty_gen_name) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * RFC5280 has: "When the subjectAltName extension contains an
     * iPAddress, the address MUST be stored in the octet string in
     * "network byte order", as specified in [RFC791].  The least
     * significant bit (LSB) of each octet is the LSB of the
     * corresponding byte in the network address.  For IP version
     * 4, as specified in [RFC791], the octet string MUST contain
     * exactly four octets. For IP version 6, as specified in
     * [RFC2460], the octet string MUST contain exactly sixteen
     * octets.
     */
    if (buf[0] == NAME_TYPE_iPAddress) {
      switch (eaten) {
      case 6: /* id/len/IPv4(4 bytes) */
        break;
      case 18: /* id/len/IPv6(16 bytes) */
        break;
      default: /* invalid */
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
        break;
      }
    }

    remain -= eaten;
    buf += eaten;
  }

  /*
   * Now that we know the extension is valid, let's record some
   * useful info.
   */
  ctx->has_san = 1;
  ctx->san_critical = critical;

  ret = 0;

out:
  return ret;
}

/* 4.2.1.7. Issuer Alternative Name */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_IAN(cert_parsing_ctx FD_FN_UNUSED *ctx,
       const uchar *cert, uint off, uint len,
       int FD_FN_UNUSED critical)
{
  uint data_len = 0, hdr_len = 0, remain = 0, eaten = 0;
  const uchar *buf = cert + off;
  int ret, unused = 0;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * Section 4.2.1.7 of RFC 5280 has "Where present, conforming CAs
   * SHOULD mark this extension as non-critical."
   *
   * FIXME! add a check?
   */

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * As specified in section 4.2.1.6. of RFC 5280, "if the subjectAltName
   * extension is present, the sequence MUST contain at least one entry.
   * Unlike the subject field, conforming CAs MUST NOT issue certificates
   * with subjectAltNames containing empty GeneralName fields.
   *
   * The first check is done here.
   *
   * FIXME! second check remains to be done. Possibly in adding an additional
   * out parameter to parse_GeneralName(), to tell if an empty one is
   * empty. This is because
   */
  if (!data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop assigns ret, buf, remain, eaten, unused, off;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop invariant (off + remain) <= UINT_MAX;
    @ loop variant remain;
    @ */
  while (remain) {
    ret = parse_GeneralName(buf, remain, &eaten, &unused);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= eaten;
    off += eaten;
    buf += eaten;
  }

  ret = 0;

out:
  return ret;
}

/*
 * 4.2.1.8. Subject Directory Attributes
 *
 * id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
 *
 * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *
 * Attribute ::= SEQUENCE {
 *   type    AttributeType,
 *   values  SET OF AttributeValue
 *   -- at least one value is required --
 * }
 *
 * AttributeType           ::= OBJECT IDENTIFIER
 *
 * AttributeValue          ::= ANY -- DEFINED BY AttributeType
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_subjectDirAttr(cert_parsing_ctx FD_FN_UNUSED *ctx,
            const uchar *cert, uint off, uint len,
            int critical)
{
  uint hdr_len = 0, data_len = 0, oid_len = 0, remain = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * As specified in section 4.2.1.8. of RFC 5280, conforming CAs
   * MUST mark this extension as non-critical.
   */
  if (critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop assigns ret, buf, remain, hdr_len, data_len, oid_len, off;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop invariant (off + remain) <= UINT_MAX;
    @ loop variant remain;
    @ */
  while (remain) {
    /* Parse current attribute. Each one is a sequence ... */
    ret = parse_id_len(buf, remain,
           CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
           &hdr_len, &data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += hdr_len;
    off += hdr_len;
    remain -= hdr_len;

    /* ... containing an OID (AttributeType) */
    ret = parse_OID(buf, data_len, &oid_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /* FIXME! check the value depanding on the OID */

    remain -= data_len;
    off += data_len;
    buf += data_len;
  }

  ret = 0;

out:
  return ret;
}

/* 4.2.1.9. Basic Constraints
 *
 * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 *
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->bc_critical,
      ctx->ca_true,
      ctx->pathLenConstraint_set;
  @*/
static int parse_ext_basicConstraints(cert_parsing_ctx *ctx,
              const uchar *cert, uint off, uint len,
              int critical)
{
  uint hdr_len = 0, data_len = 0;
  const uchar ca_true_wo_plc[] = { 0x01, 0x01, 0xff };
  const uchar ca_true_w_plc[] = { 0x01, 0x01, 0xff, 0x02, 0x01 };
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* Record if basicConstraints extension was mared critical */
  ctx->bc_critical = critical;

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Only the following cases are valid/reasonable:
   *
   *  1) an empty sequence (cA default to false, resulting in
   *    no pathLenConstraint): { }
   *  2) cA is explicitly set to TRUE and no pathLenConstraint
   *    is enforced. { 0x01, 0x01, 0xff }
   *  3) cA is explicitly set to TRUE and a pathLenConstraint
   *    is enforced, in which case it is reasonable to limit
   *    allowed pathLenConstraint values to [0, 255]:
   *    { 0x01, 0x01, 0xff, 0x02, 0x01, 0xXX }
   *
   * Note:
   *
   *  - encoding an explicit FALSE value for cA is invalid
   *    because this is the default value.
   *  - providing a pathLenConstraint w/o setting cA boolean
   *    does not make sense
   */
  switch (data_len) {
  case 0: /* empty sequence */
    ret = 0;
    break;
  case 3: /* no pathLenConstraint */
    /*
     * We should indeed find a CA TRUE here. If this is
     * the case everything is fine.
     */
    ret = bufs_differ(buf, ca_true_wo_plc, 3);
    if (!ret) {
      ctx->ca_true = 1;
      break;
    }

    /*
     * Here, we should directly leave w/o spending more
     * time except if we were instructed to accept
     * wrongdoing CAs asserting FALSE boolean for CA.
     */
#ifdef TEMPORARY_LAXIST_CA_BASIC_CONSTRAINTS_BOOLEAN_EXPLICIT_FALSE
    {
      const uchar ca_false_explicit_wo_plc[] = { 0x01, 0x01, 0x00 };

      ret = bufs_differ(buf, ca_false_explicit_wo_plc, 3);
      if (!ret) {
        break;
      }
    }
#endif

    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;
  case 6: /* CA set, pathLenConstraint given ([0,127] allowed) */
    ret = bufs_differ(buf, ca_true_w_plc, 5);
    if (ret) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * Section 4.2.1.9 of RFC 5280 has "Where it appears, the
     * pathLenConstraint field MUST be greater than or equal
     * to zero". We check MSB is not set, indicating it is
     * positive.
     */
    if (buf[5] & 0x80) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    ctx->ca_true = 1;
    ctx->pathLenConstraint_set = 1;
    break;
  default: /* crap */
    ret = -X509_FILE_LINE_NUM_ERR;
    break;
  }

out:
  return ret;
}

/* 4.2.1.10. Name Constraints */


/*
 * Parse GeneralSubtrees structure.
 *
 *    GeneralSubtree ::= SEQUENCE {
 *         base                    GeneralName,
 *         minimum         [0]     BaseDistance DEFAULT 0,
 *         maximum         [1]     BaseDistance OPTIONAL }
 *
 *    BaseDistance ::= INTEGER (0..MAX)
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_GeneralSubtrees(const uchar *buf, uint len)
{
  uint hdr_len = 0, remain = 0, grabbed = 0, data_len = 0;
  int ret, unused = 0;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain = data_len;

  /* base is a GeneralName */
  ret = parse_GeneralName(buf, remain, &grabbed, &unused);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += grabbed;
  remain -= grabbed;

  /*
   * Section 4.2.1.10 of RFC5280 has "Within this profile, the minimum
   * and maximum fields are not used with any name forms, thus, the
   * minimum MUST be zero, ...
   *
   * Note: as the minum defaults to 0 in its definition, the field
   * must be absent (i.e. cannot be present with a value of 0),
   * as expected in DER encoding (11.5 of X.690 has: "the encoding of
   * a set value or sequence value shall not include an encoding for
   * any component value which is equal to its default value.)"
   */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
         &hdr_len, &data_len);
  if (!ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* ... and maximum MUST be absent." */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
         &hdr_len, &data_len);
  if (!ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Nothing should remain behind */
  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}


/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_name_constraints;
  @*/
static int parse_ext_nameConstraints(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len, int critical)
{
  uint remain = 0, hdr_len = 0, data_len = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * Section 4.2.1.10 of RFC 5280 has "Conforming CAs MUST mark
   * this extension as critical.
   */
  if (!critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &remain);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;

  /*
   * 4.2.1.10 has: "Conforming CAs MUST NOT issue certificates
   * where name constraints is an empty sequence
   */
  if (!remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check if we have a permittedSubtrees structure */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
         &hdr_len, &data_len);
  if (!ret) {
    buf += hdr_len;
    off += hdr_len;
    remain -= hdr_len;

    ret = parse_GeneralSubtrees(buf, data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += data_len;
    off += data_len;
    remain -= data_len;
  }

  /* Check if we have an excludedSubtrees structure */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
         &hdr_len, &data_len);
  if (!ret) {
    buf += hdr_len;
    off += hdr_len;
    remain -= hdr_len;

    ret = parse_GeneralSubtrees(buf, data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += data_len;
    off += data_len;
    remain -= data_len;
  }

  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->has_name_constraints = 1;

  ret = 0;

out:
  return ret;
}

/*
 * 4.2.1.11. Policy Constraints
 *
 * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
 *
 *  PolicyConstraints ::= SEQUENCE {
 *       requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *       inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 *  SkipCerts ::= INTEGER (0..MAX)
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_policyConstraints(cert_parsing_ctx FD_FN_UNUSED *ctx,
               const uchar *cert, uint off, uint len,
               int critical)
{
  uint data_len = 0, hdr_len = 0, remain = 0, parsed = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * Section 4.2.1.11 of RFC 5280 has "Conforming CAs MUST mark this
   * extension as critical".
   */
  if (!critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's first check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Section 4.2.1.11 of RFC 5280 has "Conforming CAs MUST NOT issue
   * certificates where policy constraints is an empty sequence".
   */
  if (data_len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  /* Check if we have a requireExplicitPolicy */
  ret = parse_integer(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
          &hdr_len, &data_len);
  if (!ret) {
    /*
     * As the value is expected to be a very small integer,
     * content should be encoded on at most 1 byte, i.e.
     * 'parsed' value should be 3 (w/ 2 bytes header).
     */
    parsed = hdr_len + data_len;
    if (parsed != 3) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += parsed;
    off += parsed;
    remain -= parsed;
  }

  /* Check if we have an inhibitPolicyMapping */
  ret = parse_integer(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
          &hdr_len, &data_len);
  if (!ret) {
    /*
     * As the value is expected to be a very small integer,
     * content should be encoded on at most 1 byte, i.e.
     * 'parsed' value should be 3 (w/ 2 bytes header).
     */
    parsed = hdr_len + data_len;
    if (parsed != 3) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += parsed;
    off += parsed;
    remain -= parsed;
  }

  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
       return ret;
}

static const uchar _id_kp_anyEKU[] =       { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x00 };
static const uchar _id_kp_serverAuth[] =   { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x01 };
static const uchar _id_kp_clientAuth[] =   { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x02 };
static const uchar _id_kp_codeSigning[] =  { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x03 };
static const uchar _id_kp_emailProt[] =    { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x04 };
static const uchar _id_kp_timeStamping[] = { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x08 };
static const uchar _id_kp_OCSPSigning[] =  { 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07,
            0x03, 0x09 };
static const uchar _id_kp_ns_SGC[] = {  0x06, 0x09, 0x60, 0x86, 0x48,
             0x01, 0x86, 0xF8, 0x42, 0x04,
             0x01  };
static const uchar _id_kp_ms_SGC[] = {  0x06, 0x0A, 0x2B, 0x06, 0x01,
             0x04, 0x01, 0x82, 0x37, 0x0A,
             0x03, 0x03,   };


typedef struct {
  const uchar *oid;
  uchar oid_len;
} _kp_oid;

static const _kp_oid known_kp_oids[] = {
  { .oid = _id_kp_anyEKU,
    .oid_len = sizeof(_id_kp_anyEKU),
  },
  { .oid = _id_kp_serverAuth,
    .oid_len = sizeof(_id_kp_serverAuth),
  },
  { .oid = _id_kp_clientAuth,
    .oid_len = sizeof(_id_kp_clientAuth),
  },
  { .oid = _id_kp_codeSigning,
    .oid_len = sizeof(_id_kp_codeSigning),
  },
  { .oid = _id_kp_emailProt,
    .oid_len = sizeof(_id_kp_emailProt),
  },
  { .oid = _id_kp_timeStamping,
    .oid_len = sizeof(_id_kp_timeStamping),
  },
  { .oid = _id_kp_OCSPSigning,
    .oid_len = sizeof(_id_kp_OCSPSigning),
  },
  { .oid = _id_kp_ns_SGC,
    .oid_len = sizeof(_id_kp_ns_SGC),
  },
  { .oid = _id_kp_ms_SGC,
    .oid_len = sizeof(_id_kp_ms_SGC),
  },
};

const ushort num_known_kp_oids = (sizeof(known_kp_oids) / sizeof(known_kp_oids[0]));

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < num_known_kp_oids && \result == &known_kp_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _kp_oid * find_kp_by_oid(const uchar *buf, uint len)
{
  const _kp_oid *found = NULL;
  const _kp_oid *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ loop unroll num_known_kp_oids ;
    @ loop invariant 0 <= k <= num_known_kp_oids;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (num_known_kp_oids - k);
    @*/
  for (k = 0; k < num_known_kp_oids; k++) {
    int ret;

    cur = &known_kp_oids[k];

    /*@ assert cur == &known_kp_oids[k];*/
    if (cur->oid_len != len) {
      continue;
    }

    /*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
    ret = !bufs_differ(cur->oid, buf, cur->oid_len);
    if (ret) {
      found = cur;
      break;
    }
  }

out:
  return found;
}

/*
 * 4.2.1.12. Extended Key Usage
 *
 *    id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 *
 *   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 *   KeyPurposeId ::= OBJECT IDENTIFIER
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_eku;
  @*/
static int parse_ext_EKU(cert_parsing_ctx FD_FN_UNUSED *ctx,
       const uchar *cert, uint off, uint len,
       int critical)
{
  uint remain = 0, data_len = 0, hdr_len = 0, oid_len = 0;
  const uchar *buf = cert + off;
  const _kp_oid *kp = NULL;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret || (data_len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Let's now check each individual KeyPurposeId in the sequence */
  /*@
    @ loop assigns ret, oid_len, kp, buf, remain, off;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop invariant (off + remain) <= UINT_MAX;
    @ loop variant remain;
    @ */
  while (remain) {
    ret = parse_OID(buf, remain, &oid_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    kp = find_kp_by_oid(buf, oid_len);
    if (kp == NULL) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * RFC5280 sect 4.2.1.12 contains "Conforming CAs SHOULD NOT
     * mark this extension as critical if the anyExtendedKeyUsage
     * KeyPurposeId is present." We enforce this expected behavior."
     */
    if ((kp->oid == _id_kp_anyEKU) && critical) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += oid_len;
    off += oid_len;
    remain -= oid_len;
  }

  ctx->has_eku = 1;

  ret = 0;

out:
  return ret;
}


/*
 * 4.2.1.13. CRL Distribution Points.
 *
 *     CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 * Note that the Freshest CRL extension uses the exact same syntax and
 * convention as CRLDP extension. The only minor difference is that section
 * 4.2.1.13 has that "The extension SHOULD be non-critical" and section
 * 4.2.1.15 has that "The extension MUST be marked as non-critical by
 * conforming CAs". This is the main difference between the function below
 * and parse_crl_ext_FreshestCRL().
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_crldp,
      ctx->one_crldp_has_all_reasons;
  @*/
static int parse_ext_CRLDP(cert_parsing_ctx *ctx,
         const uchar *cert, uint off, uint len,
         int FD_FN_UNUSED critical)
{
  uint hdr_len = 0, data_len = 0, remain;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len,
         CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain = data_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->has_crldp = 1;
  ctx->one_crldp_has_all_reasons = 0;

  /* Iterate on DistributionPoint */
  /*@
    @ loop assigns ret, buf, remain, ctx->one_crldp_has_all_reasons;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    int crldp_has_all_reasons = 0;
    uint eaten = 0;

    ret = parse_DistributionPoint(buf, remain,
                &crldp_has_all_reasons, &eaten);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    if (crldp_has_all_reasons) {
      ctx->one_crldp_has_all_reasons = 1;
    }

    remain -= eaten;
    buf += eaten;
  }

  ret = 0;

out:
  return ret;
}

/*
 * 4.2.1.14. Inhibit anyPolicy
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
#define MAX_INHIBITANYPOLICY 64
static int parse_ext_inhibitAnyPolicy(cert_parsing_ctx FD_FN_UNUSED *ctx,
              const uchar *cert, uint off, uint len,
              int critical)
{
  const uchar *buf = cert + off;
  uint eaten = 0, hdr_len = 0, data_len = 0;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * 4.2.1.14 of RFC5280 has "Conforming CAs MUST mark this
   * extension as critical".
   */
  if (!critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_integer(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
          &hdr_len, &data_len);
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  eaten = hdr_len + data_len;

  /*
   * We limit SkipCerts values to integers between 0 and
   * MAX_INHIBITANYPOLICY. This implies an encoding on 3 bytes.
   */
  if (eaten != 3) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if ((buf[2] & 0x80) || (buf[2] > MAX_INHIBITANYPOLICY)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (eaten != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/* The OID we will support in final implementation */
static const uchar _ext_oid_AIA[] =               { 0x06, 0x08, 0x2b, 0x06, 0x01,
             0x05, 0x05, 0x07, 0x01, 0x01 };
static const uchar _ext_oid_subjectDirAttr[] =    { 0x06, 0x03, 0x55, 0x1d, 0x09 };
static const uchar _ext_oid_SKI[] =               { 0x06, 0x03, 0x55, 0x1d, 0x0e };
static const uchar _ext_oid_keyUsage[] =          { 0x06, 0x03, 0x55, 0x1d, 0x0f };
static const uchar _ext_oid_SAN[] =               { 0x06, 0x03, 0x55, 0x1d, 0x11 };
static const uchar _ext_oid_IAN[] =               { 0x06, 0x03, 0x55, 0x1d, 0x12 };
static const uchar _ext_oid_basicConstraints[] =  { 0x06, 0x03, 0x55, 0x1d, 0x13 };
static const uchar _ext_oid_nameConstraints[] =   { 0x06, 0x03, 0x55, 0x1d, 0x1e };
static const uchar _ext_oid_CRLDP[] =             { 0x06, 0x03, 0x55, 0x1d, 0x1f };
static const uchar _ext_oid_certPolicies[] =      { 0x06, 0x03, 0x55, 0x1d, 0x20 };
static const uchar _ext_oid_policyMapping[] =     { 0x06, 0x03, 0x55, 0x1d, 0x21 };
static const uchar _ext_oid_AKI[] =               { 0x06, 0x03, 0x55, 0x1d, 0x23 };
static const uchar _ext_oid_policyConstraints[] = { 0x06, 0x03, 0x55, 0x1d, 0x24 };
static const uchar _ext_oid_EKU[] =               { 0x06, 0x03, 0x55, 0x1d, 0x25 };
static const uchar _ext_oid_FreshestCRL[] =       { 0x06, 0x03, 0x55, 0x1d, 0x2e };
static const uchar _ext_oid_inhibitAnyPolicy[] =  { 0x06, 0x03, 0x55, 0x1d, 0x36 };

/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_bad_oid(cert_parsing_ctx FD_FN_UNUSED *ctx,
           const uchar *cert, uint FD_FN_UNUSED off, uint len,
           int FD_FN_UNUSED critical)
{
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

#ifdef TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
/*
 * Some common OID for which we DO NOT CURRENTLY support data parsing but may
 * include for tests only to progress in certificates and improve code coverage
 */
static const uchar _ext_oid_bad_ct1[] = {
  0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
  0x01, 0x01
};
static const uchar _ext_oid_bad_ct_poison[] = {
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6,
  0x79, 0x02, 0x04, 0x03
};
static const uchar _ext_oid_bad_ct_enabled[] = {
  0x06, 0x0a, 0x2b, 0x06,   0x01, 0x04, 0x01, 0xd6,
  0x79, 0x02, 0x04, 0x02
};
static const uchar _ext_oid_bad_ns_cert_type[] = {
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
  0x42, 0x01, 0x01
};
static const uchar _ext_oid_bad_szOID_ENROLL[] = {
  0x06, 0x09, 0x2b, 0x06,  0x01, 0x04, 0x01, 0x82,
  0x37, 0x14, 0x02
};
static const uchar _ext_oid_bad_smime_cap[] = {
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x09, 0x0f
};
static const uchar _ext_oid_bad_ns_comment[] = {
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
  0x42, 0x01, 0x0d
};
static const uchar _ext_oid_bad_deprecated_AKI[] = {
  0x06, 0x03, 0x55, 0x1d, 0x01
};
static const uchar _ext_oid_bad_szOID_CERT_TEMPLATE[] = {
  0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
  0x37, 0x15, 0x07
};
static const uchar _ext_oid_bad_pkixFixes[] = {
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97,
  0x55, 0x03, 0x01, 0x05
};
static const uchar _ext_oid_bad_ns_ca_policy_url[] = {
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
  0x42, 0x01, 0x08
};
static const uchar _ext_oid_bad_szOID_CERTSRV_CA_VERS[] = {
  0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
  0x37, 0x15, 0x01
};
static const uchar _ext_oid_bad_szOID_APP_CERT_POL[] = {
  0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
  0x37, 0x15, 0x0a
};
static const uchar _ext_oid_bad_priv_key_usage_period[] = {
  0x06, 0x03, 0x55, 0x1d, 0x10
};
static const uchar _ext_oid_bad_subject_signing_tool[] = {
  0x06, 0x05, 0x2a, 0x85,  0x03, 0x64, 0x6f
};
static const uchar _ext_oid_bad_issuer_signing_tool[] = {
  0x06, 0x05, 0x2a, 0x85,  0x03, 0x64, 0x70
};
static const uchar _ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH[] = {
  0x06, 0x09, 0x2b, 0x06,  0x01, 0x04, 0x01,
  0x82, 0x37, 0x15, 0x02
};
#endif

typedef struct {
  const uchar *oid;
  uint oid_len;
  int (*parse_ext_params)(cert_parsing_ctx *ctx,
        const uchar *cert, uint off, uint len, int critical);
} _ext_oid;

static const _ext_oid generic_unsupported_ext_oid = {
  .oid = NULL,
  .oid_len = 0,
  .parse_ext_params = parse_ext_bad_oid
};

static const _ext_oid known_ext_oids[] = {
  { .oid = _ext_oid_AIA,
    .oid_len = sizeof(_ext_oid_AIA),
    .parse_ext_params = parse_ext_AIA,
  },
  { .oid = _ext_oid_AKI,
    .oid_len = sizeof(_ext_oid_AKI),
    .parse_ext_params = parse_ext_AKI,
  },
  { .oid = _ext_oid_SKI,
    .oid_len = sizeof(_ext_oid_SKI),
    .parse_ext_params = parse_ext_SKI,
  },
  { .oid = _ext_oid_keyUsage,
    .oid_len = sizeof(_ext_oid_keyUsage),
    .parse_ext_params = parse_ext_keyUsage,
  },
  { .oid = _ext_oid_certPolicies,
    .oid_len = sizeof(_ext_oid_certPolicies),
    .parse_ext_params = parse_ext_certPolicies,
  },
  { .oid = _ext_oid_policyMapping,
    .oid_len = sizeof(_ext_oid_policyMapping),
    .parse_ext_params = parse_ext_policyMapping,
  },
  { .oid = _ext_oid_SAN,
    .oid_len = sizeof(_ext_oid_SAN),
    .parse_ext_params = parse_ext_SAN,
  },
  { .oid = _ext_oid_IAN,
    .oid_len = sizeof(_ext_oid_IAN),
    .parse_ext_params = parse_ext_IAN,
  },
  { .oid = _ext_oid_subjectDirAttr,
    .oid_len = sizeof(_ext_oid_subjectDirAttr),
    .parse_ext_params = parse_ext_subjectDirAttr,
  },
  { .oid = _ext_oid_basicConstraints,
    .oid_len = sizeof(_ext_oid_basicConstraints),
    .parse_ext_params = parse_ext_basicConstraints,
  },
  { .oid = _ext_oid_nameConstraints,
    .oid_len = sizeof(_ext_oid_nameConstraints),
    .parse_ext_params = parse_ext_nameConstraints,
  },
  { .oid = _ext_oid_policyConstraints,
    .oid_len = sizeof(_ext_oid_policyConstraints),
    .parse_ext_params = parse_ext_policyConstraints,
  },
  { .oid = _ext_oid_EKU,
    .oid_len = sizeof(_ext_oid_EKU),
    .parse_ext_params = parse_ext_EKU,
  },
  { .oid = _ext_oid_CRLDP,
    .oid_len = sizeof(_ext_oid_CRLDP),
    .parse_ext_params = parse_ext_CRLDP,
  },
  { .oid = _ext_oid_inhibitAnyPolicy,
    .oid_len = sizeof(_ext_oid_inhibitAnyPolicy),
    .parse_ext_params = parse_ext_inhibitAnyPolicy,
  },
  { .oid = _ext_oid_FreshestCRL,
    .oid_len = sizeof(_ext_oid_FreshestCRL),
    .parse_ext_params = parse_ext_CRLDP,
  },
#ifdef TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
  { .oid = _ext_oid_bad_ct1,
    .oid_len = sizeof(_ext_oid_bad_ct1),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_ct_poison,
    .oid_len = sizeof(_ext_oid_bad_ct_poison),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_ct_enabled,
    .oid_len = sizeof(_ext_oid_bad_ct_enabled),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_ns_cert_type,
    .oid_len = sizeof(_ext_oid_bad_ns_cert_type),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_szOID_ENROLL,
    .oid_len = sizeof(_ext_oid_bad_szOID_ENROLL),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_smime_cap,
    .oid_len = sizeof(_ext_oid_bad_smime_cap),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_ns_comment,
    .oid_len = sizeof(_ext_oid_bad_ns_comment),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_deprecated_AKI,
    .oid_len = sizeof(_ext_oid_bad_deprecated_AKI),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_szOID_CERT_TEMPLATE,
    .oid_len = sizeof(_ext_oid_bad_szOID_CERT_TEMPLATE),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_pkixFixes,
    .oid_len = sizeof(_ext_oid_bad_pkixFixes),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_ns_ca_policy_url,
    .oid_len = sizeof(_ext_oid_bad_ns_ca_policy_url),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_szOID_CERTSRV_CA_VERS,
    .oid_len = sizeof(_ext_oid_bad_szOID_CERTSRV_CA_VERS),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_szOID_APP_CERT_POL,
    .oid_len = sizeof(_ext_oid_bad_szOID_APP_CERT_POL),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_priv_key_usage_period,
    .oid_len = sizeof(_ext_oid_bad_priv_key_usage_period),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_subject_signing_tool,
    .oid_len = sizeof(_ext_oid_bad_subject_signing_tool),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_issuer_signing_tool,
    .oid_len = sizeof(_ext_oid_bad_issuer_signing_tool),
    .parse_ext_params = parse_ext_bad_oid,
  },
  { .oid = _ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH,
    .oid_len = sizeof(_ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH),
    .parse_ext_params = parse_ext_bad_oid,
  },
#endif
};

#define NUM_KNOWN_EXT_OIDS (sizeof(known_ext_oids) / sizeof(known_ext_oids[0]))

/*
 * We limit the amount of extensions we accept per certificate. This can be
 * done because each kind of extension is allowed to appear only once in a
 * given certificate. Note that it is logical to allow
 */
#define MAX_EXT_NUM_PER_CERT NUM_KNOWN_EXT_OIDS

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_EXT_OIDS && \result == &known_ext_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _ext_oid const * find_ext_by_oid(const uchar *buf, uint len)
{
  const _ext_oid *found = NULL;
  const _ext_oid *cur = NULL;
  ushort k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ loop unroll NUM_KNOWN_EXT_OIDS ;
    @ loop invariant 0 <= k <= NUM_KNOWN_EXT_OIDS;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (NUM_KNOWN_EXT_OIDS - k);
    @*/
  for (k = 0; k < NUM_KNOWN_EXT_OIDS; k++) {
    int ret;

    cur = &known_ext_oids[k];

    /*@ assert cur == &known_ext_oids[k];*/
    if (cur->oid_len != len) {
      continue;
    }

    /*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
    ret = !bufs_differ(cur->oid, buf, cur->oid_len);
    if (ret) {
      found = cur;
      break;
    }
  }

out:
  return found;
}

/*@
  @ requires ext != \null;
  @ requires (parsed_oid_list != NULL) ==> \valid(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \separated(ext, parsed_oid_list);
  @
  @ ensures \result <= 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
  @*/
static int check_record_ext_unknown(const _ext_oid *ext,
            const _ext_oid **parsed_oid_list)
{
  ushort pos = 0;
  int ret;

  /*@
    @ loop invariant pos <= MAX_EXT_NUM_PER_CERT;
    @ loop assigns ret, pos, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
    @ loop variant MAX_EXT_NUM_PER_CERT - pos;
    @*/
  while (pos < MAX_EXT_NUM_PER_CERT) {
    /*
     * Check if we are at the end of already seen extensions. In
     * that case, record the extension as a new one.
     */
    if (parsed_oid_list[pos] == NULL) {
      parsed_oid_list[pos] = ext;
      break;
    }

    if (ext == parsed_oid_list[pos]) {
      ret = -X509_FILE_LINE_NUM_ERR;
      goto out;
    }

    pos = (ushort)( pos+1 );
  }

  /*
   * If we went to the end of our array, this means there are too many
   * extensions in the certificate.
   */
  if (pos >= MAX_EXT_NUM_PER_CERT) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Parse one extension.
 *
 *  Extension  ::=  SEQUENCE  {
 *       extnID      OBJECT IDENTIFIER,
 *       critical    BOOLEAN DEFAULT FALSE,
 *       extnValue   OCTET STRING
 *                   -- contains the DER encoding of an ASN.1 value
 *                   -- corresponding to the extension type identified
 *                   -- by extnID
 *       }
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires (parsed_oid_list != NULL) ==> \valid(parsed_oid_list);
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \separated(ctx, cert+(..),parsed_oid_list,eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)], *eaten, *ctx;
  @*/
static int parse_x509_cert_Extension(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len,
             const _ext_oid **parsed_oid_list,
             uint *eaten)
{
  uint data_len = 0, hdr_len = 0, remain = 0;
  uint ext_hdr_len = 0, ext_data_len = 0, oid_len = 0;
  uint saved_ext_len = 0, parsed = 0;
  const uchar *buf = cert + off;
  const _ext_oid *ext = NULL;
  int critical = 0;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

  remain = len;

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, remain,
         CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &ext_hdr_len, &ext_data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += ext_hdr_len;
  off += ext_hdr_len;
  remain -= ext_hdr_len;
  saved_ext_len = ext_hdr_len + ext_data_len;

  /*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

  /*
   * Let's parse the OID and then check if we have
   * an associated handler for that extension.
   */
  ret = parse_OID(buf, ext_data_len, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

  ext = find_ext_by_oid(buf, oid_len);
  if (ext == NULL) {
#ifndef TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
#else
    ext = &generic_unsupported_ext_oid;
#endif
  }

  /*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

  /*
   * There is no efficient way to support check of duplicate OID for
   * extension we do not known, i.e. if
   * TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS has been enabled
   * _and_ we end up on an unsupported OID, we just skip duplicate
   * check, as documented.
   */
  if (ext != &generic_unsupported_ext_oid) {
    /*
     * Now that we know the OID is one we support, we verify
     * this is the first time we handle an instance of this
     * type. Having multiple instances of a given extension
     * in a certificate is forbidden by both section 4.2 of
     * RFC5280 and section 8 of X.509, w/ respectively
     *
     * - "A certificate MUST NOT include more than one
     *    instance of a particular extension."
     * - "For all certificate extensions, CRL extensions,
     *    and CRL entry extensions defined in this Directory
     *    Specification, there shall be no more than one
     *    instance of each extension type in any certificate,
     *    CRL, or CRL entry, respectively."
     *
     * This is done by recording for each extension we
     * processed the pointer to its vtable and compare
     * it with current one.
     */
    ret = check_record_ext_unknown(ext, parsed_oid_list);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  buf += oid_len;
  off += oid_len;
  ext_data_len -= oid_len;

  /*
   * Now that we got the OID, let's check critical
   * field value if present. It's a boolean
   * defaulting to FALSE (in which case, it is absent).
   * We could parse it as an integer but that
   * would be a lot of work for three simple bytes.
   */
  ret = parse_boolean(buf, ext_data_len, &parsed);
  if (ret) {
    /*
     * parse_boolean() returned an error which means this
     * was either a boolean with invalid content or
     * something else. If this was indeed a boolean, we can
     * just leave. Otherwise, this just measn the critical
     * flag was missing and the default value (false) applies,
     * in which case, we can continue parsing.
     */
    if (ext_data_len && (buf[0] == ASN1_TYPE_BOOLEAN)) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  } else {
    /*
     * We now know it's a valid BOOLEAN, *but* in our
     * case (DER), the DEFAULT FALSE means we cannot
     * accept an encoded value of FALSE. Note that we
     * sanity check the value we expect for the length
     */
    if (parsed != 3) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

#ifndef TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE
    if (buf[2] == 0x00) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
#endif

    /*
     * We now know the BOOLEAN is present and has
     * a value of TRUE. Record that.
     */
    critical = 1;

    buf += parsed;
    off += parsed;
    ext_data_len -= parsed;
  }

  /*
   * We should now be in front of the octet string
   * containing the extnValue.
   */
  ret = parse_id_len(buf, ext_data_len,
         CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  off += hdr_len;
  ext_data_len -= hdr_len;

  /* Check nothing remains behind the extnValue */
  if (data_len != ext_data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Parse the parameters for that extension */
  /*@ assert ext->parse_ext_params \in {
      parse_ext_AIA, parse_ext_AKI,
      parse_ext_SKI, parse_ext_keyUsage,
      parse_ext_certPolicies, parse_ext_policyMapping,
      parse_ext_SAN, parse_ext_IAN, parse_ext_subjectDirAttr,
      parse_ext_basicConstraints, parse_ext_nameConstraints,
      parse_ext_policyConstraints, parse_ext_EKU,
      parse_ext_CRLDP, parse_ext_inhibitAnyPolicy,
      parse_ext_bad_oid }; @*/
  /*@ calls parse_ext_AIA, parse_ext_AKI,
      parse_ext_SKI, parse_ext_keyUsage,
      parse_ext_certPolicies, parse_ext_policyMapping,
      parse_ext_SAN, parse_ext_IAN,
      parse_ext_subjectDirAttr, parse_ext_basicConstraints,
      parse_ext_nameConstraints, parse_ext_policyConstraints,
      parse_ext_EKU, parse_ext_CRLDP,
      parse_ext_inhibitAnyPolicy, parse_ext_bad_oid ; @*/
  ret = ext->parse_ext_params(ctx, cert, off, ext_data_len, critical);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = saved_ext_len;
  ret = 0;

out:
  return ret;
}



/*
 * Parse X.509 extensions.
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *
 *       ...
 *
 *       extensions      [3]  EXPLICIT Extensions OPTIONAL
 *  }
 *
 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(eaten, ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_cert_Extensions(cert_parsing_ctx *ctx,
              const uchar *cert, uint off, uint len,
              uint *eaten)
{
  uint data_len = 0, hdr_len = 0, remain = 0;
  const uchar *buf = cert + off;
  uint saved_len = 0;
  const _ext_oid *parsed_oid_list[MAX_EXT_NUM_PER_CERT];
  int ret;
  ushort i;

  if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * Extensions in X.509 v3 certificates is an EXPLICITLY tagged
   * sequence.
   */
  ret = parse_explicit_id_len(buf, len, 3,
            CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
            &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = data_len;
  buf += hdr_len;
  off += hdr_len;
  /*@ assert \valid_read(buf + (0 .. (remain - 1))); */

  saved_len = hdr_len + data_len;
  /*@ assert saved_len <= len; */
  /*@ assert data_len <= saved_len; */

  /* If present, it must contain at least one extension */
  if (data_len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Initialize list of already seen extensions */
  /*@ loop unroll MAX_EXT_NUM_PER_CERT;
    @ loop assigns i, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
    @ loop invariant (i < MAX_EXT_NUM_PER_CERT) ==> \valid(&parsed_oid_list[i]);
    @ loop variant (MAX_EXT_NUM_PER_CERT - i);
    @*/
  for (i = 0; i < MAX_EXT_NUM_PER_CERT; i++) {
    parsed_oid_list[i] = NULL;
  }
  /*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

  /* Now, let's work on each extension in the sequence */
  /*@
    @ loop assigns off, ret, buf, remain, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)], *ctx;
    @ loop invariant (remain != 0) ==> \valid_read(cert + (off .. (off + remain - 1)));
    @ loop invariant (remain != 0) ==> off + remain <= UINT_MAX;
    @ loop variant remain;
    @*/
  while (remain) {
    uint ext_len = 0;

    ret = parse_x509_cert_Extension(ctx, cert, off, remain,
            parsed_oid_list, &ext_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= ext_len;
    buf += ext_len;
    off += ext_len;
  }

  /*
   * RFC5280 has "If the subject field contains an empty sequence,
   * then the issuing CA MUST include a subjectAltName extension
   * that is marked as critical."
   */
  if (ctx->empty_subject) {
    if (!ctx->has_san) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    if (!ctx->san_critical) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  /*@ assert 1 <= saved_len <= len; */
  *eaten = saved_len;

  ret = 0;

out:
  return ret;
}

/*
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *  version    [0]  EXPLICIT Version DEFAULT v1,
 *  serialNumber       CertificateSerialNumber,
 *  signature       AlgorithmIdentifier,
 *  issuer         Name,
 *  validity       Validity,
 *  subject         Name,
 *  subjectPublicKeyInfo SubjectPublicKeyInfo,
 *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *           -- If present, version MUST be v2 or v3
 *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *           -- If present, version MUST be v2 or v3
 *  extensions  [3]  EXPLICIT Extensions OPTIONAL
 *           -- If present, version MUST be v3
 *  }
 *
 * On success, the function returns the size of the tbsCertificate
 * structure in 'eaten' parameter. It also provides in 'sig_alg'
 * a pointer to the signature algorithm found in the signature field.
 * This one is provided to be able to check later against the signature
 * algorithm found in the signatureAlgorithm field of the certificate.
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(sig_alg, eaten, cert+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start < off + *eaten;
  @
  @ assigns *eaten, *ctx, *sig_alg;
  @*/
static int parse_x509_tbsCertificate(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len,
             const _sig_alg **sig_alg, uint *eaten)
{
  uint tbs_data_len = 0;
  uint tbs_hdr_len = 0;
  uint tbs_cert_len = 0;
  uint remain = 0;
  uint parsed = 0;
  uint cur_off = off;
  const uchar *buf = cert + cur_off;
  const uchar *subject_ptr, *issuer_ptr;
  uint subject_len, issuer_len;
  const _sig_alg *alg = NULL;
  int ret, empty_issuer = 1;

  if ((ctx == NULL) || (cert == NULL) || (len == 0) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * Let's first check we are dealing with a valid sequence containing
   * all the elements of the certificate.
   */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &tbs_hdr_len, &tbs_data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  tbs_cert_len = tbs_hdr_len + tbs_data_len;
  buf += tbs_hdr_len;
  cur_off += tbs_hdr_len;
  remain = tbs_data_len;

  /*
   * Now, we can start and parse all the elements in the sequence
   * one by one.
   */

  /* version */
  ret = parse_x509_cert_Version(cert, cur_off, remain, &ctx->version, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* serialNumber */
  ret = parse_CertSerialNumber(ctx, cert, cur_off, remain,
             CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
             &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (ctx->version != 0x02) {
    ret = X509_PARSER_ERROR_VERSION_NOT_3;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* signature */
  ret = parse_x509_tbsCert_sig_AlgorithmIdentifier(ctx, cert, cur_off, remain,
               &alg, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert \initialized(&(ctx->tbs_sig_alg_start)); */
  /*@ assert ctx->tbs_sig_alg_start == cur_off; */
  /*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */
  /*@ assert \initialized(&(ctx->tbs_sig_alg_len)); */
  /*@ assert \initialized(&(ctx->sig_alg)); */

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* issuer */
  ret = parse_x509_Name(buf, remain, &parsed, &empty_issuer);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  ctx->issuer_start = cur_off;
  ctx->issuer_len = parsed;

  /*
   * As described in section 4.1.2.4 of RFC 5280, "The issuer field MUST
   * contain a non-empty distinguished name (DN)".
   */
  /*@ assert (empty_issuer == 0) || (empty_issuer == 1); */
  if (empty_issuer) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  issuer_ptr = buf;
  issuer_len = parsed;

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* validity */
  ret = parse_x509_Validity(ctx, cert, cur_off, remain, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* subject */
  ret = parse_x509_Name(buf, remain, &parsed, &ctx->empty_subject);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->subject_start = cur_off;
  ctx->subject_len = parsed;

  subject_ptr = buf;
  subject_len = parsed;

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /* We can now check if subject and issuer fields are identical */
  ctx->subject_issuer_identical = 0;
  if (subject_len == issuer_len) {
    ctx->subject_issuer_identical = !bufs_differ(subject_ptr,
                   issuer_ptr,
                   issuer_len);
  }

  /* subjectPublicKeyInfo */
  ret = parse_x509_subjectPublicKeyInfo(ctx, cert, cur_off, remain, &parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

  buf += parsed;
  cur_off += parsed;
  remain -= parsed;

  /*
   * At that point, the remainder of the tbsCertificate part
   * is made of 3 *optional* elements:
   *
   *     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
   *     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
   *     extensions      [3]  EXPLICIT Extensions OPTIONAL
   *
   *  w/ UniqueIdentifier  ::=  BIT STRING
   *     Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
   *
   * Section 4.1.2.8 of RFC 5280 explicitly states that "CAs
   * conforming to this profile MUST NOT generate certificates
   * with unique identifier" but "Applications conforming to
   * this profile SHOULD be capable of parsing certificates
   * that include unique identifiers, but there are no processing
   * requirements associated with the unique identifiers."
   *
   * Additionnally, some tests performed on 9826768 (of 18822321)
   * certificates that validate in a 2011 TLS campaign, we do not
   * have any certificate w/ either a subjectUniqueID or
   * issuerUniqueID.
   *
   * For that reason, in order to simplify parsing, we expect NOT
   * to find either a subject or issuer unique identifier and to
   * directly find extensions, if any. This is done by checking if
   * data remain at that point. If that is the case, we perform
   * a full parsing of the Extensions.
   */
  if (remain) {
    ret = parse_x509_cert_Extensions(ctx, cert, cur_off, remain,
             &parsed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += parsed;
    cur_off += parsed;
    remain -= parsed;
  }

  /*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

  if (remain != 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * RFC 5280 requires that SKI extension "MUST appear in all conforming
   * CA certificates, that is, all certificates including the basic
   * constraints extension (Section 4.2.1.9) where the value of cA is
   * TRUE"
   */
#ifndef TEMPORARY_LAXIST_CA_WO_SKI
  if (ctx->ca_true && !ctx->has_ski) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
#endif

  /*
   * RFC 5280 has "If the keyCertSign bit is asserted, then the cA bit in
   * the basic constraints extension (Section 4.2.1.9) MUST also be
   * asserted.
   *
   * It also has the following regarding basicConstraints extension:
   * "Conforming CAs MUST include this extension in all CA certificates
   * that contain public keys used to validate digital signatures on
   * certificates and MUST mark the extension as critical in such
   * certificates."
   *
   * Note that we do not enforce basicConstraints criticality otherwise
   * as required by "This extension MAY appear as a critical or
   * non-critical extension in CA certificates that contain public keys
   * used exclusively for purposes other than validating digital
   * signatures on certificates. This extension MAY appear as a critical
   * or non-critical extension in end entity certificates."
   */
  if (ctx->keyCertSign_set && (!ctx->ca_true || !ctx->bc_critical)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * If the subject is a CRL issuer (e.g., the key usage extension, as
   * discussed in Section 4.2.1.3, is present and the value of cRLSign is
   * TRUE), then the subject field MUST be populated with a non-empty
   * distinguished name matching the contents of the issuer field (Section
   * 5.1.2.3) in all CRLs issued by the subject CRL issuer.
   */
  if (ctx->cRLSign_set && ctx->empty_subject) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * RFC5280 has "CAs MUST NOT include the pathLenConstraint field
   * unless the cA boolean is asserted and the key usage extension
   * asserts the keyCertSign bit."
   */
  if (ctx->pathLenConstraint_set &&
      (!ctx->ca_true || !ctx->keyCertSign_set)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

       /*
  * RFC5280 has "The name constraints extension, which MUST be used only
  * in a CA certificate, ..."
  */
  if (ctx->has_name_constraints && !ctx->ca_true) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

       /*
  * RFC5280 has "When a conforming CA includes a cRLDistributionPoints
  * extension in a certificate, it MUST include at least one
  * DistributionPoint that points to a CRL that covers the certificate
  * for all reasons."
  */
  if (ctx->ca_true && ctx->has_crldp && !ctx->one_crldp_has_all_reasons) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */
  /*@ assert 1 < tbs_cert_len <= len; */
  *eaten = tbs_cert_len;
  /*@ assert ctx->tbs_sig_alg_start < off + *eaten; */
  *sig_alg = alg;

  ret = 0;

out:
  return ret;
}

/*
 * The function is used to parse signatureAlgorithm field found after the
 * tbsCertificate and before the signature. As the field is expected
 * to exactly match the tbsCertificate.signature field which has already
 * been fully parsed and validated, we only verify here that the element
 * to parse is identical to previously parsed tbsCertificate.signature
 * using the pointers in the context.
 */
/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (0 .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \initialized(&(ctx->tbs_sig_alg_start));
  @ requires \initialized(&(ctx->tbs_sig_alg_len));
  @ requires ctx->tbs_sig_alg_start <= off;
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten,
      ctx->sig_alg_start,
      ctx->sig_alg_len;
  @*/
static int parse_x509_signatureAlgorithm(cert_parsing_ctx *ctx,
           const uchar *cert, uint off, uint len,
           uint *eaten)
{
  uint prev_len;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  prev_len = ctx->tbs_sig_alg_len;
  if (prev_len > len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = bufs_differ(cert + ctx->tbs_sig_alg_start, cert + off, prev_len);
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  ctx->sig_alg_start = off;
  ctx->sig_alg_len = prev_len;

  *eaten = prev_len;

  ret = 0;

out:
  return ret;
}



/*@
  @ requires ((u64)off + (u64)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (sig_alg != \null) ==> \valid_read(sig_alg) && \valid_function(sig_alg->parse_sig);
  @ requires (\initialized(&ctx->sig_alg));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..), sig_alg, eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_signatureValue(cert_parsing_ctx *ctx,
             const uchar *cert, uint off, uint len,
             const _sig_alg *sig_alg, uint *eaten)
{
  uint saved_off = off;
  sig_params *params;
  int ret;

  if ((cert == NULL) || (len == 0) || (sig_alg == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (sig_alg->parse_sig == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  params = &(ctx->sig_alg_params);
  /*@ assert \valid(params); */

  /*@ assert sig_alg->parse_sig \in {
      parse_sig_ed448,
      parse_sig_ed25519 }; @*/
  /*@ calls parse_sig_ed25519; @*/
  ret = sig_alg->parse_sig(params, cert, off, len, eaten);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ctx->sig_start = saved_off;
  ctx->sig_len = *eaten;
  ret = 0;

out:
  return ret;
}

/*
 * The goal being to zeroify all the fields of a given structure (not a buffer)
 * using a function, we did not manage to do that using memset() in Typed memory
 * model and at the same time validate assigns clause. I tried and reimplement
 * a specific function but conversion of the structure to a buffer to initialize
 * one by one all the bytes of the structure result in an inability to validate
 * assigns clause for the structure in the function. A good amount of time was
 * spent on annotations strategies w/o success.
 *
 * Until one finds a better solution, a decent workaround has been found with
 * the following function, which internally declares a structure with a static
 * initializer and returns that (zeroized) structure by value. In a caller, the
 * variable to be zeroized can just be overridden with the result of the
 * function. This is not generic but sufficient for the need we have in the
 * parser.
 */
/*@
  @ assigns \nothing;
  @*/
static cert_parsing_ctx get_zeroized_cert_ctx_val(void)
{
  cert_parsing_ctx zeroized_ctx = { 0 };

  return zeroized_ctx;
}

/*@
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (0 .. (len - 1)));
  @ requires (ctx != NULL) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *ctx;
  @*/
int parse_x509_cert(cert_parsing_ctx *ctx, const uchar *cert, uint len)
{
  uint seq_data_len = 0;
  uint eaten = 0;
  uint off = 0;
  const _sig_alg *sig_alg = NULL;
  int ret;

  if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *ctx = get_zeroized_cert_ctx_val();

  /*
   * Parse beginning of buffer to verify it's a sequence and get
   * the length of the data it contains.
   */
  ret = parse_id_len(cert, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &eaten, &seq_data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= eaten;
  off += eaten;
  /*@ assert off + len <= UINT_MAX; */

  /*
   * We do expect advertised length to match what now remains in buffer
   * after the sequence header we just parsed.
   */
  if (seq_data_len != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Parse first element of the sequence: tbsCertificate */
  ret = parse_x509_tbsCertificate(ctx, cert, off, len, &sig_alg, &eaten);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \initialized(&(ctx->sig_alg)); */
  /*@ assert ctx->tbs_sig_alg_start < off + eaten; */

  ctx->tbs_start = off;
  ctx->tbs_len = eaten;

  len -= eaten;
  off += eaten;

  /*@ assert ctx->tbs_sig_alg_start <= off; */

  /* Parse second element of the sequence: signatureAlgorithm */
  ret = parse_x509_signatureAlgorithm(ctx, cert, off, len, &eaten);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \initialized(&(ctx->sig_alg)); */

  len -= eaten;
  off += eaten;

  /* Parse second element of the sequence: signatureValue */
  ret = parse_x509_signatureValue(ctx, cert, off, len, sig_alg, &eaten);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check there is nothing left behind */
  if (len != eaten) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}
