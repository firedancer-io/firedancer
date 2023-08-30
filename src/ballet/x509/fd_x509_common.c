/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */

#include "fd_x509_common.h"

#define X509_FILE_NUM 3 /* See x509-utils.h for rationale */

/********************************************************************
 * Hash algs
 ********************************************************************/

#define DECL_HASH_ALG(TTalg, UUname, VVoid, WWoidbuf, XXtype) \
static const uchar _##TTalg##_hash_name[] = UUname;             \
static const uchar _##TTalg##_hash_printable_oid[] = VVoid;     \
static const uchar _##TTalg##_hash_der_oid[] = WWoidbuf;        \
                   \
static const _hash_alg _##TTalg##_hash_alg = {               \
  .alg_name = _##TTalg##_hash_name,                    \
  .alg_printable_oid = _##TTalg##_hash_printable_oid,  \
  .alg_der_oid = _##TTalg##_hash_der_oid,              \
  .alg_der_oid_len = sizeof(_##TTalg##_hash_der_oid),  \
  .hash_id = (XXtype),             \
}

/* M-x toggle-truncate-lines is your friend here ;-) */
DECL_HASH_ALG(sha512, "SHA512", "2.16.840.1.101.3.4.2.3", P99_PROTECT({ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 }), HASH_ALG_SHA512);

const _hash_alg *known_hashes[] = {
  &_sha512_hash_alg,
};

#define NUM_KNOWN_HASHES (sizeof(known_hashes) / sizeof(known_hashes[0]))





/********************************************************************
 * Elliptic curves
 ********************************************************************/

#define DECL_CURVE(TTcurve, UUname, VVoid, WWoidbuf, XXtype, YYbitlen)    \
static const uchar _##TTcurve##_curve_name[] = UUname;                       \
static const uchar _##TTcurve##_curve_printable_oid[] = VVoid;               \
static const uchar _##TTcurve##_curve_der_oid[] = WWoidbuf;                  \
                    \
static const _curve _curve_##TTcurve = {                                  \
  .crv_name = _##TTcurve##_curve_name,                              \
  .crv_printable_oid = _##TTcurve##_curve_printable_oid,            \
  .crv_der_oid = _##TTcurve##_curve_der_oid,                        \
  .crv_der_oid_len = sizeof(_##TTcurve##_curve_der_oid),            \
  .crv_order_bit_len = (YYbitlen),          \
  .crv_id = (XXtype),              \
}

/* M-x toggle-truncate-lines is your friend here ;-) */
DECL_CURVE(Curve25519, "Curve25519", "1.3.6.1.4.1.11591.15.1", P99_PROTECT({ 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 }), CURVE_WEI25519, 256);

const _curve *known_curves[] = {
  &_curve_Curve25519,
};

#define NUM_KNOWN_CURVES (sizeof(known_curves) / sizeof(known_curves[0]))





/********************************************************************
 * Signature algs
 ********************************************************************/

#define DECL_SIG_ALG(TTalg, SSsig, HHhash, YYparse_sig, ZZparse_algoid, UUname, VVoid, WWoidbuf) \
static const uchar _##TTalg##_sig_name[] = UUname;             \
static const uchar _##TTalg##_sig_printable_oid[] = VVoid;     \
static const uchar _##TTalg##_sig_der_oid[] = WWoidbuf;        \
                  \
static const _sig_alg _##TTalg##_sig_alg = {                \
  .alg_name = _##TTalg##_sig_name,                    \
  .alg_printable_oid = _##TTalg##_sig_printable_oid,  \
  .alg_der_oid = _##TTalg##_sig_der_oid,              \
  .alg_der_oid_len = sizeof(_##TTalg##_sig_der_oid),  \
  .sig_id = (SSsig),            \
  .hash_id = (HHhash),            \
  .parse_sig = (YYparse_sig),          \
  .parse_algoid_sig_params = (ZZparse_algoid),      \
}

/* M-x toggle-truncate-lines is your friend here ;-) */

/*
 *-----------------------------------+---------------------------+----------------------+-------------------------+---------------------------------------------+-----------------------------------------------+-----------------------------+----------------------...
 *           struct name             | signature alg             | hash alg if known    | sig parsing func        | sig algs params parsing func                | pretty name for sig alg                       | printable OID               | OID in DER format
 *-----------------------------------+---------------------------+----------------------+-------------------------+---------------------------------------------+-----------------------------------------------+-----------------------------+----------------------...
 */
DECL_SIG_ALG(ed25519                 , SIG_ALG_ED25519           , HASH_ALG_SHA512      , parse_sig_ed25519       , parse_algoid_sig_params_eddsa               , "Ed25519"                                     , "1.3.101.112"               , P99_PROTECT({ 0x06, 0x03, 0x2b, 0x65, 0x70 }));

const _sig_alg *known_sig_algs[] = {
  &_ed25519_sig_alg,
};

const ushort num_known_sig_algs = (sizeof(known_sig_algs) / sizeof(known_sig_algs[0]));





/*
 * Some implementation notes:
 *
 * The implementation is based on X.690 and X.680 (both 07/2002). It is
 * voluntarily limited to parsing a buffer of small size (no more than
 * ASN1_MAX_BUFFER_SIZE bytes long) containing a DER encoded ASN.1
 * structure.
 *
 */


/*
 * Helper for ASN.1 DER identifier field parsing, which extracts the tag number
 * when it is not encoded on a single byte, i.e. when the first encountered byte
 * for the field is 0x1f. The function takes as parameter the buffer following
 * this 0x1f byte and, upon success, extracts the tag value.
 *
 * In our implementation, tag numbers are limited by the return type used for
 * the parameter (32 bit unsigned integers). In practice we allow tag encoded
 * on 4 bytes, i.e. with a final value of 4 * 7 bits, i.e. 28 bits. This is
 * considered largely sufficient in the context of X.509 certificates (which is
 * validated by our tests).
 *
 * Note that the function does verify that extracted tag is indeed >= 0x1f.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (tag_num != NULL) ==> \valid(tag_num);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(tag_num, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> 1 <= *eaten <= len;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten > 0);
  @
  @ assigns *tag_num, *eaten;
  @*/
static int _extract_complex_tag(const uchar *buf, uint len, uint *tag_num, uint *eaten)
{
  uint rbytes;
  uint t = 0;
  int ret;

  if ((len == 0) || (buf == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len > 4) {
    len = 4;
  }

  /*@ loop unroll 4;
    @ loop invariant 0 <= rbytes <= len;
    @ loop invariant t <= (((uint)1 << (uint)(7*(rbytes))) - 1);
    @ loop invariant \forall integer x ; 0 <= x < rbytes ==>
     ((buf[x] & 0x80) != 0);
    @ loop assigns rbytes, t;
    @ loop variant (len - rbytes);
    @ */
  for (rbytes = 0; rbytes < len; rbytes++) {
    uint tmp1, tmp2;
    /*@ assert rbytes <= 3; */
    /*@ assert t <= (((uint)1 << (uint)(7*(rbytes))) - 1); */
    /*@ assert t <= (uint)0x1fffff; */
    tmp1 = (t << (uint)7);
    tmp2 = ((uint)buf[rbytes] & (uint)0x7f);
    /*@ assert tmp1 <= (uint)0xfffff80; */
    /*@ assert tmp2 <= (uint)0x7f; */
    t = tmp1 + tmp2;
    /*@ assert t <= (((uint)1 << (uint)(7*(rbytes + 1))) - 1); */
    /*@ assert t <= 0xfffffff; */

    if ((buf[rbytes] & 0x80) == 0) {
      break;
    }
  }

  /* Check if we left the loop w/o finding tag's end */
  if (rbytes == len) {
    /*@ assert ((buf[len - 1] & 0x80) != 0); */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (t < 0x1f) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *tag_num = t;
  *eaten = rbytes + 1;

  ret = 0;

out:
  return ret;
}

/*
 * Parse beginning of current buffer to get the identifier parameters (class,
 * P/C flag and tag number). On success, the amount of bytes eaten to extract
 * those information is returned in 'eaten' parameter, which is guaranteed to
 * be lower or equal than 'len' parameter. On error, a non-zero negative value
 * is returned.
 *
 * Note: tags numbers are limited by the return type used for the parameter
 * (32 bit unsigned integer). In practice, this allows tag encoded on 4 bytes,
 * i.e. 4 x 7 bits, i.e. 28 bits. This is considered largely sufficient in
 * the context of X.509 certificates. An error is returned if a tag number
 * higher than that is found.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==>
       \valid_read(buf + (0 .. (len - 1)));
  @ requires (cls != NULL) ==> \valid(cls);
  @ requires (prim != NULL) ==> \valid(prim);
  @ requires (tag_num != NULL) ==> \valid(tag_num);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(cls, prim, tag_num, eaten, buf+(..));
  @
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (\result == 0) ==> (*cls <= 0x3);
  @ ensures (\result == 0) ==> (*prim <= 0x1);
  @
  @ assigns *tag_num, *eaten, *prim, *cls;
  @*/
static int get_identifier(const uchar *buf, uint len,
        tag_class *cls, uchar *prim, uint *tag_num, uint *eaten)
{
  int ret;
  uint t;
  uint rbytes = 0;
  uchar p;
  tag_class c;

  if (buf == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * First byte (if available) will give us the class and P/C, and also
   * tells us (based on the value of the 6 LSB of the bytes) if the tag
   * number is stored on additional bytes.
   */
  if (len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* See 8.1.2.3 */
  c = (buf[0] >> 6) & 0x03; /* Extract class from 2 MSB */
  p = (buf[0] >> 5) & 0x01; /* Extract P/C bit */
  t = buf[0] & 0x1f;        /* Extract tag number from 6 LSB */
  rbytes = 1;

  /*
   * Check if we know given class (see Table 1 from 8.1.2.2). In practice,
   * there is no way to end up in default case, because 'c' has at most
   * its two MSB set (see above).
   */
  switch (c) {
  case CLASS_UNIVERSAL:
  case CLASS_APPLICATION:
  case CLASS_CONTEXT_SPECIFIC:
  case CLASS_PRIVATE:
    break;
  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;
  }

  /*
   * If the tag number (6 LSB of first byte) we already extracted is less
   * than 0x1f, then it directly represents the tag number (which is <=
   * 30) and our work is over. Otherwise (t == 0x1f) the real tag number
   * is encoded on multiple bytes following the first byte. Note that we
   * limit ourselves to tag encoded on less than 28 bits, i.e. only accept
   * at most 4 bytes (only 7 LSB of each byte will count because MSB tells
   * if this is the last).
   */
  if (t == 0x1f) {
    uint tag_len = 0;

    /*@
      @ assert (len >= rbytes) &&
        \valid_read(buf + (rbytes .. len - 1));
      @*/
    ret = _extract_complex_tag(buf + rbytes, len - rbytes,
             &t, &tag_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    rbytes += tag_len;
  }

  /* Export what we extracted to caller */
  *cls = c;
  *prim = p;
  *tag_num = t;
  *eaten = rbytes;

  ret = 0;

out:
  return ret;
}

/*
 * Parse beginning of current buffer to get the length parameter. Input buffer
 * 'buf' has size 'len'. On success, 0 is returned, advertised length is
 * returned in 'adv_len' and the number of bytes used for the encoding of the
 * length is returned in 'eaten'.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (adv_len != NULL) ==> \valid(adv_len);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(adv_len, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (\result == 0) ==> (*adv_len <= len);
  @ ensures (\result == 0) ==> ((*adv_len + *eaten) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *adv_len, *eaten;
  @*/
int get_length(const uchar *buf, uint len, uint *adv_len, uint *eaten)
{
  uint l, rbytes = 0;
  uint len_len, b0;
  int ret;

  if (buf == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + 0); */
  b0 = buf[0];

  /* Single byte length (i.e. definitive form, on one byte)? */
  if ((b0 & 0x80) == 0) {
    l = b0 & 0x7f;
    /*@ assert l <= 0x7f ; */

    /*
     * Adding 1 below to take into account the byte that
     * encode the length is possible because l does not
     * have its MSB set, i.e. is less than or equal to
     * 127.
     */
    if ((l + 1) > len) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /* Advertised length looks ok */
    *eaten = 1;
    *adv_len = l;
    /*@ assert (*eaten + *adv_len) <= len ; */
    ret = 0;
    goto out;
  }

  /*
   * DER requires the definitive form for the length, i.e. that
   * first byte of the length field is not 0x80. At that point,
   * we already know that MSB of the byte is 1.
   */
  if (b0 == 0x80) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * We now know that the long form of the length is used. Let's
   * extract how many bytes are used to encode the length.
   */
  len_len = b0 & 0x7f;
  /*@ assert len_len <= 0x7f ; */
  rbytes += 1;
  /*@ assert rbytes > 0 ; */

  /*
   * We first check that given length for the length field is not
   * more than the size of the buffer (including the first byte
   * encoding the length of that length). Note that we can do
   * the addition below because MSB of len_len is 0.
   */
  if ((len_len + 1) > len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Now that we have length's length, let's now extract its value */
  switch (len_len) {
  case 0: /* Not acceptable */
    /* Length's length cannot be 0 */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;

  case 1: /* Length values in [ 128, 255 ] */
    /* assert \valid_read(buf + 1); */
    l = buf[1];
    if (l <= 127) {
      /*
       * For such a length value, the compact encoding
       * (definitive form) should have been used.
       */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert 127 < l ; */
    rbytes += 1;
    break;

  case 2: /* Length values in [ 256, 65535 ] */
    /* assert \valid_read(buf + (1 .. 2)); */
    l = (((uint)buf[1]) << 8) + buf[2];
    if (l <= 0xff) {
      /* Why 2 bytes if most significant is 0? */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert 0xff < l <= 0xffff ; */
    rbytes += 2;
    break;

  case 3: /* Length values in [ 65536, 16777215 ] */
    /* assert \valid_read(buf + (1 .. 3)); */
    l = (((uint)buf[1]) << 16) + (((uint)buf[2]) << 8) + buf[3];
    if (l <= 0xffff) {
      /* Why 3 bytes if most significant is 0? */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert 0xffff < l <= 0xffffff ; */
    rbytes += 3;
    break;

  case 4: /* Length values in [ 16777215, 4294967295 ] */
    /* assert \valid_read(buf + (1 .. 4)); */
    l = (((uint)buf[1]) << 24) + (((uint)buf[2]) << 16) + (((uint)buf[3]) << 8) + buf[4];
    if (l <= 0xffffff) {
      /* Why 4 bytes if most significant is 0? */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert 0xffffff < (ulong)l <= 0xffffffff ; */
    rbytes += 4;
    break;

  default: /* Not acceptable */
    /*
     * Length cannot be encoded on more than fours bytes (we
     * have an *intentional* internal limitation for
     * all ASN.1 DER structures set to 2^32 - 1 bytes (all
     * our lengths are u32)
     */
     ret = -X509_FILE_LINE_NUM_ERR;
     ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
     goto out;
     break;
  }

  /*@ assert l > 127 ; */
  /*@ assert len >= rbytes ; */
  if ((len - rbytes) < l) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert (rbytes + l) <= len ; */
  /*@ assert rbytes > 0 ; */
  *eaten = rbytes;
  *adv_len = l;

  ret = 0;

out:
  return ret;
}

/*
 * All DER-encoded elements are basically TLV structures (or identifier octets,
 * length octets, contents octets). This function parses the T and L elements
 * from given buffer and verifies the advertised length for the value (content
 * octets) does not overflow outside of the buffer. Additionally, the expected
 * class and type for the tag are verified. On success, the size of parsed
 * elements (class, type and length) are returned in 'parsed' and the size of
 * content octets are returned in 'content_len'.
 *
 * Note that the function does not parse the content of the encoded value, i.e.
 * the 'content_len' bytes in the buffer after the 'parsed' (TL header) ones. It
 * only guarantees that they are in the buffer.
 *
 * This function is critical for the security of the module.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (parsed != NULL) ==> \valid(parsed);
  @ requires (content_len != NULL) ==> \valid(content_len);
  @ requires \separated(parsed, content_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *parsed <= len);
  @ ensures (\result == 0) ==> (*content_len <= len);
  @ ensures (\result == 0) ==> (1 < (*content_len + *parsed) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed, *content_len;
  @*/
int parse_id_len(const uchar *buf, uint len, tag_class exp_class,
      uint exp_type, uint *parsed, uint *content_len)
{
  tag_class c = 0;
  uchar p;
  uint t = 0;
  uint cur_parsed = 0;
  uint grabbed;
  uint adv_len = 0;
  int ret;

  if (buf == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Get the first part of the encoding, i.e. the identifier */
  ret = get_identifier(buf, len, &c, &p, &t, &cur_parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert cur_parsed > 0; */

  /*
   * Now, verify we are indeed dealing with an element of
   * given type ...
   */
  if (t != exp_type) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* ... and class. */
  if (c != exp_class) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  grabbed = cur_parsed;
  /*@ assert grabbed > 0; */
  len -= cur_parsed;
  buf += cur_parsed;

  /* Get the second part of the encoding, i.e. the length */
  ret = get_length(buf, len, &adv_len, &cur_parsed);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert cur_parsed > 0; */

  grabbed += cur_parsed;
  /*@ assert grabbed > 1; */
  len -= cur_parsed;
  buf += cur_parsed;

  /* Verify advertised length is smaller than remaining buffer length */
  if (adv_len > len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *parsed = grabbed;
  /*@ assert *parsed > 1; */
  *content_len = adv_len;

  ret = 0;

out:
  return ret;
}

/*
 * Here, we have to deal with a wrapper around our a usual ASN.1 TLV.
 * The id of that wrapper has a given type and a context specific
 * class (CLASS_CONTEXT_SPECIFIC), i.e. a T1L1T2L2V where
 * T1 has exp_ext_type and class CLASS_CONTEXT_SPECIFIC
 * L1 provides the length of T2L2V
 * T2 has exp_int_type and exp_int_class
 * L2 provides the length of V
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (parsed != NULL) ==> \valid(parsed);
  @ requires (data_len != NULL) ==> \valid(data_len);
  @ requires \separated(parsed, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*parsed <= len);
  @ ensures (\result == 0) ==> (*data_len <= len);
  @ ensures (\result == 0) ==> ((*data_len + *parsed) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed, *data_len;
  @*/
int parse_explicit_id_len(const uchar *buf, uint len,
         uint exp_ext_type,
         tag_class exp_int_class, uint exp_int_type,
         uint *parsed, uint *data_len)
{
  uint hdr_len = 0;
  uint val_len = 0;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Work on external packaging */
  ret = parse_id_len(buf, len, CLASS_CONTEXT_SPECIFIC,
         exp_ext_type, &hdr_len, &val_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  len -= hdr_len;
  *parsed = hdr_len;

  /* Work on internal packaging */
  ret = parse_id_len(buf, len, exp_int_class, exp_int_type,
         &hdr_len, &val_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= hdr_len;
  *parsed += hdr_len;
  if (len < val_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Export the size of data */
  *data_len = val_len;

  ret = 0;

out:
  return ret;
}


/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (arc_val != NULL) ==> \valid(arc_val);
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(arc_val, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten > 0);
  @ ensures ((len > 0) && (buf != \null) && (\result != 0)) ==>
      \forall integer x ; 0 <= x < \min(len, 4) ==>
      ((buf[x] & 0x80) != 0);
  @ ensures (len == 0) ==> \result < 0;
  @
  @ assigns *arc_val, *eaten;
  @*/
static int _parse_arc(const uchar *buf, uint len, uint *arc_val, uint *eaten)
{
  uint rbytes;
  uint av = 0;
  int ret;

  if ((len == 0) || (buf == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * RFC 5280 has "There is no maximum size for OIDs. This specification
   * mandates support for OIDs that have arc elements with values that
   * are less than 2^28, that is, they MUST be between 0 and 268,435,455,
   * inclusive. This allows each arc element to be represented within a
   * single 32-bit word." For that reason, we just leave if we end up
   * encountering more than 4 bytes here.
   */
  if (len > 4) {
    len = 4;
  }

  /*@ loop unroll 4;
    @ loop invariant 0 <= rbytes <= len;
    @ loop invariant av <= (((uint)1 << (uint)(7*(rbytes))) - 1);
    @ loop invariant \forall integer x ; 0 <= x < rbytes ==>
     ((buf[x] & 0x80) != 0);
    @ loop assigns rbytes, av;
    @ loop variant (len - rbytes);
    @ */
  for (rbytes = 0; rbytes < len; rbytes++) {
    uint tmp1, tmp2;

    /*@ assert rbytes <= 3; */
    /*@ assert av <= (((uint)1 << (uint)(7*(rbytes))) - 1); */
    /*@ assert av <= (uint)0x1fffff; */

    tmp1 = (av << (uint)7);
    /*@ assert tmp1 <= (uint)0xfffff80; */
    tmp2 = ((uint)buf[rbytes] & (uint)0x7f);
    /*@ assert tmp2 <= (uint)0x7f; */
    av = tmp1 + tmp2;
    /*@ assert av <= (((uint)1 << (uint)(7*(rbytes + 1))) - 1); */
    /*@ assert av <= 0xfffffff; */

    if ((buf[rbytes] & 0x80) == 0) {
      break;
    }
  }

  if (rbytes >= len) {
    /*@ assert ((buf[len - 1] & 0x80) != 0); */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *arc_val = av;
  *eaten = rbytes + 1;

  ret = 0;

out:
  return ret;
}


static const uchar null_encoded_val[] = { 0x05, 0x00 };

/*
 * Implements a function for parsing ASN1. NULL object. On success, the function
 * returns 0 and set 'parsed' parameters to the amount of bytes parsed (i.e. 2).
 * -1 is returned on error.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (parsed != NULL) ==> \valid(parsed);
  @ requires \separated(parsed, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> *parsed == 2;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed;
  @*/
int parse_null(const uchar *buf, uint len, uint *parsed)
{
  int ret;

  if ((len == 0) || (buf == NULL) || (parsed == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len != sizeof(null_encoded_val)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = bufs_differ(buf, null_encoded_val, sizeof(null_encoded_val));
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;
  *parsed = sizeof(null_encoded_val);

out:
  return ret;
}

/*
 * Implements a function for parsing OID as described in section 8.19
 * of X.690. On success, the function returns 0 and set 'parsed'
 * parameters to the amount of bytes on which the OID is encoded
 * (header and content bytes).
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (parsed != NULL) ==> \valid(parsed);
  @ requires \separated(parsed,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *parsed <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed;
  @*/
int parse_OID(const uchar *buf, uint len, uint *parsed)
{
  uint data_len = 0;
  uint hdr_len = 0;
  uint remain = 0;
  uint num;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_OID,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= hdr_len;
  buf += hdr_len;
  if (data_len < 1) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert \valid_read(buf + (0 .. (data_len - 1))); */

  remain = data_len;
  num = 0;

  /*@
    @ loop assigns ret, num, buf, remain;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    uint arc_val = 0;
    uint rbytes = 0;

    /*
     * RFC 5280 has "Implementations MUST be able to handle
     * OIDs with up to 20 elements (inclusive)".
     */
    if (num > 20) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    ret = _parse_arc(buf, remain, &arc_val, &rbytes);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*@ assert rbytes <= remain ; */

    num += 1;

    buf += rbytes;
    remain -= rbytes;
  }

  /*
   * Let's check the OID had at least the first initial
   * subidentifier (the one derived from the two first
   * components) as described in section 8.19 of X.690.
   */
  if (num < 1) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *parsed = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}

/*
 * Implements a function for parsing integers as described in section 8.3
 * of X.690. As integers may be used in a context specific way, we allow
 * passing the expected class and type values which are to be found. The
 * parameter pos_or_zero allows specifying if only non-negative integer
 * (postive or zero) should be accepted. When set, the function returns
 * a non zero value when the parsed integer is negative. The functions
 * is not expected to be used directly but only as a helper in the
 * two function that follows it.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (hdr_len != NULL) ==> \valid(hdr_len);
  @ requires (data_len != NULL) ==> \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> ((ulong)2 < ((ulong)*hdr_len + (ulong)*data_len) <= (ulong)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
static int _parse_integer(const uchar *buf, uint len,
        tag_class exp_class, uint exp_type,
        uint *hdr_len, uint *data_len,
        int pos_or_zero)
{
  int ret;

  if ((buf == NULL) || (len == 0) || (hdr_len == NULL) || (data_len == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *hdr_len = 0;
  *data_len = 0;
  ret = parse_id_len(buf, len, exp_class, exp_type, hdr_len, data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += *hdr_len;

  /*
   * Regarding integer encoding, 8.3.1 of X.690 has "The contents octets
   * shall consist of one or more octets".
   */
  if (*data_len == 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * On integer encoding, 8.3.2 of x.690 has "If the contents octets of
   * an integer value encoding consist of more than one octet, then the
   * bits of the first octet and bit 8 of the second octet:
   *
   *  a) shall not all be ones; and
   *  b) shall not all be zero.
   */
  if (*data_len > 1) {
    if ((buf[0] == 0) && ((buf[1] & 0x80) == 0)) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    if ((buf[0] == 0xff) && (buf[1] & 0x80)) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  if (pos_or_zero && (buf[0]) & 0x80) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Common version. Allow positive and negative integers.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (hdr_len != NULL) ==> \valid(hdr_len);
  @ requires (data_len != NULL) ==> \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < ((ulong)*hdr_len + (ulong)*data_len) <= (ulong)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
int parse_integer(const uchar *buf, uint len,
        tag_class exp_class, uint exp_type,
        uint *hdr_len, uint *data_len)
{
  return _parse_integer(buf, len, exp_class, exp_type,
            hdr_len, data_len, 0);
}

/*
 * Same as previous but additionally enforce the value at hand is not negative,
 * i.e. positive or 0. This is for instance useful for integer encoding value
 * that are reduced modulo another value (e.g. ECDSA signature components).
 * The function returns 0 when the integer is valid and positive.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (hdr_len != NULL) ==> \valid(hdr_len);
  @ requires (data_len != NULL) ==> \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < ((ulong)*hdr_len + (ulong)*data_len) <= (ulong)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
int parse_non_negative_integer(const uchar *buf, uint len,
               tag_class exp_class, uint exp_type,
               uint *hdr_len, uint *data_len)
{
  return _parse_integer(buf, len, exp_class, exp_type,
            hdr_len, data_len, 1);
}

/*
 * Implements a function for parsing booleans as described in section 8.2
 * of X.690. When encoded in DER, a boolean is a 3 bytes elements which
 * can take a value of:
 *
 *  FALSE : { 0x01, 0x01, 0x00 }
 *  TRUE  : { 0x01, 0x01, 0xff }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
int parse_boolean(const uchar *buf, uint len, uint *eaten)
{
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 3) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if ((buf[0] != ASN1_TYPE_BOOLEAN) || (buf[1] != 0x01)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  switch (buf[2]) {
  case 0x00: /* FALSE */
  case 0xff: /* TRUE  */
    break;
  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;
  }

  *eaten = 3;

  ret = 0;

out:
  return ret;
}

/*@
  @ requires 0x30 <= d <= 0x39;
  @ requires 0x30 <= u <= 0x39;
  @
  @ ensures 0 <= \result <= 99;
  @
  @ assigns \nothing;
  @*/
static uchar compute_decimal(uchar d, uchar u)
{
  return (uchar)( (d - 0x30) * 10 + (u - 0x30) );
}

/* Validate UTCTime (including the constraints from RFC 5280) */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (year != NULL) ==> \valid(year);
  @ requires (month != NULL) ==> \valid(month);
  @ requires (day != NULL) ==> \valid(day);
  @ requires (hour != NULL) ==> \valid(hour);
  @ requires (min != NULL) ==> \valid(min);
  @ requires (sec != NULL) ==> \valid(sec);
  @ requires \separated(eaten, year, month, day, hour, min, sec, buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten == 15);
  @ ensures (len < 15) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> 1950 <= *year <= 2049;
  @ ensures (\result == 0) ==> *month <= 12;
  @ ensures (\result == 0) ==> *day <= 31;
  @ ensures (\result == 0) ==> *hour <= 23;
  @ ensures (\result == 0) ==> *min <= 59;
  @ ensures (\result == 0) ==> *sec <= 59;
  @
  @ assigns *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
static int parse_UTCTime(const uchar *buf, uint len, uint *eaten,
       ushort *year, uchar *month, uchar *day,
       uchar *hour, uchar *min, uchar *sec)
{
  ushort yyyy;
  uchar mo, dd, hh, mm, ss;
  const uchar c_zero = '0';
  uchar time_type;
  uchar time_len;
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar i;

  if (buf == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * As described in section 4.1.2.5.1 of RFC 5280, we do
   * expect the following encoding: YYMMDDHHMMSSZ, i.e.
   * a length of at least 15 bytes for the buffer, i.e.
   * an advertised length of 13 bytes for the string
   * it contains.
   */
  if (len < 15) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  time_type = buf[0];
  if (time_type != ASN1_TYPE_UTCTime) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  time_len = buf[1];
  if (time_len != 13) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  /*
   * Check all first 12 characters are decimal digits and
   * last one is character 'Z'
   */
  /*@
    @ loop invariant \valid_read(buf + i);
    @ loop invariant \forall integer x ; 0 <= x < i ==>
     0x30 <= buf[x] <= 0x39;
    @ loop assigns i;
    @ loop variant (12 - i);
    @ */
  for (i = 0; i < 12; i++) {
    if (c_zero > buf[i]) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    if ((buf[i] - c_zero) > 9) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    /*@ assert 0 <= buf[i] - c_zero <= 9; */
  }
  if (buf[12] != 'Z') {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert c_zero == 0x30; */
  /*@ assert \forall integer x ; 0 <= x < 12 ==> 0x30 <= buf[x] <= 0x39; */
  yyyy = compute_decimal(buf[0], buf[1]);
  /*@ assert yyyy <= 99; */
  if (yyyy >= 50) {
    yyyy += 1900;
    /*@ assert 1950 <= yyyy <= 1999; */
  } else {
    yyyy += 2000;
    /*@ assert 2000 <= yyyy <= 2049; */
  }
  /*@ assert 1950 <= yyyy <= 2049; */

  mo = compute_decimal(buf[ 2], buf[ 3]);
  dd = compute_decimal(buf[ 4], buf[ 5]);
  hh = compute_decimal(buf[ 6], buf[ 7]);
  mm = compute_decimal(buf[ 8], buf[ 9]);
  ss = compute_decimal(buf[10], buf[11]);

  /*
   * Check values are valid.
   *
   * n.b.: for dates in validity period, RFC 5280 requires the use of
   * UTCTime for dates through the year 2049. Dates in 2050 or later
   * MUST be encoded as GeneralizedTime. But this is not true for
   * use of GeneralizeTime used in other fields in X.509 structures:
   * for instance, the Invalidity date in CRL is expected to encode
   * dates in GeneralizedTime for all values of time. For that reason
   * the check for the year (<= 2049 or >= 2050) is done at a higher
   * level, i.e. see verify_correct_time_use().
   *
   */
  /*    month         day          hour         min          sec     */
  if ((mo > 12) || (dd > 31) || (hh > 23) || (mm > 59) || (ss > 59)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Export what we extracted */
  *year  = yyyy;
  *month = mo;
  *day   = dd;
  *hour  = hh;
  *min   = mm;
  *sec   = ss;

  ret = 0;

out:
  if (!ret) {
    *eaten = 15;
  }

  return ret;
}

/*@
  @ requires 0x30 <= d1 <= 0x39;
  @ requires 0x30 <= d2 <= 0x39;
  @ requires 0x30 <= d3 <= 0x39;
  @ requires 0x30 <= d4 <= 0x39;
  @
  @ ensures 0 <= \result <= 9999;
  @
  @ assigns \nothing;
  @*/
static ushort compute_year(uchar d1, uchar d2, uchar d3, uchar d4)
{
  return (ushort)(
         ((ushort)d1 - (ushort)0x30) * 1000 +
         ((ushort)d2 - (ushort)0x30) * 100 +
         ((ushort)d3 - (ushort)0x30) * 10 +
         ((ushort)d4 - (ushort)0x30) );
}

/*
 * Validate generalizedTime (including the constraints from RFC 5280). Note that
 * the code is very similar to the one above developed for UTCTime. It
 * could be possible to merge the functions into a unique helper
 * but this would impact readibility.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (year != NULL) ==> \valid(year);
  @ requires (month != NULL) ==> \valid(month);
  @ requires (day != NULL) ==> \valid(day);
  @ requires (hour != NULL) ==> \valid(hour);
  @ requires (min != NULL) ==> \valid(min);
  @ requires (sec != NULL) ==> \valid(sec);
  @ requires \separated(eaten, year, month, day, hour, min, sec, buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten == 17);
  @ ensures (len < 17) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> 0 <= *year <= 9999;
  @ ensures (\result == 0) ==> *month <= 12;
  @ ensures (\result == 0) ==> *day <= 31;
  @ ensures (\result == 0) ==> *hour <= 23;
  @ ensures (\result == 0) ==> *min <= 59;
  @ ensures (\result == 0) ==> *sec <= 59;
  @
  @ assigns *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
int parse_generalizedTime(const uchar *buf, uint len, uint *eaten,
         ushort *year, uchar *month, uchar *day,
         uchar *hour, uchar *min, uchar *sec)
{
  ushort yyyy;
  uchar mo, dd, hh, mm, ss;
  const uchar c_zero = '0';
  uchar time_type;
  uchar time_len;
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar i;

  if (buf == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * As described in section 4.1.2.5.2 of RFC 5280, we do
   * expect the following encoding: YYYYMMDDHHMMSSZ, i.e.
   * a length of at least 17 bytes for the buffer, i.e.
   * an advertised length of 15 bytes for the string
   * it contains.
   */
  if (len < 17) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  time_type = buf[0];
  if (time_type != ASN1_TYPE_GeneralizedTime) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  time_len = buf[1];
  if (time_len != 15) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  /*
   * Check all first 14 characters are decimal digits and
   * last one is character 'Z'
   */
  /*@
    @ loop invariant \valid_read(buf + i);
    @ loop invariant \forall integer x ; 0 <= x < i ==>
     0x30 <= buf[x] <= 0x39;
    @ loop assigns i;
    @ loop variant (14 - i);
    @ */
  for (i = 0; i < 14; i++) {
    if (c_zero > buf[i]) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    if ((buf[i] - c_zero) > 9) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }
  if (buf[14] != 'Z') {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert c_zero == 0x30; */
  /*@ assert \forall integer x ; 0 <= x < 12 ==> 0x30 <= buf[x] <= 0x39; */
  yyyy = compute_year(buf[0], buf[1], buf[2], buf[3]);
  /*@ assert 0 <= yyyy <= 9999 ; */
  mo = compute_decimal(buf[ 4], buf[ 5]);
  dd = compute_decimal(buf[ 6], buf[ 7]);
  hh = compute_decimal(buf[ 8], buf[ 9]);
  mm = compute_decimal(buf[10], buf[11]);
  ss = compute_decimal(buf[12], buf[13]);

  /*
   * Check values are valid.
   *
   * n.b.: for dates in validity period, RFC 5280 requires the use of
   * UTCTime for dates through the year 2049. Dates in 2050 or later
   * MUST be encoded as GeneralizedTime. But this is not true for
   * use of GeneralizeTime used in other fields in X.509 structures:
   * for instance, the Invalidity date in CRL is expected to encode
   * dates in GeneralizedTime for all values of time. For that reason
   * the check for the year (<= 2049 or >= 2050) is done at a higher
   * level, i.e. see _verify_correct_time_use().
   */
  /*    month         day          hour         min          sec     */
  if ((mo > 12) || (dd > 31) || (hh > 23) || (mm > 59) || (ss > 59)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert mo <= 12; */
  /*@ assert dd <= 31; */
  /*@ assert hh <= 23; */
  /*@ assert mm <= 59; */
  /*@ assert ss <= 59; */

  /* Export what we extracted */
  *year  = yyyy;
  *month = mo;
  *day   = dd;
  *hour  = hh;
  *min   = mm;
  *sec   = ss;

  ret = 0;

out:
  if (!ret) {
    *eaten = 17;
  }

  return ret;
}


/*
 * This function verify given buffer contains a valid UTF-8 string
 * -1 is returned on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_utf8_string(const uchar *buf, uint len)
{
  int ret;
  uchar b0;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop invariant \valid_read(buf + (0 .. (len - 1)));
    @ loop assigns b0, len, buf, ret;
    @ loop variant len;
    @ */
  while (len) {
    b0 = buf[0];

    /*
     * CP encoded on a single byte, coding from 1 to 7 bits,
     * U+000 to U+07FF.
     */

    if (b0 <= 0x7f) {                   /* 0x00 to 0x7f */
      len -= 1;
      buf += 1;
      continue;
    }

    /*
     * CP encoded on 2 bytes, coding from 8 to 11 bits,
     * U+0080 to U+07FF
     */

    if ((b0 >= 0xc2) && (b0 <= 0xdf)) { /* 0xc2 to 0xdf */
      if (len < 2) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      /*@ assert \valid_read(buf + (0 .. 1)); */
      if ((buf[1] & 0xc0) != 0x80) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      len -= 2;
      buf += 2;
      continue;
    }

    /*
     * CP encoded on 3 bytes, coding 12 to 16 bits,
     * U+0800 to U+FFFF.
     */

    if ((b0 >= 0xe0) && (b0 <= 0xef)) { /* 0xe0 to 0xef */
      if (len < 3) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      /*@ assert \valid_read(buf + (0 .. 2)); */
      if (((buf[1] & 0xc0) != 0x80) ||
          ((buf[2] & 0xc0) != 0x80)) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      /*
       * 1rst byte is 0xe0 => 2nd byte in [0xa0, 0xbf]
       * 1rst byte is 0xed => 2nd byte in [0x80, 0x9f]
       */
      if ((b0 == 0xe0) &&
          ((buf[1] < 0xa0) || (buf[1] > 0xbf))) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      } else if ((b0 == 0xed) &&
           ((buf[1] < 0x80) || (buf[1] > 0x9f))) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      len -= 3;
      buf += 3;
      continue;
    }

    /*
     * CP encoded on 4 bytes, coding 17 to 21 bits,
     * U+10000 to U+10FFFF.
     */

    if ((b0 >= 0xf0) && (b0 <= 0xf4)) { /* 0xf0 to 0xf4 */
      if (len < 4) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      /*
       * 1rst byte is 0xe0 => 2nd byte in [0xa0, 0xbf]
       * 1rst byte is 0xed => 2nd byte in [0x80, 0x9f]
       */
      /*@ assert \valid_read(buf + (0 .. 3)); */
      if ((b0 == 0xf0) &&
          ((buf[1] < 0x90) || (buf[1] > 0xbf))) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      } else if ((b0 == 0xf4) &&
           ((buf[1] < 0x80) || (buf[1] > 0x8f))) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      if (((buf[1] & 0xc0) != 0x80) ||
          ((buf[2] & 0xc0) != 0x80) ||
          ((buf[3] & 0xc0) != 0x80)) {
        ret = -X509_FILE_LINE_NUM_ERR;
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      len -= 4;
      buf += 4;
      continue;
    }

    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Verify given buffer contains only printable characters. -1 is
 * returned on error, 0 on success.
 *
 * RFC 5280 has: "The character string type PrintableString supports a
 * very basic Latin character set: the lowercase letters 'a' through 'z',
 * uppercase letters 'A' through 'Z', the digits '0' through '9',
 * eleven special characters ' = ( ) + , - . / : ? and space."
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_printable_string(const uchar *buf, uint len)
{
  int ret;
  uint rbytes;
  uchar c;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop invariant 0 <= rbytes <= len;
    @ loop assigns rbytes, c, ret;
    @ loop variant (len - rbytes);
    @ */
  for (rbytes = 0; rbytes < len; rbytes++) {
    c = buf[rbytes];

    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      continue;
    }

    switch (c) {
    case 39: /* ' */
    case '=':
    case '(':
    case ')':
    case '+':
    case ',':
    case '-':
    case '.':
    case '/':
    case ':':
    case '?':
    case ' ':
      continue;
    default:
      break;
    }

    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Verify given buffer contains only numeric characters. -1 is
 * returned on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_numeric_string(const uchar *buf, uint len)
{
  int ret;
  uint rbytes;
  uchar c;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop invariant 0 <= rbytes <= len;
    @ loop assigns rbytes, c, ret;
    @ loop variant (len - rbytes);
    @ */
  for (rbytes = 0; rbytes < len; rbytes++) {
    c = buf[rbytes];

    if ((c < '0') || (c > '9')) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  ret = 0;

out:
  return ret;
}

/*
 * VisibleString == ISO646String == ASCII
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_visible_string(const uchar *buf, uint len)
{
  int ret;
  uint rbytes = 0;
  uchar c;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop assigns rbytes, c, ret;
    @ loop variant (len - rbytes);
    @ */
  while (rbytes < len) {
    c = buf[rbytes];

    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      rbytes += 1;
      continue;
    }

    switch (c) {
    case 39: /* ' */
    case '=':
    case '(':
    case ')':
    case '+':
    case ',':
    case '-':
    case '.':
    case '/':
    case ':':
    case '?':
    case ' ':
    case '!':
    case '"':
    case '#':
    case '$':
    case '%':
    case '&':
    case '*':
    case ';':
    case '<':
    case '>':
    case '[':
    case '\\':
    case ']':
    case '^':
    case '_':
    case '`':
    case '{':
    case '|':
    case '}':
    case '~':
      rbytes += 1;
      continue;
    default:
      break;
    }

    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

#ifdef TEMPORARY_LAXIST_DIRECTORY_STRING
/*
 * Teletex string is not supposed to be supported and there is no good
 * defintiion of allowed charset. At the moment, we perform the check
 * using visible string charset. XXX we should revisit that later
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_teletex_string(const uchar *buf, uint len)
{
  return check_visible_string(buf, len);
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_universal_string(const uchar ATTRIBUTE_UNUSED *buf,
          uint ATTRIBUTE_UNUSED len)
{
  return -X509_FILE_LINE_NUM_ERR;
}
#endif

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_bmp_string(const uchar ATTRIBUTE_UNUSED *buf,
          uint ATTRIBUTE_UNUSED len)
{
  /* Support is OPTIONAL */
  return -X509_FILE_LINE_NUM_ERR;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_ia5_string(const uchar *buf, uint len)
{
  int ret;
  uint i;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@
    @ loop invariant \forall integer x ; 0 <= x < i ==>
     ((buf[x] <= 0x7f));
    @ loop assigns i;
    @ loop variant (len - i);
    @ */
  for (i = 0; i < len; i++) {
    if (buf[i] > 0x7f) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  ret = 0;

out:
  return ret;
}


/*
 * Parse GeneralName (used in SAN and AIA extensions)
 *
 *  GeneralName ::= CHOICE {
 *       otherName                 [0]  AnotherName,
 *       rfc822Name                [1]  IA5String,
 *       dNSName                   [2]  IA5String,
 *       x400Address               [3]  ORAddress,
 *       directoryName             [4]  Name,
 *       ediPartyName              [5]  EDIPartyName,
 *       uniformResourceIdentifier [6]  IA5String,
 *       iPAddress                 [7]  OCTET STRING,
 *       registeredID              [8]  OBJECT IDENTIFIER }
 *
 *  OtherName ::= SEQUENCE {
 *       type-id    OBJECT IDENTIFIER,
 *       value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *  EDIPartyName ::= SEQUENCE {
 *       nameAssigner            [0]     DirectoryString OPTIONAL,
 *       partyName               [1]     DirectoryString }
 *
 */

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (empty != NULL) ==> \valid(empty);
  @ requires \separated(eaten, empty, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> (0 <= *empty <= 1);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *empty;
  @*/
int parse_GeneralName(const uchar *buf, uint len, uint *eaten, int *empty)
{
  uint remain = 0, name_len = 0, name_hdr_len = 0, grabbed = 0;
  uchar name_type;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = len;

  /*
   * We expect the id for current name to be encoded on
   * a single byte, i.e. we expect its MSB to be set.
   */
  name_type = buf[0];
  if (!(name_type & 0x80)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  switch (name_type) {
  case NAME_TYPE_rfc822Name: /* 0x81 - rfc822Name - IA5String */
  case NAME_TYPE_dNSName:    /* 0x82 - dNSName - IA5String */
  case NAME_TYPE_URI:        /* 0x86 - uniformResourceIdentifier - IA5String */
    buf += 1;
    remain -= 1;

    ret = get_length(buf, remain, &name_len, &grabbed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    buf += grabbed;
    remain -= grabbed;

    if (name_len > remain) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    ret = check_ia5_string(buf, name_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /* Now, do some more specific checks */
    switch (name_type) {
    case NAME_TYPE_rfc822Name: /* rfc822Name - IA5String */

      /* FIXME! We should do more parsing on that one */

      break;
    case NAME_TYPE_dNSName: /* dNSName - IA5String */

      /* FIXME! We should do more parsing on that one */
      /*
       * From section 4.2.1.6 of RFC5280:
       * The name MUST be in the "preferred name syntax",
       * as specified by Section 3.5 of [RFC1034] and as
       * modified by Section 2.1 of [RFC1123].
       */
      break;
    case NAME_TYPE_URI: /* uniformResourceIdentifier - IA5String */

      /* FIXME! We should do more parsing on that one */

      break;
    default:
      break;
    }

    remain -= name_len;
    buf += name_len;
    *eaten = name_len + grabbed + 1;
    *empty = !name_len;
    /*@ assert *eaten > 1; */
    break;

  case NAME_TYPE_iPAddress: /* 0x87 - iPaddress - OCTET STRING */
    buf += 1;
    remain -= 1;

    ret = get_length(buf, remain, &name_len, &grabbed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
    buf += grabbed;
    remain -= grabbed;

    if (name_len > remain) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /* FIXME! Check size is 4, resp. 16, for IPv4, resp. IPv6. */

    remain -= name_len;
    buf += name_len;
    *eaten = name_len + grabbed + 1;
    *empty = !name_len;
    /*@ assert *eaten > 1; */
    break;

  case NAME_TYPE_otherName: /* 0xa0 - otherName - OtherName */
    /* FIXME! unsupported */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;

  case NAME_TYPE_x400Address: /* 0xa3 - x400Address - ORAddress */
    /* FIXME! unsupported */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;

  case NAME_TYPE_directoryName: /* 0xa4 - directoryName - Name */
    ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 4,
           &name_hdr_len, &name_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += name_hdr_len;
    remain = name_len;

    ret = parse_x509_Name(buf, remain, &grabbed, empty);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += grabbed;
    remain -= grabbed;

    if (remain) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    *eaten = name_hdr_len + name_len;
    /*@ assert *eaten > 1; */
    break;

  case NAME_TYPE_ediPartyName: /* 0xa5 - ediPartyName - EDIPartyName */
    /* FIXME! unsupported */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;

  case NAME_TYPE_registeredID: /* 0x88 - registeredID - OBJECT IDENTIFIER */
    /* FIXME! unsupported */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;

  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;
  }

  /*@ assert *eaten > 1; */
  ret = 0;

out:
  return ret;
}


/* GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
int parse_GeneralNames(const uchar *buf, uint len, tag_class exp_class,
           uint exp_type, uint *eaten)
{
  uint remain, parsed = 0, hdr_len = 0, data_len = 0;
  int ret, unused = 0;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, exp_class, exp_type,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain = data_len;

  /*@
    @ loop assigns ret, buf, remain, parsed, unused;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    ret = parse_GeneralName(buf, remain, &parsed, &unused);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= parsed;
    buf += parsed;
  }

  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}


/*
 * used for SerialNumber (in tbsCertificate or AKI). As the underlying integer
 * might be used with context specific class and types, those two elements are
 * passed to the function and verified to match in given encoding.
 *
 *     CertificateSerialNumber  ::=  INTEGER
 *
 */
#define MAX_SERIAL_NUM_LEN 22 /* w/ header */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
int parse_SerialNumber(const uchar *cert, uint off, uint len,
           tag_class exp_class, uint exp_type,
           uint *eaten)
{
  const uchar *buf = cert + off;
  uint parsed = 0, hdr_len = 0, data_len = 0;
  int ret;

  if ((cert == NULL) || (len == 0) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /* Verify the integer is DER-encoded as it should */
  ret = parse_integer(buf, len, exp_class, exp_type,
          &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  parsed = hdr_len + data_len;
  /*@ assert parsed > 2; */

  *eaten = parsed;
  /*@ assert *eaten > 2; */

  /*
   * We now have the guarantee the integer has the following format:
   * [2 bytes for t/c and len][data_len bytes for encoded value]
   */

  /*
   * Serial is expected not to be 0. Because we are guaranteed with the
   * check above to deal with a DER encoded integer, 0 would be encoded
   * on exactly 3 bytes (2 for header and 1 for the value), the last one
   * being 0.
   */
  if ((data_len == 1) && (buf[2] == 0)) {
#ifndef TEMPORARY_LAXIST_SERIAL_NULL
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
#else
    ret = 0;
    goto out;
#endif
  }

  /*
   * serialNumber value is expected to be at most 20 bytes long, which
   * makes 22 bytes for the whole structure (if we include the associated
   * two bytes header (a length of 20 is encoded on a single byte of
   * header following the type/class byte.
   */
  if (parsed > MAX_SERIAL_NUM_LEN) {
#ifndef TEMPORARY_LAXIST_SERIAL_LENGTH
    ret = -X509_FILE_LINE_NUM_ERR;
         ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
         goto out;
#else
         ret = 0;
#endif
  }

  /* ... and be positive */
  if (buf[2] & 0x80) {
#ifndef TEMPORARY_LAXIST_SERIAL_NEGATIVE
    /*
     * RFC has a MUST (4.1.2.2) for serial integer to
     * be positive.
     */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
#else
    /* here, we let it happen */
    ret = 0;
#endif
  }

  ret = 0;

out:
  return ret;
}

/*
 * RFC 5280 has "CAs conforming to this profile MUST always encode certificate
 * validity dates through the year 2049 as UTCTime; certificate validity dates
 * in 2050 or later MUST be encoded as GeneralizedTime."
 *
 * This function performs that simple check. It returns 0 on success, a non
 * zero value on error.
 */
/*@ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
int verify_correct_time_use(uchar time_type, ushort yyyy)
{
  int ret;

  switch (time_type) {
  case ASN1_TYPE_UTCTime:
    ret = (yyyy <= 2049) ? 0 : -X509_FILE_LINE_NUM_ERR;
    break;
  case ASN1_TYPE_GeneralizedTime:
    ret = (yyyy >= 2050) ? 0 : -X509_FILE_LINE_NUM_ERR;
    break;
  default:
    ret = -1;
    break;
  }

  return ret;

}

/*
 * Time ::= CHOICE {
 *    utcTime        UTCTime,
 *    generalTime    GeneralizedTime }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (t_type != NULL) ==> \valid(t_type);
  @ requires (year != NULL) ==> \valid(year);
  @ requires (month != NULL) ==> \valid(month);
  @ requires (day != NULL) ==> \valid(day);
  @ requires (hour != NULL) ==> \valid(hour);
  @ requires (min != NULL) ==> \valid(min);
  @ requires (sec != NULL) ==> \valid(sec);
  @ requires \separated(t_type,eaten,year,month,day,hour,min,sec,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> 0 <= *year <= 9999;
  @ ensures (\result == 0) ==> *month <= 12;
  @ ensures (\result == 0) ==> *day <= 31;
  @ ensures (\result == 0) ==> *hour <= 23;
  @ ensures (\result == 0) ==> *min <= 59;
  @ ensures (\result == 0) ==> *sec <= 59;
  @
  @ assigns *t_type, *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
int parse_Time(const uchar *buf, uint len, uchar *t_type, uint *eaten,
         ushort *year, uchar *month, uchar *day,
         uchar *hour, uchar *min, uchar *sec)
{
  uchar time_type;
  int ret = -X509_FILE_LINE_NUM_ERR;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  time_type = buf[0];

  switch (time_type) {
  case ASN1_TYPE_UTCTime:
    ret = parse_UTCTime(buf, len, eaten, year, month,
            day, hour, min, sec);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case ASN1_TYPE_GeneralizedTime:
    ret = parse_generalizedTime(buf, len, eaten, year, month,
              day, hour, min, sec);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    break;
  }

  *t_type = time_type;

out:
  if (ret) {
    *eaten = 0;
  }
  return ret;
}

/* Specification version for serial number field from AKI */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
int parse_AKICertSerialNumber(const uchar *cert, uint off, uint len,
            tag_class exp_class, uint exp_type,
            uint *eaten)
{
  int ret;

  ret = parse_SerialNumber(cert, off, len, exp_class, exp_type, eaten);
  if (ret) {
         ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
         goto out;
  }

out:
  return ret;
}

/*
 * X.509 certificates includes 2 definitions of named bit list which
 * both define 9 flags: KeyUsage and ReasonFlags. For that reason, most
 * of the decoding logic for the instances of this types (keyUsage
 * extension, CRLDP and FreshestCRL) can be done in a single location.
 *
 * Note that the function enforces that at least one bit is set in the
 * nit named bit list, as explicitly required at least for Key Usage.
 * This is in sync with what is given in Appendix B of RFC 5280:
 * "When DER encoding a named bit list, trailing zeros MUST be omitted.
 * That is, the encoded value ends with the last named bit that is set
 * to one."
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (val != NULL) ==> \valid(val);
  @ requires \separated(val, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *val;
  @*/
int parse_nine_bit_named_bit_list(const uchar *buf, uint len, ushort *val)
{
  uchar k, non_signif;
  ushort tmp;
  int ret;

  /*
   * Initial content octet is required. It provides the number of
   * non-significative bits at the end of the last bytes carrying
   * the bitstring value.
   */
  if ((buf == NULL) || (len == 0) || (val == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* ... and it must be in the range [0,7]. */
  if (buf[0] & 0xf8) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * We encode 9 bits of information in a named bit list bitstring.
   * With the initial octet of the content octets (encoding the number
   * of unused bits in the final octet), the whole content octets
   * should be made of 1, 2 or 3 bytes.
   */
  switch (len) {
  case 1: /* 1 byte giving number of unused bits - no following bytes */
    if (buf[0] != 0) {
      /*
       * The number of non-significative bits is non-zero
       * but no bits are following. This is invalid.
       */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    } else {
      /*
       * Last paragraph of section 4.2.1.3 of RFC 5280 has
       * "When the keyUsage extension appears in a
       * certificate, at least one of the bits
       * MUST be set to 1.". Regarding ReasonFlags, this
       * is not explictly stated but would not make sense
       * either.
       */
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    break;

  case 2: /* 1 byte giving number of unused bits - 1 following byte */
    /*
     * Last paragraph of section 4.2.1.3 of RFC 5280 has
     * "When the keyUsage extension appears in a
     * certificate, at least one of the bits
     * MUST be set to 1". Regarding ReasonFlags, this would
     * not make sense either to have an empty list.
     */
    if (buf[1] == 0) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * Now that we are sure at least one bit is set, we can see
     * which one is the last one set to verify it matches what
     * the byte giving the number of unused bits tells us. When
     * we are dealing w/ non-significative bits, they should be
     * set to 0 in the byte (11.2.1 of X.690).
     * Additionally, keyUsage type is a NamedBitList-based
     * bitstring, and for that reason X.680 clause 11.2.2 requires
     * "the bitstring shall have all trailing 0 bits removed
     * before it is encoded". This is also the conclusion of
     * http://www.ietf.org/mail-archive/web/pkix/current/
     * msg10424.html. This is also explicitly stated in Appendix B
     * of RFC5280: "When DER encoding a named bit list, trailing
     * zeros MUST be omitted.  That is, the encoded value ends with
     * the last named bit that is set to one."
     */

    non_signif = 0;

    /*@
      @ loop assigns k, non_signif;
      @ loop variant (8 - k);
      @*/
    for (k = 0; k < 8; k++) {
      if ((buf[1] >> k) & 0x1) {
        non_signif = k;
        break;
      }
    }

    if (buf[0] != non_signif) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /* Revert bits to provide a usable value to caller */
    tmp = 0;
    /*@
      @ loop unroll 8;
      @ loop invariant 0 <= k <= 8;
      @ loop assigns k, tmp;
      @ loop variant (8 - k);
      @*/
    for (k = 0; k < 8; k++) {
      const uchar mask[8] = {1, 2, 4, 8, 16, 32, 64, 128 };
      tmp |= (buf[1] & mask[k]) ? mask[7-k] : 0;
    }
    *val = tmp;

    break;

  case 3: /* 1 byte for unused bits - 2 following bytes */
    /*
     * keyUsage and ReasonFlags support at most 9 bits. When the
     * named bit list bitstring is made of 1 byte giving unused
     * bits and 2 following bytes, this means the 9th bit (i.e.
     * bit 8, decipherOnly) is asserted.
     * Because of that, the value of the byte giving the number
     * of unused bits is necessarily set to 7.
     */
    if ((buf[0] != 7) || (buf[2] != 0x80)) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * Revert bits to provide a usable value to caller,
     * working on first byte's bits and then on single
     * MSB from second byte.
     */
    tmp = 0;
    /*@
      @ loop unroll 8;
      @ loop invariant 0 <= k <= 8;
      @ loop assigns k, tmp;
      @ loop variant (8 - k);
      @*/
    for (k = 0; k < 8; k++) {
      const uchar mask[8] = {1, 2, 4, 8, 16, 32, 64, 128 };
      tmp |= (buf[1] & mask[k]) ? mask[7-k] : 0;
    }
    tmp |= (buf[2] & 0x80) ? 0x0100 : 0x0000;
    *val = tmp;
    break;

  default: /* too many bytes for encoding 9 poor bits */
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 *  ReasonFlags ::= BIT STRING {
 *       unused                  (0),
 *       keyCompromise           (1),
 *       cACompromise            (2),
 *       affiliationChanged      (3),
 *       superseded              (4),
 *       cessationOfOperation    (5),
 *       certificateHold         (6),
 *       privilegeWithdrawn      (7),
 *       aACompromise            (8) }
 *
 * Note that the occurences of reasons in the specs are all context specific
 * with different type values: 0x01 in CRLDP and 0x03 in IDP. For that reason
 * the parsing function below takes an exp_type value.
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
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
int parse_crldp_reasons(const uchar *buf, uint len, uint exp_type, uint *eaten)
{
  uint hdr_len = 0, data_len = 0;
  ushort val = 0;
  int ret;

  if ((buf == NULL) || (len == 0) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, CLASS_CONTEXT_SPECIFIC, exp_type,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  len -= hdr_len;

  ret = parse_nine_bit_named_bit_list(buf, data_len, &val);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = hdr_len + data_len;

  ret = 0;

out:
  return ret;
}



/*
 *     DistributionPoint ::= SEQUENCE {
 *          distributionPoint       [0]     DistributionPointName OPTIONAL,
 *          reasons                 [1]     ReasonFlags OPTIONAL,
 *          cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 *     DistributionPointName ::= CHOICE {
 *          fullName                [0]     GeneralNames,
 *          nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 *
 *     ReasonFlags ::= BIT STRING {
 *          unused                  (0),
 *          keyCompromise           (1),
 *          cACompromise            (2),
 *          affiliationChanged      (3),
 *          superseded              (4),
 *          cessationOfOperation    (5),
 *          certificateHold         (6),
 *          privilegeWithdrawn      (7),
 *          aACompromise            (8) }
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (crldp_has_all_reasons != NULL) ==> \valid(crldp_has_all_reasons);
  @ requires \separated(eaten, buf+(..), crldp_has_all_reasons);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *crldp_has_all_reasons;
  @*/
int parse_DistributionPoint(const uchar *buf, uint len,
          int *crldp_has_all_reasons, uint *eaten)
{
  uint hdr_len = 0, data_len = 0, remain = 0, total_len = 0;
  int dp_or_issuer_present = 0;
  uint parsed = 0;
  int ret, has_all_reasons = 0;

  if ((buf == NULL) || (len == 0) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* DistributionPoint is a sequence */
  ret = parse_id_len(buf, len,
         CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    goto out;
  }

  total_len = hdr_len + data_len;
  /*@ assert total_len > 0; */
  remain = data_len;
  buf += hdr_len;

  /*
   * Check if we have a (optional) distributionPoint field
   * (of type DistributionPointName)
   */
  ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
         &hdr_len, &data_len);
  if (!ret) {
    uint dpn_remain = 0, dpn_eaten = 0;
    uchar dpn_type;

    buf += hdr_len;
    remain -= hdr_len;
    dpn_remain = data_len;

    if (data_len == 0) {
      ret = -X509_FILE_LINE_NUM_ERR;
      goto out;
    }

    dpn_type = buf[0];

    /*
     * distributionPoint field of type DistributionPointName
     * can be either a fullName or a nameRelativeToCRLIssuer.
     */
    switch (dpn_type) {
    case 0xa0: /* fullName (i.e. a GeneralNames) */
      ret = parse_GeneralNames(buf, dpn_remain,
             CLASS_CONTEXT_SPECIFIC, 0,
             &dpn_eaten);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }

      dpn_remain -= dpn_eaten;
      buf += dpn_eaten;
      break;

    case 0xa1: /* nameRelativeToCRLIssuer (RDN) */
      /*
       * This form of distributionPoint is never used
       * in practice in real X.509 certs, so not
       * supported here. Note that RFC5280 has the
       * following: "Conforming CAs SHOULD NOT use
       * nameRelativeToCRLIssuer to specify distribution
       * point names."
       */
      ret = -X509_FILE_LINE_NUM_ERR;
      goto out;
      break;

    default:
      ret = -X509_FILE_LINE_NUM_ERR;
      goto out;
      break;
    }

    if (dpn_remain) {
      ret = -X509_FILE_LINE_NUM_ERR;
      goto out;
    }

    /* Record the fact we found a DP */
    dp_or_issuer_present |= 1;

    remain -= data_len;
  }

  /* Check if we have a (optional) ReasonFlags */
  ret = parse_crldp_reasons(buf, remain, 0x01, &parsed);
  if (!ret) {
    buf += parsed;
    remain -= parsed;
  } else {
    /*
     * RFC 5280 has "If the DistributionPoint omits the reasons
     * field, the CRL MUST include revocation information for all
     * reasons", i.e. no reasonFlags means all reasons.
     */
    has_all_reasons = 1;
  }

  /* Check if we have a (optional) cRLIssuer (GeneralNames) */
  ret = parse_GeneralNames(buf, remain, CLASS_CONTEXT_SPECIFIC, 2,
         &parsed);
  if (!ret) {
    /* Record the fact we found a cRLIssuer */
    dp_or_issuer_present |= 1;

    buf += parsed;
    remain -= parsed;
  }

  if (remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * RFC580 has (about DP and cRLIssuer): "While each of these fields is
   * optional, a DistributionPoint MUST NOT consist of only the reasons
   * field; either distributionPoint or cRLIssuer MUST be present."
   */
  if (!dp_or_issuer_present) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = total_len;
  *crldp_has_all_reasons = has_all_reasons;
  /*@ assert *eaten > 0; */

  ret = 0;

out:
  return ret;
}


/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_AccessDescription(const uchar *buf, uint len, uint *eaten)
{
  const uchar id_ad_caIssuers_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
             0x05, 0x07, 0x30, 0x01 };
  const uchar id_ad_ocsp_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
              0x05, 0x07, 0x30, 0x02 };
  uint remain, hdr_len = 0, data_len = 0, oid_len = 0;
  uint al_len = 0, saved_ad_len = 0;
  int ret, found, unused;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = len;

  ret = parse_id_len(buf, remain,
         CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  saved_ad_len = hdr_len + data_len;
  /*@ assert saved_ad_len <= len ; */
  remain -= hdr_len;
  /*@ assert remain >= data_len ; */
  buf += hdr_len;

  /* accessMethod is an OID */
  ret = parse_OID(buf, data_len, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * We only support the two OID that are reference in the RFC,
   * i.e. id-ad-caIssuers and id-ad-ocsp.
   */
  found = 0;

  if (oid_len == sizeof(id_ad_caIssuers_oid)) {
    found = !bufs_differ(buf, id_ad_caIssuers_oid, oid_len);
  }

  if ((!found) && (oid_len == sizeof(id_ad_ocsp_oid))) {
    found = !bufs_differ(buf, id_ad_ocsp_oid, oid_len);
  }

  if (!found) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += oid_len;
  remain -= oid_len;
  data_len -= oid_len;
  /*@ assert remain >= data_len ; */

  /* accessLocation is a GeneralName */
  ret = parse_GeneralName(buf, data_len, &al_len, &unused);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * FIXME! I guess we could do some specific parsing on the
   * content of the generalName based on what is described
   * in section 4.2.2.1 of RFC 5280.
   */

  buf += al_len;
  /*@ assert remain >= data_len >= al_len; */
  remain -= al_len;
  data_len -= al_len;

  if (data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = saved_ad_len;
  /*@ assert *eaten <= len ; */
  ret = 0;

out:
  return ret;
}

/*
 * 4.2.2.1 - Certificate Authority Information Access (Certificate extension)
 * 5.2.7 - Authority Information Access (CRL extension)
 *
 *    id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *
 *    AuthorityInfoAccessSyntax  ::=
 *            SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 *    AccessDescription  ::=  SEQUENCE {
 *            accessMethod          OBJECT IDENTIFIER,
 *            accessLocation        GeneralName  }
 *
 *    id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
 *
 *    id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 *
 *    id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 *
 *  GeneralName ::= CHOICE {
 *       otherName                 [0]  AnotherName,
 *       rfc822Name                [1]  IA5String,
 *       dNSName                   [2]  IA5String,
 *       x400Address               [3]  ORAddress,
 *       directoryName             [4]  Name,
 *       ediPartyName              [5]  EDIPartyName,
 *       uniformResourceIdentifier [6]  IA5String,
 *       iPAddress                 [7]  OCTET STRING,
 *       registeredID              [8]  OBJECT IDENTIFIER }
 */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (critical != 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
int parse_AIA(const uchar *cert, uint off, uint len, int critical)
{
  uint hdr_len = 0, data_len = 0, remain;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert \valid_read(buf + (0 .. len - 1)); */

  /*
   * 4.2.2.1 of RFC5280 has "Conforming CAs MUST mark this
   * extension as non-critical"
   */
  if (critical) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  remain = len;

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;
  remain -= hdr_len;

  /* We do expect sequence to exactly match the length */
  if (remain != data_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Empty AIA extensions are not authorized (AIA is a non empty sequence
   * of AccessDescription structures.
   */
  if (!remain) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*
   * Iterate on AccessDescription structures: each is
   * a sequence containing an accessMethod (an OID)
   * and an accessLocation (a GeneralName).
   */
  /*@
    @ loop assigns ret, buf, remain;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    uint parsed = 0;

    ret = parse_AccessDescription(buf, remain, &parsed);
    if (ret) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    remain -= parsed;
    buf += parsed;
  }

  ret = 0;

out:
  return ret;
}

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \forall integer k; 0 <= k < num_known_sig_algs ==> \valid_read(known_sig_algs[k]);
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < num_known_sig_algs && \result == known_sig_algs[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \result;
  @*/
const _sig_alg * find_sig_alg_by_oid(const uchar *buf, uint len)
{
  const _sig_alg *found = NULL;
  const _sig_alg *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@
    @ loop unroll num_known_sig_algs;
    @ loop invariant 0 <= k <= num_known_sig_algs;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (num_known_sig_algs - k);
    @*/
  for (k = 0; k < num_known_sig_algs; k++) {
    int ret;

    cur = known_sig_algs[k];

    /*@ assert cur == known_sig_algs[k]; */
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


/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && \result == known_hashes[i] && \valid_read(\result);
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \result;
  @*/
const _hash_alg * find_hash_by_oid(const uchar *buf, uint len)
{
  const _hash_alg *found = NULL;
  const _hash_alg *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ loop unroll NUM_KNOWN_HASHES ;
    @ loop invariant 0 <= k <= NUM_KNOWN_HASHES;
    @ loop invariant found == NULL;
    @ loop invariant (cur != NULL) ==> \valid_read(cur);
    @ loop assigns cur, found, k;
    @ loop variant (NUM_KNOWN_HASHES - k);
    @*/
  for (k = 0; k < NUM_KNOWN_HASHES; k++) {
    int ret;

    cur = known_hashes[k];
    /*@ assert \valid_read(cur); */

    /*@ assert cur == known_hashes[k];*/
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

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_CURVES && \result == known_curves[i] && \valid_read(known_curves[i]);
  @ ensures (\result != NULL) ==> \result->crv_order_bit_len <= 571;
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \result;
  @*/
const _curve * find_curve_by_oid(const uchar *buf, uint len)
{
  const _curve *found = NULL;
  const _curve *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ assert \forall integer k; 0 <= k < NUM_KNOWN_CURVES ==> \valid_read(known_curves[k]); */
  /*@ assert \forall integer k; 0 <= k < NUM_KNOWN_CURVES ==> known_curves[k]->crv_order_bit_len <= 571; */

  /*@
    @ loop unroll NUM_KNOWN_CURVES;
    @ loop invariant 0 <= k <= NUM_KNOWN_CURVES;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (NUM_KNOWN_CURVES - k);
    @*/
  for (k = 0; k < NUM_KNOWN_CURVES; k++) {
    int ret;

    cur = known_curves[k];

    /*@ assert cur == known_curves[k];*/
    if (cur->crv_der_oid_len != len) {
      continue;
    }

    /*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
    ret = !bufs_differ(cur->crv_der_oid, buf, cur->crv_der_oid_len);
    if (ret) {
      found = cur;
      break;
    }
  }
  /*@ assert (found != NULL) ==> found->crv_order_bit_len <= 571; */

out:
  return found;
}


static const uchar _dn_oid_cn[] =        { 0x06, 0x03, 0x55, 0x04, 0x03 };
static const uchar _dn_oid_surname[] =   { 0x06, 0x03, 0x55, 0x04, 0x04 };
static const uchar _dn_oid_serial[] =    { 0x06, 0x03, 0x55, 0x04, 0x05 };
static const uchar _dn_oid_country[] =   { 0x06, 0x03, 0x55, 0x04, 0x06 };
static const uchar _dn_oid_locality[] =  { 0x06, 0x03, 0x55, 0x04, 0x07 };
static const uchar _dn_oid_state[] =     { 0x06, 0x03, 0x55, 0x04, 0x08 };
static const uchar _dn_oid_org[] =       { 0x06, 0x03, 0x55, 0x04, 0x0a };
static const uchar _dn_oid_org_unit[] =  { 0x06, 0x03, 0x55, 0x04, 0x0b };
static const uchar _dn_oid_title[] =     { 0x06, 0x03, 0x55, 0x04, 0x0c };
static const uchar _dn_oid_name[] =      { 0x06, 0x03, 0x55, 0x04, 0x29 };
static const uchar _dn_oid_emailaddress[] = { 0x06, 0x09, 0x2a, 0x86, 0x48,
             0x86, 0xf7, 0x0d, 0x01, 0x09,
             0x01  };
static const uchar _dn_oid_given_name[] = { 0x06, 0x03, 0x55, 0x04, 0x2a };
static const uchar _dn_oid_initials[] =  { 0x06, 0x03, 0x55, 0x04, 0x2b };
static const uchar _dn_oid_gen_qual[] =  { 0x06, 0x03, 0x55, 0x04, 0x2c };
static const uchar _dn_oid_dn_qual[] =   { 0x06, 0x03, 0x55, 0x04, 0x2e };
static const uchar _dn_oid_pseudo[] =    { 0x06, 0x03, 0x55, 0x04, 0x41 };
static const uchar _dn_oid_dc[] =        { 0x06, 0x0a, 0x09, 0x92, 0x26,
          0x89, 0x93, 0xf2, 0x2c, 0x64,
          0x01, 0x19 };
static const uchar _dn_oid_ogrn[] =      { 0x06, 0x05, 0x2a, 0x85, 0x03,
          0x64, 0x01 };
static const uchar _dn_oid_snils[] =     { 0x06, 0x05, 0x2a, 0x85, 0x03,
          0x64, 0x03 };
static const uchar _dn_oid_ogrnip[] =    { 0x06, 0x05, 0x2a, 0x85, 0x03,
          0x64, 0x05 };
static const uchar _dn_oid_inn[] =       { 0x06, 0x08, 0x2a, 0x85, 0x03,
          0x03, 0x81, 0x03, 0x01, 0x01 };
static const uchar _dn_oid_street_address[] = { 0x06, 0x03, 0x55, 0x04, 0x09 };

/*
 * Most RDN values are encoded using the directory string type
 * defined below. This function performs the required check to
 * verify the given string is a valid DirectoryString. The
 * function returns 0 on success and -1 on error.
 *
 * This is an error if the length does not match that of the
 * string, if buffer is too short or too long for the encoded
 * string.
 *
 *  DirectoryString ::= CHOICE {
 *        teletexString           TeletexString (SIZE (1..MAX)),
 *        printableString         PrintableString (SIZE (1..MAX)),
 *        universalString         UniversalString (SIZE (1..MAX)),
 *        utf8String              UTF8String (SIZE (1..MAX)),
 *        bmpString               BMPString (SIZE (1..MAX)) }
 *
 *
 * 'len' is the size of given buffer, including string type
 * and string length. 'lb' and 'ub' are respectively lower and
 * upper bounds for the effective string.
 *
 * Note that RFC 5280 has the following: "upper bounds on string types,
 * such as TeletexString, are measured in characters.  Excepting
 * PrintableString or IA5String, a significantly greater number of
 * octets will be required to hold  such a value.  As a minimum, 16
 * octets, or twice the specified  upper bound, whichever is the larger,
 * should be allowed for TeletexString.  For UTF8String or UniversalString
 * at least four times the upper bound should be allowed.
 *
 */
#define STR_TYPE_UTF8_STRING      12
#define STR_TYPE_NUMERIC_STRING   18
#define STR_TYPE_PRINTABLE_STRING 19
#define STR_TYPE_TELETEX_STRING   20
#define STR_TYPE_IA5_STRING       22
#define STR_TYPE_VISIBLE_STRING   26
#define STR_TYPE_UNIVERSAL_STRING 28
#define STR_TYPE_BMP_STRING       30
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_directory_string(const uchar *buf, uint len, uint lb, uint ub)
{
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar str_type;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];

  len -= 2;
  if (buf[1] != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  if ((len < lb) || (len > ub)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  switch (str_type) {
  case STR_TYPE_PRINTABLE_STRING:
    ret = check_printable_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case STR_TYPE_UTF8_STRING:
    ret = check_utf8_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
#ifdef TEMPORARY_LAXIST_DIRECTORY_STRING
    /*
     * Section 4.1.2.4 of RFC 5280 has "CAs conforming to this
     * profile MUST use either the PrintableString or UTF8String
     * encoding of DirectoryString, with two exceptions
     */
  case STR_TYPE_TELETEX_STRING:
    ret = check_teletex_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case STR_TYPE_UNIVERSAL_STRING:
    ret = check_universal_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case STR_TYPE_BMP_STRING:
    ret = check_bmp_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case STR_TYPE_IA5_STRING:
    ret = check_ia5_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  case STR_TYPE_NUMERIC_STRING:
    ret = check_numeric_string(buf, len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
#endif
  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    break;
  }

  if (ret) {
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Some RDN values are specifically encoded as PrintableString and the usual
 * directoryString. The function verifies that. It returns -1 on error, 0
 * on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_printable_string(const uchar *buf, uint len, uint lb, uint ub)
{
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar str_type;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];
  if (str_type != STR_TYPE_PRINTABLE_STRING) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= 2;
  if (buf[1] != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  if ((len < lb) || (len > ub)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = check_printable_string(buf, len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * Some RDN values are specifically encoded as NumericString. The function
 * verifies that. It returns -1 on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_numeric_string(const uchar *buf, uint len, uint lb, uint ub)
{
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar str_type;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];
  if (str_type != STR_TYPE_NUMERIC_STRING) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= 2;
  if (buf[1] != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  if ((len < lb) || (len > ub)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = check_numeric_string(buf, len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*
 * As pointed by RFC 4519 and described by RFC 4517, IA5String
 * is defined in ABNF form as *(%x00-7F).
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
int parse_ia5_string(const uchar *buf, uint len, uint lb, uint ub)
{
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar str_type;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];
  if (str_type != STR_TYPE_IA5_STRING) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= 2;
  if (buf[1] != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  if ((len < lb) || (len > ub)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = check_ia5_string(buf, len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

#ifdef TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_utf8_string(const uchar *buf, uint len, uint lb, uint ub)
{
  int ret = -X509_FILE_LINE_NUM_ERR;
  uchar str_type;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  if (len < 2) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];
  if (str_type != STR_TYPE_IA5_STRING) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  len -= 2;
  if (buf[1] != len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  buf += 2;

  if ((len < lb) || (len > ub)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = check_utf8_string(buf, len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}
#endif

/*
 *
 * -- Naming attributes of type X520CommonName:
 * --   X520CommonName ::= DirectoryName (SIZE (1..ub-common-name))
 * --
 * -- Expanded to avoid parameterized type:
 * X520CommonName ::= CHOICE {
 *       teletexString     TeletexString   (SIZE (1..ub-common-name)),
 *       printableString   PrintableString (SIZE (1..ub-common-name)),
 *       universalString   UniversalString (SIZE (1..ub-common-name)),
 *       utf8String        UTF8String      (SIZE (1..ub-common-name)),
 *       bmpString         BMPString       (SIZE (1..ub-common-name)) }
 */
#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_COMMON_NAME 192
#else
#define UB_COMMON_NAME 64
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_cn(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_COMMON_NAME);
}

#define UB_NAME 32768
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_x520name(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_NAME);
}

#define UB_EMAILADDRESS 255
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_emailaddress(const uchar *buf, uint len)
{
  int ret;

  /* RFC 5280 has:
   *
   * "Legacy implementations exist where an electronic mail address is
   * embedded in the subject distinguished name as an emailAddress
   * attribute [RFC2985].  The attribute value for emailAddress is of
   * type IA5String to permit inclusion of the character '@', which is
   * not part of the PrintableString character set.  emailAddress
   * attribute values are not case-sensitive (e.g.,
   * "subscriber@example.com" is the same as "SUBSCRIBER@EXAMPLE.COM").
   *
   * Conforming implementations generating new certificates with
   * electronic mail addresses MUST use the rfc822Name in the subject
   * alternative name extension (Section 4.2.1.6) to describe such
   * identities.  Simultaneous inclusion of the emailAddress attribute
   * in the subject distinguished name to support legacy implementations
   * is deprecated but permitted."
   */
  ret = parse_ia5_string(buf, len, 1, UB_EMAILADDRESS);

  /*
   * As a side note, tests performed on our set indicates some
   * implementations currently use UTF8 encoding for emailAddress.
   * Hence the quirks below to support the (invalid) certificates
   * generated by those implementations.
   */
#ifdef TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING
  if (ret) {
    ret = parse_utf8_string(buf, len, 1, UB_EMAILADDRESS);
  }
#endif

  return ret;
}

#define UB_SERIAL_NUMBER 64
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_serial(const uchar *buf, uint len)
{
  int ret;

  ret = parse_printable_string(buf, len, 1, UB_SERIAL_NUMBER);
  if (ret) {
#ifdef TEMPORARY_LAXIST_SERIAL_RDN_AS_IA5STRING
    ret = parse_ia5_string(buf, len, 1, UB_SERIAL_NUMBER);
#endif
  }

  return ret;
}

#define UB_COUNTRY 2
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_country(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, UB_COUNTRY, UB_COUNTRY);
}

#define UB_LOCALITY_NAME 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_locality(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_LOCALITY_NAME);
}

#define UB_STATE_NAME 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_state(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_STATE_NAME);
}

#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_ORGANIZATION_NAME 64
#else
#define UB_ORGANIZATION_NAME 128
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_org(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_ORGANIZATION_NAME);
}

#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_ORGANIZATION_UNIT_NAME 128
#else
#define UB_ORGANIZATION_UNIT_NAME 64
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_org_unit(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_ORGANIZATION_UNIT_NAME);
}

#define UB_TITLE_NAME 64
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_title(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_TITLE_NAME);
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_dn_qual(const uchar *buf, uint len)
{
  /*
   * There is no specific limit on that one, so giving the maximum
   * buffer size we support will do the job.
   */
  return parse_printable_string(buf, len, 1, ASN1_MAX_BUFFER_SIZE);
}

/*@
  @ assigns \nothing;
  @*/
static inline int _is_digit(uchar c)
{
  return ((c >= '0') && (c <= '9'));
}

/*@
  @ assigns \nothing;
  @*/
static inline int _is_alpha(uchar c)
{
  return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')));
}

/*
 * As point in RFC 5280 and defined in section 2.4 of RFC 4519,
 * 'dc' (domainComponent) is a string attribute type holding a
 * DNS label. It is encoded as an IA5String. The ABNF for the
 * label is the following:
 *
 * label = (ALPHA / DIGIT) [*61(ALPHA / DIGIT / HYPHEN) (ALPHA / DIGIT)]
 * ALPHA   = %x41-5A / %x61-7A     ; "A"-"Z" / "a"-"z"
 * DIGIT   = %x30-39               ; "0"-"9"
 * HYPHEN  = %x2D                  ; hyphen ("-")
 *
 * To simplify things, we first verify this is a valid IA5string and then
 * verify the additional restrictions given above for the label.
 *
 * Note that RFC 2181 (Clarifications on DNS) has the following: "The DNS
 * itself places only one restriction on the particular labels that can
 * be used to identify resource records.  That one restriction relates
 * to the length of the label and the full name...". In the case of dc
 * attributes, limitations are imposed by the use of IA5String for
 * encoding and by the ABNF above.
 */
#define UB_DC 63
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_dc(const uchar *buf, uint len)
{
  int ret;
  uint i;
  uchar c;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* We expect an IA5String */
  ret = parse_ia5_string(buf, len, 1, UB_DC);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += 2;
  len -= 2;

  /* Restriction on first byte */
  c = buf[0];
  ret = _is_alpha(c) || _is_digit(c);
  if (!ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += 1;
  len -= 1;

  if (!len) { /* over ? */
    ret = 0;
    goto out;
  }

  /* Restriction on last byte if any */
  c = buf[len - 1];
  ret = _is_alpha(c) || _is_digit(c);
  if (!ret) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += 1;
  len -= 1;

  /* Restriction on middle bytes */
  /*@
    @ loop invariant 0 <= i <= len;
    @ loop assigns c, ret, i;
    @ loop variant (len - i);
    @ */
  for (i = 0; i < len; i++) {
    c = buf[i];
    ret = _is_digit(c) || _is_alpha(c) || (c == '-');
    if (!ret) {
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }
  }

  ret = 0;

out:
  return ret;
}

#define UB_PSEUDONYM 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_pseudo(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_PSEUDONYM);
}


/* From section 5.1 of draft-deremin-rfc4491-bis-01 */

/* OGRN is the main state registration number of juridical entities */
#define UB_OGRN 13
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_ogrn(const uchar *buf, uint len)
{
  return parse_numeric_string(buf, len, 1, UB_OGRN);
}

/* SNILS is the individual insurance account number */
#define UB_SNILS 11
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_snils(const uchar *buf, uint len)
{
  return parse_numeric_string(buf, len, 1, UB_SNILS);
}

/*
 * OGRNIP is the main state registration number of individual
 * enterpreneurs
 */
#define UB_OGRNIP 15
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_ogrnip(const uchar *buf, uint len)
{
  return parse_numeric_string(buf, len, 1, UB_OGRNIP);
}

/* INN is the individual taxpayer number (ITN). */
#define UB_INN 12
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_inn(const uchar *buf, uint len)
{
  return parse_numeric_string(buf, len, 1, UB_INN);
}

/* street address. */
#define UB_STREET_ADDRESS 64 /* XXX FIXME Don't know what the limit is */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_street_address(const uchar *buf, uint len)
{
  return parse_directory_string(buf, len, 1, UB_STREET_ADDRESS);
}

typedef struct {
  const uchar *oid;
  uchar oid_len;
  int (*parse_rdn_val)(const uchar *buf, uint len);
} _name_oid;

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_bad_oid(const uchar *buf, uint len)
{
  (void) buf;
  (void) len;
  return 0;
}

static const _name_oid generic_unsupported_rdn_oid = {
  .oid = NULL,
  .oid_len = 0,
  .parse_rdn_val = parse_rdn_val_bad_oid
};

static const _name_oid known_dn_oids[] = {
  { .oid = _dn_oid_cn,
    .oid_len = sizeof(_dn_oid_cn),
    .parse_rdn_val = parse_rdn_val_cn
  },
  { .oid = _dn_oid_surname,
    .oid_len = sizeof(_dn_oid_surname),
    .parse_rdn_val = parse_rdn_val_x520name
  },
  { .oid = _dn_oid_serial,
    .oid_len = sizeof(_dn_oid_serial),
    .parse_rdn_val = parse_rdn_val_serial
  },
  { .oid = _dn_oid_country,
    .oid_len = sizeof(_dn_oid_country),
    .parse_rdn_val = parse_rdn_val_country
  },
  { .oid = _dn_oid_locality,
    .oid_len = sizeof(_dn_oid_locality),
    .parse_rdn_val = parse_rdn_val_locality
  },
  { .oid = _dn_oid_state,
    .oid_len = sizeof(_dn_oid_state),
    .parse_rdn_val = parse_rdn_val_state
  },
  { .oid = _dn_oid_org,
    .oid_len = sizeof(_dn_oid_org),
    .parse_rdn_val = parse_rdn_val_org
  },
  { .oid = _dn_oid_org_unit,
    .oid_len = sizeof(_dn_oid_org_unit),
    .parse_rdn_val = parse_rdn_val_org_unit
  },
  { .oid = _dn_oid_title,
    .oid_len = sizeof(_dn_oid_title),
    .parse_rdn_val = parse_rdn_val_title
  },
  { .oid = _dn_oid_name,
    .oid_len = sizeof(_dn_oid_name),
    .parse_rdn_val = parse_rdn_val_x520name
  },
  { .oid = _dn_oid_emailaddress,
    .oid_len = sizeof(_dn_oid_emailaddress),
    .parse_rdn_val = parse_rdn_val_emailaddress
  },
  { .oid = _dn_oid_given_name,
    .oid_len = sizeof(_dn_oid_given_name),
    .parse_rdn_val = parse_rdn_val_x520name
  },
  { .oid = _dn_oid_initials,
    .oid_len = sizeof(_dn_oid_initials),
    .parse_rdn_val = parse_rdn_val_x520name
  },
  { .oid = _dn_oid_gen_qual,
    .oid_len = sizeof(_dn_oid_gen_qual),
    .parse_rdn_val = parse_rdn_val_x520name
  },
  { .oid = _dn_oid_dn_qual,
    .oid_len = sizeof(_dn_oid_dn_qual),
    .parse_rdn_val = parse_rdn_val_dn_qual
  },
  { .oid = _dn_oid_pseudo,
    .oid_len = sizeof(_dn_oid_pseudo),
    .parse_rdn_val = parse_rdn_val_pseudo
  },
  { .oid = _dn_oid_dc,
    .oid_len = sizeof(_dn_oid_dc),
    .parse_rdn_val = parse_rdn_val_dc
  },
  { .oid = _dn_oid_ogrn,
    .oid_len = sizeof(_dn_oid_ogrn),
    .parse_rdn_val = parse_rdn_val_ogrn
  },
  { .oid = _dn_oid_snils,
    .oid_len = sizeof(_dn_oid_snils),
    .parse_rdn_val = parse_rdn_val_snils
  },
  { .oid = _dn_oid_ogrnip,
    .oid_len = sizeof(_dn_oid_ogrnip),
    .parse_rdn_val = parse_rdn_val_ogrnip
  },
  { .oid = _dn_oid_inn,
    .oid_len = sizeof(_dn_oid_inn),
    .parse_rdn_val = parse_rdn_val_inn
  },
  { .oid = _dn_oid_street_address,
    .oid_len = sizeof(_dn_oid_street_address),
    .parse_rdn_val = parse_rdn_val_street_address
  },
};

#define NUM_KNOWN_DN_OIDS (sizeof(known_dn_oids) / sizeof(known_dn_oids[0]))

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \forall integer i ; 0 <= i < NUM_KNOWN_DN_OIDS ==> \valid_read(&known_dn_oids[i]);
  @ requires \forall integer i ; 0 <= i < NUM_KNOWN_DN_OIDS ==> \valid_function((known_dn_oids[i]).parse_rdn_val);
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_DN_OIDS && \result == &known_dn_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \result;
  @*/
static const _name_oid * find_dn_by_oid(const uchar *buf, uint len)
{
  const _name_oid *found = NULL;
  const _name_oid *cur = NULL;
  uchar k;

  if ((buf == NULL) || (len == 0)) {
    goto out;
  }

  /*@ loop unroll NUM_KNOWN_DN_OIDS ;
    @ loop invariant 0 <= k <= NUM_KNOWN_DN_OIDS;
    @ loop invariant found == NULL;
    @ loop assigns cur, found, k;
    @ loop variant (NUM_KNOWN_DN_OIDS - k);
    @*/
  for (k = 0; k < NUM_KNOWN_DN_OIDS; k++) {
    int ret;

    cur = &known_dn_oids[k];

    /*@ assert cur == &known_dn_oids[k];*/
    /*@ assert \valid_function(cur->parse_rdn_val); */
    if (cur->oid_len != len) {
      continue;
    }

    /*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
    ret = !bufs_differ(cur->oid, buf, cur->oid_len);
    if (ret) {
      found = cur;
      /*@ assert \valid_function(found->parse_rdn_val); */
      break;
    }
  }
  /*@ assert (found != NULL) ==> \valid_function(found->parse_rdn_val); */

out:
  /*@ assert (found != NULL) ==> \valid_function(found->parse_rdn_val); */
  return found;
}


/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(buf+(..), eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_AttributeTypeAndValue(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0;
  uint data_len = 0;
  uint oid_len = 0;
  uint parsed;
  const _name_oid *cur = NULL;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* ... of SEQUENCEs ... */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  parsed = hdr_len + data_len;
  /*@ assert parsed <= len ; */

  buf += hdr_len;
  len -= hdr_len;

  /* ... Containing an OID ... */
  ret = parse_OID(buf, data_len, &oid_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  cur = find_dn_by_oid(buf, oid_len);
  if (cur == NULL) {
#ifndef TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_RDN_OIDS
    /*
     * OID not found => over. The trick below is a nop
     * to let generic_unsupported_rdn_oid and
     * parse_rdn_val_bad_oid() it contains be available
     * and defined for Frama-C in all cases for the assert
     * and calls just below.
     */
    (void)generic_unsupported_rdn_oid;
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
#else
    cur = &generic_unsupported_rdn_oid;
#endif
  }

  data_len -= oid_len;
  buf += oid_len;

  /*
   * Let's now check the value associated w/ and
   * following the OID has a valid format.
   */
  /*@ assert cur->parse_rdn_val \in {
      parse_rdn_val_cn, parse_rdn_val_x520name,
      parse_rdn_val_serial, parse_rdn_val_country,
      parse_rdn_val_locality, parse_rdn_val_state,
      parse_rdn_val_org, parse_rdn_val_org_unit,
      parse_rdn_val_title,  parse_rdn_val_dn_qual,
      parse_rdn_val_pseudo, parse_rdn_val_dc,
      parse_rdn_val_ogrn, parse_rdn_val_snils,
      parse_rdn_val_ogrnip, parse_rdn_val_inn,
      parse_rdn_val_street_address,
      parse_rdn_val_emailaddress,
      parse_rdn_val_bad_oid };
    @*/
  /*@ calls parse_rdn_val_cn, parse_rdn_val_x520name,
      parse_rdn_val_serial, parse_rdn_val_country,
      parse_rdn_val_locality, parse_rdn_val_state,
      parse_rdn_val_org, parse_rdn_val_org_unit,
      parse_rdn_val_title, parse_rdn_val_dn_qual,
      parse_rdn_val_pseudo, parse_rdn_val_dc,
      parse_rdn_val_ogrn, parse_rdn_val_snils,
      parse_rdn_val_ogrnip, parse_rdn_val_inn,
      parse_rdn_val_street_address,
      parse_rdn_val_emailaddress,
      parse_rdn_val_bad_oid;
    @*/
  ret = cur->parse_rdn_val(buf, data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = parsed;
  /*@ assert *eaten <= \at(len,Pre) ; */

  ret = 0;

out:
  return ret;
}


/*
 *  RelativeDistinguishedName ::=
 *    SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_RelativeDistinguishedName(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0;
  uint data_len = 0;
  uint rdn_remain, saved_rdn_len;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Each RDN is a SET ... */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SET,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  saved_rdn_len = hdr_len + data_len;
  buf += hdr_len;
  rdn_remain = data_len;

  /*@
    @ loop assigns ret, buf, rdn_remain;
    @ loop invariant \valid_read(buf + (0 .. (rdn_remain - 1)));
    @ loop variant rdn_remain;
    @ */
  while (rdn_remain) {
    uint parsed = 0;

    ret = parse_AttributeTypeAndValue(buf, rdn_remain, &parsed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    /*
     * FIXME! we should check the amount of AttributeTypeAndValue
     * elements is between 1 and MAX
     */

    rdn_remain -= parsed;
    buf += parsed;
  }

  *eaten = saved_rdn_len;

  ret = 0;

out:
  return ret;
}

/*
 * Used for Issuer and subject
 *
 *  Name ::= CHOICE { -- only one possibility for now --
 *    rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * Here is what section 4.1.2.4 of RFC 5280 has:
 *
 * As noted above, distinguished names are composed of attributes.  This
 * specification does not restrict the set of attribute types that may
 * appear in names.  However, conforming implementations MUST be
 * prepared to receive certificates with issuer names containing the set
 * of attribute types defined below.  This specification RECOMMENDS
 * support for additional attribute types.
 *
 * Standard sets of attributes have been defined in the X.500 series of
 * specifications [X.520].  Implementations of this specification MUST
 * be prepared to receive the following standard attribute types in
 * issuer and subject (Section 4.1.2.6) names:
 *
 *    * country,
 *    * organization,
 *    * organizational unit,
 *    * distinguished name qualifier,
 *    * state or province name,
 *    * common name (e.g., "Susan Housley"), and
 *    * serial number.
 *
 * In addition, implementations of this specification SHOULD be prepared
 * to receive the following standard attribute types in issuer and
 * subject names:
 *
 *    * locality,
 *    * title,
 *    * surname,
 *    * given name,
 *    * initials,
 *    * pseudonym, and
 *    * generation qualifier (e.g., "Jr.", "3rd", or "IV").
 *
 * The syntax and associated object identifiers (OIDs) for these
 * attribute types are provided in the ASN.1 modules in Appendix A.
 *
 * In addition, implementations of this specification MUST be prepared
 * to receive the domainComponent attribute, as defined in [RFC4519].
 * The Domain Name System (DNS) provides a hierarchical resource
 * labeling system.  This attribute provides a convenient mechanism for
 * organizations that wish to use DNs that parallel their DNS names.
 * This is not a replacement for the dNSName component of the
 * alternative name extensions.  Implementations are not required to
 * convert such names into DNS names.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (empty != NULL) ==> \valid(empty);
  @ requires \separated(eaten, empty, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> ((*empty == 0) || (*empty == 1));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *empty;
  @*/
int parse_x509_Name(const uchar *buf, uint len, uint *eaten, int *empty)
{
  uint name_hdr_len = 0;
  uint name_data_len = 0;
  uint remain = 0;
  int ret;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /* Check we are dealing with a valid sequence */
  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
         &name_hdr_len, &name_data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += name_hdr_len;
  remain = name_data_len;

  /*@
    @ loop assigns ret, buf, remain;
    @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
    @ loop variant remain;
    @ */
  while (remain) {
    uint parsed = 0;

    ret = parse_RelativeDistinguishedName(buf, remain, &parsed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += parsed;
    remain -= parsed;
  }

  *eaten = name_hdr_len + name_data_len;
  *empty = !name_data_len;
  /*@ assert (*empty == 0) ||  (*empty == 1); */

  ret = 0;

out:
  return ret;
}


/*
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
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
int parse_DisplayText(const uchar *buf, uint len, uint *eaten)
{
  uint hdr_len = 0, data_len = 0;
  uchar str_type;
  int ret = -1;

  if ((buf == NULL) || (len == 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  str_type = buf[0];

  switch (str_type) {
  case STR_TYPE_UTF8_STRING:    /* UTF8String */
  case STR_TYPE_IA5_STRING:     /* IA5String */
  case STR_TYPE_VISIBLE_STRING: /* VisibileString */
  case STR_TYPE_BMP_STRING:     /* BMPString */
    ret = parse_id_len(buf, len, CLASS_UNIVERSAL, str_type,
           &hdr_len, &data_len);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
    }

    buf += hdr_len;

    switch (str_type) {
    case STR_TYPE_UTF8_STRING:
      ret = check_utf8_string(buf, data_len);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }
      break;
    case STR_TYPE_IA5_STRING:
      ret = check_ia5_string(buf, data_len);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }
      break;
    case STR_TYPE_VISIBLE_STRING:
      ret = check_visible_string(buf, data_len);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }
      break;
    case STR_TYPE_BMP_STRING:
      ret = check_bmp_string(buf, data_len);
      if (ret) {
        ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
        goto out;
      }
      break;
    default:
      ret = -X509_FILE_LINE_NUM_ERR;
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
      goto out;
      break;
    }

    *eaten = hdr_len + data_len;

    break;
  default:
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
    break;
  }

out:
  return ret;
}



/*
 * RFC 8410 defines Agorithm Identifiers for Ed25519 and Ed448
 *
 * The same algorithm identifiers are used for signatures as are used
 * for public keys.  When used to identify signature algorithms, the
 * parameters MUST be absent.
 */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires (r_start_off != NULL) ==> \valid(r_start_off);
  @ requires (r_len != NULL) ==> \valid(r_len);
  @ requires (s_start_off != NULL) ==> \valid(s_start_off);
  @ requires (s_len != NULL) ==> \valid(s_len);
  @ requires \separated(eaten, cert+(..), r_start_off, r_len, s_start_off, s_len);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (((ulong)*r_start_off + (ulong)*r_len) <= (ulong)off + (ulong)len);
  @ ensures (\result == 0) ==> (((ulong)*s_start_off + (ulong)*s_len) <= (ulong)off + (ulong)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (r_start_off == \null) ==> \result < 0;
  @ ensures (r_len == \null) ==> \result < 0;
  @ ensures (s_start_off == \null) ==> \result < 0;
  @ ensures (s_len == \null) ==> \result < 0;
  @
  @ assigns *eaten, *r_start_off, *r_len, *s_start_off, *s_len;
  @*/
int parse_sig_eddsa(const uchar *cert, uint off, uint len, uint exp_sig_len,
        uint *r_start_off, uint *r_len, uint *s_start_off, uint *s_len,
        uint *eaten)
{
  uint comp_len, sig_len = 0, hdr_len = 0, data_len = 0, remain = 0;
  const uchar *buf = cert + off;
  int ret;

  if ((cert == NULL) || (len == 0) || (eaten == NULL) ||
      (r_start_off == NULL) || (r_len == NULL) ||
      (s_start_off == NULL) || (s_len == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
         &hdr_len, &data_len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  buf += hdr_len;

  if (len != (hdr_len + data_len)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert hdr_len + data_len == len; */

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
  sig_len = data_len - 1;
  if (sig_len != exp_sig_len) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  comp_len = sig_len / 2;

  if (sig_len != (comp_len * 2)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }
  /*@ assert sig_len == 2 * comp_len; */

  *r_start_off = off + hdr_len + 1;
  *r_len = comp_len;
  /*@ assert *r_len == comp_len; */
  /*@ assert (ulong)*r_start_off + (ulong)*r_len <= (ulong)off + (ulong)len; */

  *s_start_off = off + hdr_len + 1 + comp_len;
  *s_len = comp_len;
  /*@ assert *s_len == comp_len; */
  /*@ assert ((ulong)*s_start_off + (ulong)*s_len) <= (ulong)off + (ulong)len; */

  /*
   * Check there is nothing remaining in the bitstring
   * after the two integers
   */
  if (remain != 0) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  *eaten = hdr_len + data_len;
  ret = 0;
  /*@ assert ((ulong)*r_start_off + (ulong)*r_len) <= (ulong)off + (ulong)len; */
  /*@ assert ((ulong)*s_start_off + (ulong)*s_len) <= (ulong)off + (ulong)len; */

out:
  return ret;
}


#define ED25519_SIG_LEN 64
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (eaten != NULL) ==> \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
      params->ed25519.r_raw_off,
      params->ed25519.r_raw_len,
      params->ed25519.s_raw_off,
      params->ed25519.s_raw_len;
  @*/
int parse_sig_ed25519(sig_params *params,
          const uchar *cert, uint off, uint len, uint *eaten)
{
  int ret;

  if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_sig_eddsa(cert, off, len, ED25519_SIG_LEN,
            &params->ed25519.r_raw_off,
            &params->ed25519.r_raw_len,
            &params->ed25519.s_raw_off,
            &params->ed25519.s_raw_len,
            eaten);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}


/*
 * RFC 8410 has: "For all of the OIDs, the parameters MUST be absent."
 * This is what the function enforces. This applies to both signature
 * parameters and SPKI parameters. We have a specific helper for each
 * case.
 */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((params != \null)) ==> \valid(params);
  @ requires ((hash_alg != \null)) ==> \valid(hash_alg);
  @ requires \separated(cert+(..), params, hash_alg);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @ ensures (hash_alg == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
int parse_algoid_sig_params_eddsa(sig_params *params, hash_alg_id *hash_alg,
           const uchar *cert, uint ATTRIBUTE_UNUSED off, uint len)
{
  int ret;

  if ((params == NULL) || (hash_alg == NULL) || (cert == NULL) || (len != 0)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = 0;

out:
  return ret;
}

/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((params != \null)) ==> \valid(params);
  @ requires ((hash_alg != \null)) ==> \valid(hash_alg);
  @ requires \separated(cert+(..), params, hash_alg);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @ ensures (hash_alg == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
int parse_algoid_sig_params_none(sig_params *params, hash_alg_id *hash_alg,
          const uchar *cert, uint off, uint len)
{
  int ret;

  if ((params == NULL) || (hash_alg == NULL)) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  ret = parse_algoid_params_none(cert, off, len);
  if (ret) {
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

out:
  return ret;
}

/*
 * Handles expected lack of optinal parameters associated with sig and pubkey
 * OID. The function also support the case where lack of parames has been
 * implemented by some software by a adding a NULL instead of nothing.
 * We define specific sig and pubky function from that one below.
 */
/*@
  @ requires ((ulong)off + (ulong)len) <= UINT_MAX;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
int parse_algoid_params_none(const uchar *cert, uint off, uint len)
{
  const uchar *buf = cert + off;
  uint parsed = 0;
  int ret;

  if (cert == NULL) {
    ret = -X509_FILE_LINE_NUM_ERR;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    goto out;
  }

  /*@ assert (len > 0) ==> \valid_read(buf + (0 .. len - 1)); */

  switch (len) {
  case 0: /* Nice ! */
    ret = 0;
    break;
  case 2: /* Null ? */
    ret = parse_null(buf, len, &parsed);
    if (ret) {
      ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    }
    break;
  default: /* Crap ! */
    ret = -1;
    ERROR_TRACE_APPEND(X509_FILE_LINE_NUM_ERR);
    break;
  }

out:
  return ret;
}


/*@
  @ requires na_year <= 9999;
  @ requires na_month <= 12;
  @ requires na_day <= 31;
  @ requires na_hour <= 23;
  @ requires na_min <= 59;
  @ requires na_sec <= 59;
  @
  @ ensures \result < (1ULL << 55);
  @
  @ assigns \nothing;
  @*/
ulong time_components_to_comparable_u64(ushort na_year, uchar na_month, uchar na_day,
              uchar na_hour, uchar na_min, uchar na_sec)
{
  ulong res, tmp;

  res = ((ulong)na_sec);                 /* start with seconds */
  /*@ assert res < (1ULL << 6); */

  tmp = ((ulong)na_min) * (1ULL << 8);            /* add shifted minutes */
  /*@ assert tmp < (1ULL << 14); */
  res += tmp;
  /*@ assert res < (1ULL << 15); */

  tmp = (((ulong)na_hour) * (1ULL << 16));        /* add shifted hours */
  /*@ assert tmp < (1ULL << 21); */
  res += tmp;
  /*@ assert res < (1ULL << 22); */

  tmp = ((ulong)na_day) * (1ULL << 24);           /* add shifted days */
  /*@ assert tmp < (1ULL << 29); */
  res += tmp;
  /*@ assert res < (1ULL << 30); */

  tmp = ((ulong)na_month) * (1ULL << 32);         /* add shifted days */
  /*@ assert tmp < (1ULL << 36); */
  res += tmp;
  /*@ assert res < (1ULL << 37); */

  tmp = ((ulong)na_year) * (1ULL << 40);         /* add shifted years */
  /*@ assert tmp < (1ULL << 54); */
  res += tmp;
  /*@ assert res < (1ULL << 55); */

  return res;
}

