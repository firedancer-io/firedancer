#include "fd_x509_verify.h"
#include "fd_der.h"
#include "../ed25519/fd_ed25519.h"
#include "../secp256r1/fd_secp256r1.h"
#include "../secp384r1/fd_secp384r1.h"
#include <string.h>

/* fd_x509_verify_sig verifies a certificate's signature given the
   issuer's public key.  Returns 0 on success, non-zero on failure. */

static int
fd_x509_verify_sig( fd_x509_cert_info_t const * cert,
                    uchar const *               issuer_pubkey,
                    ulong                       issuer_pubkey_len,
                    uchar                       issuer_key_type ) {

  switch( cert->sig_alg ) {

  case FD_X509_SIG_ED25519: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ED25519 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 32 ) ) return -1;
    if( FD_UNLIKELY( cert->sig_len != 64 ) ) return -1;

    fd_sha512_t sha512[1];
    int err = fd_ed25519_verify( cert->tbs, cert->tbs_len, cert->sig, issuer_pubkey, sha512 );
    return ( err == FD_ED25519_SUCCESS ) ? 0 : -1;
  }

  case FD_X509_SIG_ECDSA_SHA256: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ECDSA_P256 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 65 ) ) return -1;

    uchar raw_sig[64];
    if( FD_UNLIKELY( fd_x509_decode_ecdsa_sig( cert->sig, cert->sig_len, raw_sig, 32 ) ) )
      return -1;

    uchar compressed_pk[33];
    if( FD_UNLIKELY( fd_x509_ec_point_compress( issuer_pubkey, 32, compressed_pk ) ) )
      return -1;

    fd_sha256_t sha256[1];
    int err = fd_secp256r1_verify_allow_high_s( cert->tbs, cert->tbs_len, raw_sig, compressed_pk, sha256 );
    return ( err == FD_SECP256R1_SUCCESS ) ? 0 : -1;
  }

  case FD_X509_SIG_ECDSA_SHA384: {
    if( FD_UNLIKELY( issuer_key_type != FD_X509_KEY_ECDSA_P384 ) ) return -1;
    if( FD_UNLIKELY( issuer_pubkey_len != 97 ) ) return -1;

    uchar raw_sig[96];
    if( FD_UNLIKELY( fd_x509_decode_ecdsa_sig( cert->sig, cert->sig_len, raw_sig, 48 ) ) )
      return -1;

    uchar compressed_pk[49];
    if( FD_UNLIKELY( fd_x509_ec_point_compress( issuer_pubkey, 48, compressed_pk ) ) )
      return -1;

    fd_sha512_t sha384[1];
    int err = fd_secp384r1_verify_allow_high_s( cert->tbs, cert->tbs_len, raw_sig, compressed_pk, sha384 );
    return ( err == FD_SECP384R1_SUCCESS ) ? 0 : -1;
  }

  default:
    return 1;  /* unsupported sig algorithm */
  }
}

/* fd_x509_check_validity returns FD_X509_VERIFY_OK if cert is within its
   validity period at unix_seconds, otherwise the error to report. */

static int
fd_x509_check_validity( fd_x509_cert_info_t const * cert,
                        long                        unix_seconds ) {
  if( FD_UNLIKELY( cert->not_before_unix==FD_X509_TIME_INVALID ||
                   cert->not_after_unix ==FD_X509_TIME_INVALID ) )
    return FD_X509_VERIFY_ERR_TIME_PARSE;
  if( FD_UNLIKELY( unix_seconds < cert->not_before_unix ) )
    return FD_X509_VERIFY_ERR_NOT_YET_VALID;
  if( FD_UNLIKELY( unix_seconds > cert->not_after_unix ) )
    return FD_X509_VERIFY_ERR_EXPIRED;
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_eku returns OK if cert may be used for TLS server
   authentication.  An absent extKeyUsage is unconstrained. */

static int
fd_x509_check_eku( fd_x509_cert_info_t const * cert ) {
  if( FD_UNLIKELY(
        cert->has_ext_key_usage &&
        !( cert->ext_key_usage & ( FD_X509_EKU_SERVER_AUTH|FD_X509_EKU_ANY ) ) ) ) {
    return FD_X509_VERIFY_ERR_EXT_KEY_USAGE;
  }
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_leaf_usage enforces the TLS 1.3 server authentication
   usage policy on the leaf.  */

static int
fd_x509_check_leaf_usage( fd_x509_cert_info_t const * leaf ) {
  if( FD_UNLIKELY(
      leaf->has_key_usage &&
      !( leaf->key_usage & FD_X509_KU_DIGITAL_SIGNATURE ) ) ) {
    return FD_X509_VERIFY_ERR_KEY_USAGE;
  }
  return fd_x509_check_eku( leaf );
}


static int
fd_x509_dns_constraint_matches( uchar const * constraint,
                                ulong         constraint_len,
                                uchar const * name,
                                ulong         name_len,
                                int           excluded ) {
  /* Excluded subtrees reject any overlapping wildcard expansion. */
  if( excluded && name_len>2UL && name[0]=='*' && name[1]=='.' ) {
    uchar const * dot = memchr( constraint, '.', constraint_len );
    if( dot ) {
      ulong tail_len = constraint_len-(ulong)( dot+1-constraint );
      if( tail_len==name_len-2UL &&
          fd_x509_dns_eq_ci( (char const *)name+2, (char const *)dot+1, tail_len ) ) return 1;
    }
  }

  int subdomains_only = constraint[0]=='.';
  if( subdomains_only ) {
    if( name_len<=constraint_len ) return 0;
    return fd_x509_dns_eq_ci( (char const *)name+name_len-constraint_len, (char const *)constraint, constraint_len );
  }

  if( name_len<constraint_len ) return 0;
  if( !fd_x509_dns_eq_ci( (char const *)name+name_len-constraint_len, (char const *)constraint, constraint_len ) ) return 0;
  return name_len==constraint_len || name[name_len-constraint_len-1UL]=='.';
}

/* iPAddress subtree base is address||mask (8 or 32 bytes). */

static int
fd_x509_ip_constraint_matches( uchar const * constraint,
                               ulong         constraint_len,
                               uchar const * ip,
                               ulong         ip_len ) {
  if( constraint_len!=2UL*ip_len ) return 0;
  uchar const * mask = constraint+ip_len;
  for( ulong i=0UL; i<ip_len; i++ ) {
    if( (ip[i] & mask[i]) != (constraint[i] & mask[i]) ) return 0;
  }
  return 1;
}

/* fd_x509_subtrees_match matches name against the subtrees of the same
   name form (tag).  Returns:
      1  a subtree matches
      0  subtrees of this form exist, none match
     -1  no subtree of this form (form is unconstrained, RFC 5280 4.2.1.10)
     -2  malformed, or a subtree of a form this verifier cannot match */

static int
fd_x509_subtrees_match( uchar const * trees,
                        ulong         trees_len,
                        int           tag,
                        uchar const * name,
                        ulong         name_len,
                        int           excluded ) {
  int found = 0;
  fd_der_cursor_t c = { .p=trees, .end=trees+trees_len };
  while( FD_DER_HAS_MORE( c ) ) {
    int tree_tag; ulong tree_len;
    if( FD_UNLIKELY( fd_der_read_tl( &c, &tree_tag, &tree_len ) ||
                     tree_tag!=(int)FD_DER_TAG_SEQUENCE ) ) return -2;
    fd_der_cursor_t t = { .p=c.p, .end=c.p+tree_len };
    c.p += tree_len;
    int base_tag; ulong base_len;
    if( FD_UNLIKELY( fd_der_read_tl( &t, &base_tag, &base_len ) ) ) return -2;
    if( base_tag!=tag ) continue;
    found = 1;
    int match;
    switch( tag ) {
    case FD_DER_TAG_CONTEXT_PRIM(2):
      match = fd_x509_dns_constraint_matches( t.p, base_len, name, name_len, excluded );
      break;
    case FD_DER_TAG_CONTEXT_PRIM(7):
      match = fd_x509_ip_constraint_matches( t.p, base_len, name, name_len );
      break;
    case FD_DER_TAG_CONTEXT(4):
      match = fd_x509_name_prefix( t.p, base_len, name, name_len );
      break;
    default:
      /* nameConstraints is critical: a form we cannot match must not
         be accepted (RFC 5280 Section 4.2). */
      return -2;
    }
    if( match ) return 1;
  }
  return found ? 0 : -1;
}

/* fd_x509_name_constrained checks one name against a CA's permitted
   and excluded GeneralSubtrees. */

static int
fd_x509_name_constrained( uchar const * permitted,
                          ulong         permitted_len,
                          uchar const * excluded,
                          ulong         excluded_len,
                          int           tag,
                          uchar const * name,
                          ulong         name_len ) {
  if( excluded_len ) {
    int match = fd_x509_subtrees_match( excluded, excluded_len, tag, name, name_len, 1 );
    if( match==1 || match==-2 ) return FD_X509_VERIFY_ERR_NAME_CONSTRAINT;
  }
  if( permitted_len ) {
    int match = fd_x509_subtrees_match( permitted, permitted_len, tag, name, name_len, 0 );
    if( match==0 || match==-2 ) return FD_X509_VERIFY_ERR_NAME_CONSTRAINT;
  }
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_name_constraints checks the subject DN (against
   directoryName subtrees, RFC 5280 Section 6.1.4 (g)) and each SAN of
   cert against a CA's permitted and excluded GeneralSubtrees.  An
   empty subject is skipped, as in OpenSSL and BoringSSL.  Subject
   emailAddress attributes are not checked against rfc822Name
   subtrees. */

static int
fd_x509_check_name_constraints( int                         has_name_constraints,
                                uchar const *               permitted,
                                ulong                       permitted_len,
                                uchar const *               excluded,
                                ulong                       excluded_len,
                                fd_x509_cert_info_t const * cert ) {
  if( !has_name_constraints ) return FD_X509_VERIFY_OK;

  if( cert->subject_len>2UL ) {
    int err = fd_x509_name_constrained( permitted, permitted_len, excluded, excluded_len,
                                        FD_DER_TAG_CONTEXT(4), cert->subject, cert->subject_len );
    if( FD_UNLIKELY( err ) ) return err;
  }

  if( !cert->has_subject_alt_name ) return FD_X509_VERIFY_OK;

  fd_der_cursor_t san = { .p=cert->san_general_names,
                          .end=cert->san_general_names+cert->san_general_names_len };
  while( FD_DER_HAS_MORE( san ) ) {
    int tag; ulong name_len;
    if( FD_UNLIKELY( fd_der_read_tl( &san, &tag, &name_len ) ) )
      return FD_X509_VERIFY_ERR_NAME_CONSTRAINT;
    uchar const * name = san.p;
    san.p += name_len;

    if( tag==(int)FD_DER_TAG_CONTEXT_PRIM(2) ) {
      int wildcard = name_len>2UL && name[0]=='*' && name[1]=='.';
      if( FD_UNLIKELY( wildcard ? !fd_x509_dns_name_valid( (char const *)name+2, name_len-2UL )
                               : !fd_x509_dns_name_valid( (char const *)name,   name_len     ) ) )
        return FD_X509_VERIFY_ERR_NAME_CONSTRAINT;
    } else if( tag==(int)FD_DER_TAG_CONTEXT_PRIM(7) ) {
      if( FD_UNLIKELY( name_len!=4UL && name_len!=16UL ) )
        return FD_X509_VERIFY_ERR_NAME_CONSTRAINT;
    }

    int err = fd_x509_name_constrained( permitted, permitted_len, excluded, excluded_len,
                                        tag, name, name_len );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_path_name_constraints applies a CA's name constraints
   to every cert in certs[0,cnt).  Name constraints do not apply to
   non-final self-issued certs (RFC 5280 Section 6.1.4 (a)). */

static int
fd_x509_check_path_name_constraints( int                         has_name_constraints,
                                     uchar const *               permitted,
                                     ulong                       permitted_len,
                                     uchar const *               excluded,
                                     ulong                       excluded_len,
                                     fd_x509_cert_info_t const * certs,
                                     ulong                       cnt ) {
  for( ulong j=0UL; j<cnt; j++ ) {
    if( j && fd_x509_name_equal( certs[j].issuer, certs[j].issuer_len,
                                 certs[j].subject, certs[j].subject_len ) ) continue;
    int nc_err = fd_x509_check_name_constraints( has_name_constraints,
                                                 permitted, permitted_len,
                                                 excluded,  excluded_len, &certs[j] );
    if( FD_UNLIKELY( nc_err ) ) return nc_err;
  }
  return FD_X509_VERIFY_OK;
}

/* fd_x509_check_anchor applies the trust anchor's own constraints to
   the path certs[0,cnt) that it terminates: its pathLenConstraint
   against the non_self_issued_ca_cnt intermediate CAs on the path, and
   its name constraints against every cert.  fd_x509_ca_store_load
   already rejected anchors whose extKeyUsage excludes serverAuth. */

static int
fd_x509_check_anchor( fd_x509_ca_entry_t const *  ca,
                      fd_x509_cert_info_t const * certs,
                      ulong                       cnt,
                      ulong                       non_self_issued_ca_cnt ) {
  if( ca->has_path_len_constraint && non_self_issued_ca_cnt>ca->path_len_constraint )
    return FD_X509_VERIFY_ERR_PATH_LEN;
  return fd_x509_check_path_name_constraints(
      ca->has_name_constraints,
      ca->name_constraints,                                   ca->name_constraints_permitted_len,
      ca->name_constraints+ca->name_constraints_permitted_len, ca->name_constraints_excluded_len,
      certs, cnt );
}

/* Implemented as specified by RFC 5280 Section 6.1.3. */
int
fd_x509_verify_chain( uchar const * const *        chain_der,
                      ulong const *                chain_der_sz,
                      ulong                        chain_cnt,
                      fd_x509_ca_store_t const *   ca_store,
                      char const *                 hostname,
                      ulong                        hostname_len,
                      long                         unix_seconds ) {

  if( FD_UNLIKELY( chain_cnt == 0 ) ) return FD_X509_VERIFY_ERR_CHAIN_BREAK;
  if( FD_UNLIKELY( chain_cnt > FD_X509_CHAIN_MAX ) ) return FD_X509_VERIFY_ERR_CHAIN_TOO_LONG;

  for( ulong i=0UL; i<chain_cnt; i++ )
    if( FD_UNLIKELY( chain_der_sz[i] > FD_X509_CERT_SZ_MAX ) )
      return FD_X509_VERIFY_ERR_CERT_TOO_LARGE;

  fd_x509_cert_info_t certs[ FD_X509_CHAIN_MAX ] = {0};

  if( FD_UNLIKELY( fd_x509_cert_parse( chain_der[0], chain_der_sz[0], &certs[0] ) ) )
    return FD_X509_VERIFY_ERR_PARSE;

  int time_err = fd_x509_check_validity( &certs[0], unix_seconds );
  if( FD_UNLIKELY( time_err ) ) return time_err;

  int usage_err = fd_x509_check_leaf_usage( &certs[0] );
  if( FD_UNLIKELY( usage_err ) ) return usage_err;

  if( hostname && hostname_len ) {
    if( FD_UNLIKELY( !fd_x509_san_matches( &certs[0], hostname, hostname_len ) ) )
      return FD_X509_VERIFY_ERR_HOSTNAME;
  }

  /* The presented list is leaf first; the issuers after it are in any
     order (RFC 8446 Section 4.4.2 tells clients to expect that).  path
     is built by picking, at each step, an unused presented cert whose
     subject names the current issuer and whose key checks out.  A
     branch that dead-ends short of a trust anchor is backed out of and
     the next candidate at that level tried (a cross-signed CA is
     presented twice under one subject).  The first dead end's error is
     reported if no branch works out.  Presented certs are parsed
     lazily.  sig_budget bounds the work on a chain of mutually valid
     same-subject CAs; an honest chain needs one verify per cert. */

  FD_STATIC_ASSERT( FD_X509_CHAIN_MAX<=64UL, bitset );
  fd_x509_cert_info_t path[ FD_X509_CHAIN_MAX ];
  ulong parsed = 1UL;  /* bit j: certs[j] is parsed */
  ulong used   = 1UL;  /* bit j: certs[j] is on path */
  path[0] = certs[0];

  ulong depth                  = 0UL;
  ulong j_start                = 1UL;
  ulong non_self_issued_ca_cnt = 0UL;
  ulong sig_budget             = 4UL*FD_X509_CHAIN_MAX;
  int   first_err              = FD_X509_VERIFY_OK;
  for(;;) {
    fd_x509_cert_info_t const * cur = &path[ depth ];

    /* A trust anchor for this cert's issuer completes the path.  Peers
       routinely append cross-signatures leading up to some older root,
       so the certs beyond this point are not ours to walk: they chain to
       an anchor we do not need and may not even hold.  Skipped when
       resuming after a backtrack: the anchors already failed here. */

    int anchored   = 0;
    int anchor_err = FD_X509_VERIFY_OK;
    if( j_start==1UL ) {
      ulong idx = 0UL;
      for( fd_x509_ca_entry_t const * ca;
           !!( ca = fd_x509_ca_store_find_next( ca_store, cur->issuer, cur->issuer_len, &idx ) ); ) {
        anchored = 1;

        /* A name match is not a key match, so keep trying the remaining
           anchors sharing this subject. */

        if( FD_UNLIKELY( !sig_budget-- ) ) return first_err ? first_err : FD_X509_VERIFY_ERR_CHAIN_BREAK;
        int sig_rc = fd_x509_verify_sig( cur, ca->pubkey, ca->pubkey_len, ca->key_type );
        if( FD_UNLIKELY( sig_rc > 0 ) ) { anchor_err = FD_X509_VERIFY_ERR_UNSUPPORTED; continue; }
        if( sig_rc )                    continue;

        anchor_err = fd_x509_check_anchor( ca, path, depth+1UL, non_self_issued_ca_cnt );
        if( !anchor_err ) return FD_X509_VERIFY_OK;
      }
    }

    /* Not anchored here, so find the issuer among the presented certs.
       Candidates that name-match but fail a check are passed over in
       favour of a later candidate (cross-signed CAs share a subject);
       the first such failure is reported if none of them work out. */

    int   cand_err  = FD_X509_VERIFY_OK;
    int   any_left  = 0;
    ulong pick      = ULONG_MAX;
    for( ulong j = j_start; j < chain_cnt; j++ ) {
      if( used & (1UL<<j) ) continue;
      any_left = 1;

      if( !( parsed & (1UL<<j) ) ) {
        if( FD_UNLIKELY( fd_x509_cert_parse( chain_der[j], chain_der_sz[j], &certs[j] ) ) )
          return FD_X509_VERIFY_ERR_PARSE;
        parsed |= 1UL<<j;
      }
      fd_x509_cert_info_t const * cand = &certs[j];

      if( !fd_x509_name_equal( cur->issuer, cur->issuer_len, cand->subject, cand->subject_len ) )
        continue;

      int err = fd_x509_check_validity( cand, unix_seconds );
      if( !err && !cand->is_ca ) err = FD_X509_VERIFY_ERR_CA_FLAG;

      /* pathLenConstraint counts non-self-issued intermediate CA certs
         between this issuer and the leaf.  The leaf itself never counts. */
      if( !err && cand->has_path_len_constraint &&
          non_self_issued_ca_cnt>cand->path_len_constraint )
        err = FD_X509_VERIFY_ERR_PATH_LEN;

      if( !err && cand->has_key_usage && !( cand->key_usage & FD_X509_KU_KEY_CERT_SIGN ) )
        err = FD_X509_VERIFY_ERR_KEY_USAGE;

      if( !err ) err = fd_x509_check_eku( cand );

      if( !err ) err = fd_x509_check_path_name_constraints(
          cand->has_name_constraints,
          cand->name_constraints_permitted, cand->name_constraints_permitted_len,
          cand->name_constraints_excluded,  cand->name_constraints_excluded_len,
          path, depth+1UL );

      if( !err ) {
        if( FD_UNLIKELY( !sig_budget-- ) ) return first_err ? first_err : FD_X509_VERIFY_ERR_CHAIN_BREAK;
        int sig_rc = fd_x509_verify_sig( cur, cand->pubkey, cand->pubkey_len, cand->key_type );
        if( sig_rc < 0 ) err = FD_X509_VERIFY_ERR_SIG;
        if( sig_rc > 0 ) err = FD_X509_VERIFY_ERR_UNSUPPORTED;
      }

      if( !err ) { pick = j; break; }
      if( !cand_err ) cand_err = err;
    }

    if( pick != ULONG_MAX ) {
      used |= 1UL<<pick;
      path[ depth+1 ] = certs[ pick ];

      /* A self-issued rollover CA does not consume path length budget. */
      if( !fd_x509_name_equal( certs[pick].issuer,  certs[pick].issuer_len,
                               certs[pick].subject, certs[pick].subject_len ) )
        non_self_issued_ca_cnt++;

      depth++;
      j_start = 1UL;
      continue;
    }

    if( !first_err ) {
      if(      cand_err   ) first_err = cand_err;
      else if( anchor_err ) first_err = anchor_err;
      else if( anchored   ) first_err = FD_X509_VERIFY_ERR_SIG;
      else                  first_err = any_left ? FD_X509_VERIFY_ERR_CHAIN_BREAK : FD_X509_VERIFY_ERR_NO_TRUST_ANCHOR;
    }
    if( !depth ) return first_err;

    /* Back up one level and release the cert picked there.  path holds
       copies, so the pick is the used cert whose tbs pointer matches. */

    depth--;
    ulong prev = 1UL;
    while( !( used & (1UL<<prev) ) || certs[prev].tbs!=path[depth+1].tbs ) prev++;
    used &= ~(1UL<<prev);
    if( !fd_x509_name_equal( certs[prev].issuer,  certs[prev].issuer_len,
                             certs[prev].subject, certs[prev].subject_len ) )
      non_self_issued_ca_cnt--;
    j_start = prev+1UL;
  }
}

int
fd_x509_verify_tls_cert_msg( uchar const *              cert_msg,
                             ulong                      cert_msg_sz,
                             fd_x509_ca_store_t const * ca_store,
                             char const *               hostname,
                             ulong                      hostname_len,
                             long                       unix_seconds ) {

  if( FD_UNLIKELY( !cert_msg ) ) return FD_X509_VERIFY_ERR_PARSE;

  uchar const * p   = cert_msg;
  uchar const * end = cert_msg + cert_msg_sz;

  /* A server Certificate sent for the main handshake must have an empty
     certificate_request_context (RFC 8446 Section 4.4.2). */
  if( FD_UNLIKELY( (ulong)(end-p)<1UL ) ) return FD_X509_VERIFY_ERR_PARSE;
  ulong ctx_len = *p++;
  if( FD_UNLIKELY( ctx_len ) ) return FD_X509_VERIFY_ERR_PARSE;

  /* certificate_list<0..2^24-1> */
  if( FD_UNLIKELY( (ulong)(end-p)<3UL ) ) return FD_X509_VERIFY_ERR_PARSE;
  ulong list_len = ( (ulong)p[0]<<16 ) | ( (ulong)p[1]<<8 ) | (ulong)p[2];
  p += 3;
  if( FD_UNLIKELY( list_len != (ulong)( end-p ) ) ) return FD_X509_VERIFY_ERR_PARSE;
  uchar const * list_end = p + list_len;

  uchar const * chain_der   [ FD_X509_CHAIN_MAX ];
  ulong         chain_der_sz[ FD_X509_CHAIN_MAX ];
  ulong         chain_cnt = 0UL;

  while( p < list_end ) {
    if( FD_UNLIKELY( chain_cnt >= FD_X509_CHAIN_MAX ) ) return FD_X509_VERIFY_ERR_CHAIN_TOO_LONG;

    /* cert_data<1..2^24-1> */
    if( FD_UNLIKELY( (ulong)(list_end-p)<3UL ) ) return FD_X509_VERIFY_ERR_PARSE;
    ulong cert_len = ( (ulong)p[0]<<16 ) | ( (ulong)p[1]<<8 ) | (ulong)p[2];
    p += 3;
    if( FD_UNLIKELY( !cert_len ) )
      return FD_X509_VERIFY_ERR_PARSE;
    if( FD_UNLIKELY( cert_len > FD_X509_CERT_SZ_MAX ) )
      return FD_X509_VERIFY_ERR_CERT_TOO_LARGE;
    if( FD_UNLIKELY( (ulong)(list_end-p)<cert_len ) )
      return FD_X509_VERIFY_ERR_PARSE;

    chain_der   [ chain_cnt ] = p;
    chain_der_sz[ chain_cnt ] = cert_len;
    chain_cnt++;
    p += cert_len;

    /* extensions<0..2^16-1> */
    if( FD_UNLIKELY( (ulong)(list_end-p)<2UL ) ) return FD_X509_VERIFY_ERR_PARSE;
    ulong ext_len = ( (ulong)p[0]<<8 ) | (ulong)p[1];
    p += 2;
    if( FD_UNLIKELY( (ulong)(list_end-p)<ext_len ) ) return FD_X509_VERIFY_ERR_PARSE;
    uchar const * ext_end = p + ext_len;

    while( p < ext_end ) {
      if( FD_UNLIKELY( (ulong)(ext_end-p)<4UL ) ) return FD_X509_VERIFY_ERR_PARSE;
      p += 2; /* ExtensionType */
      ulong ext_data_len = ( (ulong)p[0]<<8 ) | (ulong)p[1];
      p += 2;
      if( FD_UNLIKELY( (ulong)(ext_end-p)<ext_data_len ) ) return FD_X509_VERIFY_ERR_PARSE;
      p += ext_data_len;
    }
  }

  if( FD_UNLIKELY( !chain_cnt ) ) return FD_X509_VERIFY_ERR_PARSE;

  return fd_x509_verify_chain( chain_der, chain_der_sz, chain_cnt,
                              ca_store, hostname, hostname_len, unix_seconds );
}
