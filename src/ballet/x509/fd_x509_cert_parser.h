/*
 *  Copyright (C) 2019 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */
#ifndef HEADER_fd_src_ballet_x509_fd_x509_cert_parser_h
#define HEADER_fd_src_ballet_x509_fd_x509_cert_parser_h

#include "../fd_ballet_base.h"
#include "fd_x509_config.h"
#include "fd_x509_utils.h"
#include "fd_x509_common.h"

typedef struct {
	/* tbcCertificate */
	uint tbs_start;
	uint tbs_len;

	/* Version */
	uchar version;

	/* Serial */
	uint serial_start;
	uint serial_len;

	/* inner sig alg (tbsCertificate.signature) */
	uint tbs_sig_alg_start;
	uint tbs_sig_alg_len;
	uint tbs_sig_alg_oid_start; /* OID for sig alg */
	uint tbs_sig_alg_oid_len;
	uint tbs_sig_alg_oid_params_start; /* params for sig alg */
	uint tbs_sig_alg_oid_params_len;

	/* Issuer */
	uint issuer_start;
	uint issuer_len;

	/* Validity */
	ulong not_before;
	ulong not_after;

	/* Subject */
	uint subject_start;
	uint subject_len;
	int empty_subject;

	/* 1 if subject and issuer fields are binary equal */
	int subject_issuer_identical;

	/* SubjectPublicKeyInfo */
	uint spki_start;
	uint spki_len;
	uint spki_alg_oid_start;
	uint spki_alg_oid_len;
	uint spki_alg_oid_params_start;
	uint spki_alg_oid_params_len;
	uint spki_pub_key_start;
	uint spki_pub_key_len;
	spki_alg_id spki_alg;
	spki_params spki_alg_params;

	/* Extensions */

	    /* SKI related info, if present */
	    int has_ski;
	    uint ski_start;
	    uint ski_len;

	    /* AKI related info, if present */
	    int has_aki;
	    int aki_has_keyIdentifier;
	    uint aki_keyIdentifier_start;
	    uint aki_keyIdentifier_len;
	    int aki_has_generalNames_and_serial;
	    uint aki_generalNames_start;
	    uint aki_generalNames_len;
	    uint aki_serial_start;
	    uint aki_serial_len;

	    /* SAN */
	    int has_san;
	    int san_critical;

	    /* Basic constraints */
	    int bc_critical;
	    int ca_true;
	    int pathLenConstraint_set;

	    /* keyUsage */
	    int has_keyUsage;
	    int keyCertSign_set;
	    int cRLSign_set;

	    /* extendedKeyUsage (EKU) */
	    int has_eku;

	    /* CRLDP */
	    int has_crldp;
	    int one_crldp_has_all_reasons;

	    /* Name Constraints */
	    int has_name_constraints;


	/* signature alg */
	uint sig_alg_start; /* outer sig alg */
	uint sig_alg_len;
	sig_alg_id sig_alg; /* ID of signature alg */
	hash_alg_id hash_alg;
	sig_params sig_alg_params; /* depends on sig_alg */

	/* raw signature value */
	uint sig_start;
	uint sig_len;
} cert_parsing_ctx;

/*
 * Return 0 if parsing went OK, a non zero value otherwise.
 * 'len' must exactly match the size of the certificate
 * in the buffer 'buf' (i.e. nothing is expected behind).
 */
int parse_x509_cert(cert_parsing_ctx *ctx, const uchar *buf, uint len);

#endif /* HEADER_fd_src_ballet_x509_fd_x509_cert_parser_h */
