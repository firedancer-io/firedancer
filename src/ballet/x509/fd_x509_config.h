/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */
#ifndef HEADER_fd_src_ballet_x509_fd_x509_config_h
#define HEADER_fd_src_ballet_x509_fd_x509_config_h


/*
 * Max allowed buffer size for ASN.1 structures. Also note that
 * the type used for length in the whole code is an u32, so it
 * is pointless to set something higher than 2^32 - 1
 */
#define ASN1_MAX_BUFFER_SIZE (UINT_MAX)

/*
 * The following can be defined to enable an error trace to be
 * printed on standard output. The error path is made of the
 * lines in the representing the call graph leading to the
 * error.
 */
// #define ERROR_TRACE_ENABLE

/*
 * FIXME: document error values
 */

typedef enum {
	X509_PARSER_ERROR_VERSION_ABSENT            = -1,
	X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH = -2,
	X509_PARSER_ERROR_VERSION_NOT_3             = -3,
} x509_parser_errors;


/* Knob to skip over currently unknown RDN elements */
#define TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_RDN_OIDS

/*
 * Each certificate extension is made of an OID and an associated data value
 * for which we need a specific parsing function to validate the structure
 * of the data. This means that by default a certificate will be rejected if
 * an extensions is unknown. We define two macros to allow parsing to continue
 * when encoutering unsupported extensions (for which we do not have a specific
 * parsing function for data value)
 *
 * The first (TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS) handles
 * common extensions found in certificates which we know of but currently
 * have no parsing functions. Those extensions OID are explicitly referenced
 * in known_ext_oids table. When the knob is defined, the extensions data is
 * skipped to continue parsing, i.e. the structure of the data it carries is
 * NOT VERIFIED AT ALL. The check that the extension only appear once in the
 * certificate is performed.
 *
 * The second (TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS) is used as a
 * catch-all for extensions that are not known. When the knob is defined:
 *
 *  - unknown extensions data structure is NOT VERIFIED AT ALL
 *  - NO CHECK is performed to verify that the extension appears only once
 *    in the certificate.
 */
#define TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
#define TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS

/*
 * Double the defined upper upper bound value of on common RDN components
 * (CN, O and OU) length from 64 to 128.
 */
#define TEMPORARY_LAXIST_RDN_UPPER_BOUND

/* Allow CA certificates w/o SKI. */
#define TEMPORARY_LAXIST_CA_WO_SKI

/* Allow emailAddress using UTF-8 encoding instead for IA5String. */
#define TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING

/*
 * Same for otherwise unsupported extensions but for which we have an
 * internal reference to the OID
 */
#define TEMPORARY_BAD_EXT_OIDS

/*
 * Same for otherwise unsupported RDN but for which we have an internal
 * reference to the OID
 */
#define TEMPORARY_BAD_OID_RDN

/* Allow certificates w/ full directoryString . */
#define TEMPORARY_LAXIST_DIRECTORY_STRING

/*
 * Allow negative serial value
 */
#define TEMPORARY_LAXIST_SERIAL_NEGATIVE

/*
 * Allow large serial value. Limit is 20 bytes but some implementation
 * use larger serial.
 */
#define TEMPORARY_LAXIST_SERIAL_LENGTH

/*
 * Serial value is not expected to be 0. This knob make such certificate
 * valid.
 */
#define TEMPORARY_LAXIST_SERIAL_NULL

/*
 * Allow certificates w/ full basic constraints boolean explicitly set to false.
 * As this is the DEFAULT value, DER forbids encoding of that value.
 */
#define TEMPORARY_LAXIST_CA_BASIC_CONSTRAINTS_BOOLEAN_EXPLICIT_FALSE

/*
 * Allow certificates w/ extension's critical flag explicitly set to false.
 * As this is the DEFAULT value, DER forbids encoding of that value. The
 * knob also applies to CRL extensions.
 */
#define TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE

/*
 * Allow certificates w/ SKI extension critical flag set. Section 4.2.1.1. of
 * RFC 5280 forbids that with a MUST.
 */
#define TEMPORARY_LAXIST_SKI_CRITICAL_FLAG_SET

/*
 * Allow serial DN component encoded as an IA5String whereas RFC 5280
 * requires such element to be encoded using printable string.
 */
#define TEMPORARY_LAXIST_SERIAL_RDN_AS_IA5STRING

/*
 * Do not kick certificates with empty RSA pubkey algoid params or empty sig
 * algoid parmas instead of the expected NULL.
 */
#define TEMPORARY_LAXIST_RSA_PUBKEY_AND_SIG_NO_PARAMS_INSTEAD_OF_NULL

/*
 * nextUpdate field in CRL is optional in ASN.1 definition but RFC5280
 * explicitly states both at end of section 5. introduction and in section
 * 5.1.2 that conforming CRL issuers are required / MUST include
 * nextUpdate field. When following knob is defined, invalid CRL with missing
 * nextUpdate field are allowed.
 */
#define TEMPORARY_LAXIST_ALLOW_MISSING_CRL_NEXT_UPDATE

/*
 * CRL v2 may include extensions. The field is either absent or present,
 * in which case "this field is a sequence of one or more CRL extensions."
 * i.e. it is not valid to have the field with no extension in it. Some
 * CRL nonetheless exhibit the field with an empty content. Defining
 * this knob accepts those CRL.
 */
#define TEMPORARY_LAXIST_ALLOW_CRL_ENTRY_EXT_WITH_EMPTY_SEQ

/*
 * CRL Issuing Distribution Point (IDP) extension is a critical one.
 * Nonetheless, some CRL issuers did not get the memo and do not
 * assert the bit in the CRL they emit. Such invalid CRL can be let
 * pass through by defining the following knob.
 */
#define TEMPORARY_LAXIST_ALLOW_IDP_CRL_EXT_WITHOUT_CRITICAL_BIT_SET

/*
 * RFC 5280 section 5.1.2.6 has "When there are no revoked certificates,
 * the revoked certificates list MUST be absent". Some CRL wrongfully
 * include an empty list in that case. Defining this knob let those
 * CRL pass through.
 */
#define TEMPORARY_LAXIST_ALLOW_REVOKED_CERTS_LIST_EMPTY

/*
 * RFC 5280 has "When CRLs are issued, the CRLs MUST be version 2 CRLs,
 * include the date by which the next CRL will be issued in the
 * nextUpdate field (Section 5.1.2.5), include the CRL number extension
 * (Section 5.2.3), and include the authority key identifier extension
 * (Section 5.2.1)." If the CRL misses the AKI and CRL number extensions
 * then it is invalid ;-)
 */
#define TEMPORARY_LAXIST_ALLOW_MISSING_AKI_OR_CRLNUM

#endif /* HEADER_fd_src_ballet_x509_fd_x509_config_h */
