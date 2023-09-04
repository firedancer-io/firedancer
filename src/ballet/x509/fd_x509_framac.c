/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include "fd_x509_cert_parser.h"

/* fd_x509_framac contains a dummy main target for the Frama-C verifier */

#if defined(__FRAMAC__)

#include "__fc_builtin.h"

/*
 * In order to fully tests functions, we need to be able to get
 * access to a random length random content buffer. The function
 * takes as input a *valid* buffer of length len and returns
 * either
 *
 *  - a NULL pointer with a random length using out_len parameter
 *  - a pointer to input buffer and a random length in interval
 *    [0,len-1]. in that case, output buffer content is randomized
 *    using Frama_C_make_unknown() on out_len bytes.
 *
 */
/*@
  @ requires \valid(buf + (0 .. (len - 1)));
  @ requires \valid(out_len);
  @ requires \valid(out_buf);
  @ requires \separated(out_buf, out_len, buf + (..), &Frama_C_entropy_source);
  @
  @ ensures (*out_buf == \null) ==> 0 <= *out_len <= len;
  @ ensures (*out_buf != \null) ==> (*out_buf == buf) && (0 <= *out_len <= len) && \valid(buf + (0 .. (*out_len - 1)));
  @
  @*/
static void
rand_buf_or_null( uchar *  buf,
			            uint     len,
			            uchar ** out_buf,
			            uint  *  out_len)
{
	unsigned int toggle;

	toggle = Frama_C_unsigned_int_interval(0, 1);
	/*@ assert \valid(buf + (0 .. (len - 1))); */
	Frama_C_make_unknown(buf, len);

	*out_len = Frama_C_unsigned_int_interval(0, len);
	*out_buf = toggle ? NULL : buf;
}

int main(int argc, char *argv[]) {
	uchar main_buf[ASN1_MAX_BUFFER_SIZE];
	uint main_buf_len = sizeof(main_buf);
	uchar *buf;
	uint len;
	int ret = 0;

	{ /* find_sig_alg_by_oid(() */
		const _sig_alg *alg;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		alg = find_sig_alg_by_oid(buf, len);
		ret |= (alg == NULL) ? 0 : 1;
	}

	{ /* find_hash_by_oid(() */
		const _hash_alg *alg;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		alg = find_hash_by_oid(buf, len);
		ret |= (alg == NULL) ? 0 : 1;
	}

	{ /* find_curve_by_oid(() */
		const _curve *crv;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		crv = find_curve_by_oid(buf, len);
		ret |= (crv == NULL) ? 0 : 1;
	}

	{ /* get_length() */
		uint adv_len, eaten;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&adv_len, sizeof(adv_len));
		Frama_C_make_unknown(&eaten, sizeof(eaten));

		ret |= get_length(buf, len, &adv_len, &eaten);
	}

	{ /* parse_id_len() */
		tag_class exp_class;
		uint exp_type, parsed, content_len;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&parsed, sizeof(parsed));
		Frama_C_make_unknown(&content_len, sizeof(content_len));

		ret |= parse_id_len(buf, len,
				    exp_class, exp_type,
				    &parsed, &content_len);
	}

	{ /* parse_explicit_id_len() */
		tag_class exp_int_class;
		uint exp_ext_type, exp_int_type, parsed, data_len;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&exp_int_class, sizeof(exp_int_class));
		Frama_C_make_unknown(&exp_int_type, sizeof(exp_int_type));
		Frama_C_make_unknown(&exp_ext_type, sizeof(exp_ext_type));
		Frama_C_make_unknown(&parsed, sizeof(parsed));
		Frama_C_make_unknown(&data_len, sizeof(data_len));

		ret |= parse_explicit_id_len(buf, len,
					     exp_ext_type, exp_int_class, exp_int_type,
					     &parsed, &data_len);
	}

	{ /* parse_null() */
		uint parsed;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&parsed, sizeof(parsed));

		ret |= parse_null(buf, len, &parsed);
	}

	{ /* parse_OID() */
		uint parsed;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&parsed, sizeof(parsed));

		ret |= parse_OID(buf, len, &parsed);
	}

	{ /* parse_integer() */
		tag_class exp_class;
		uint exp_type, hdr_len, data_len;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&hdr_len, sizeof(hdr_len));
		Frama_C_make_unknown(&data_len, sizeof(data_len));

		ret |= parse_integer(buf, len,
				     exp_class, exp_type,
				     &hdr_len, &data_len);
	}

	{ /* parse_non_negative_integer() */
		tag_class exp_class;
		uint exp_type, hdr_len, data_len;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&hdr_len, sizeof(hdr_len));
		Frama_C_make_unknown(&data_len, sizeof(data_len));

		ret |= parse_non_negative_integer(buf, len,
						  exp_class, exp_type,
						  &hdr_len, &data_len);
	}

	{ /* parse_boolean() */
		uint parsed;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&parsed, sizeof(parsed));

		ret |= parse_boolean(buf, len, &parsed);
	}

	{ /* parse_generalizedTime() */
		uint eaten;
		ushort year;
		uchar month, day, hour, min, sec;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		Frama_C_make_unknown(&year, sizeof(year));
		Frama_C_make_unknown(&month, sizeof(month));
		Frama_C_make_unknown(&day, sizeof(day));
		Frama_C_make_unknown(&hour, sizeof(hour));
		Frama_C_make_unknown(&min, sizeof(min));
		Frama_C_make_unknown(&sec, sizeof(sec));

		ret |= parse_generalizedTime(buf, len, &eaten,
					     &year, &month, &day,
					     &hour, &min, &sec);
	}

	{ /* parse_GeneralName() */
		uint eaten;
		int empty;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		Frama_C_make_unknown(&empty, sizeof(empty));

		ret |= parse_GeneralName(buf, len, &eaten, &empty);
	}

	{ /* parse_SerialNumber() */
		tag_class exp_class;
		uint exp_type, eaten, off;

		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		/*@ assert (buf != \null) ==> \valid(buf + (0 .. (len - 1))); */
		off = Frama_C_unsigned_int_interval(0, len);
		/*@ assert off <= len; */
		len -= off;
		/*@ assert (buf != \null) ==> \valid(buf + (off .. (off + len - 1))); */

		ret |= parse_SerialNumber(buf, off, len,
					  exp_class, exp_type,
					  &eaten);
	}

	{ /* verify_correct_time_use() */
		uchar time_type;
		ushort yyyy;

		Frama_C_make_unknown(&time_type, sizeof(time_type));
		Frama_C_make_unknown(&yyyy, sizeof(yyyy));

		ret |= verify_correct_time_use(time_type, yyyy);
	}

	{ /* parse_Time() */
		uint eaten;
		ushort year;
		uchar t_type, month, day, hour, min, sec;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		Frama_C_make_unknown(&year, sizeof(year));
		Frama_C_make_unknown(&t_type, sizeof(t_type));
		Frama_C_make_unknown(&month, sizeof(month));
		Frama_C_make_unknown(&day, sizeof(day));
		Frama_C_make_unknown(&hour, sizeof(hour));
		Frama_C_make_unknown(&min, sizeof(min));
		Frama_C_make_unknown(&sec, sizeof(sec));

		ret |= parse_Time(buf, len, &t_type, &eaten,
				  &year, &month, &day, &hour, &min, &sec);
	}

	{ /* parse_AKICertSerialNumber() */
		tag_class exp_class;
		uint exp_type, eaten, off;

		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		/*@ assert (buf != \null) ==> \valid(buf + (0 .. (len - 1))); */
		off = Frama_C_unsigned_int_interval(0, len);
		/*@ assert off <= len; */
		len -= off;
		/*@ assert (buf != \null) ==> \valid(buf + (off .. (off + len - 1))); */

		ret |= parse_AKICertSerialNumber(buf, off, len,
						 exp_class, exp_type,
						 &eaten);
	}

	{ /* parse_crldp_reasons() */
		uint exp_type, eaten;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&eaten, sizeof(eaten));

		ret |= parse_crldp_reasons(buf, len, exp_type, &eaten);
	}

	{ /* parse_DistributionPoint() */
		int crldp_has_all_reasons;
		uint eaten;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&crldp_has_all_reasons, sizeof(crldp_has_all_reasons));
		Frama_C_make_unknown(&eaten, sizeof(eaten));

		ret |= parse_DistributionPoint(buf, len, &crldp_has_all_reasons, &eaten);
	}

	{ /* parse_AIA() */
		int critical;
		uint off;

		Frama_C_make_unknown(&critical, sizeof(critical));
		Frama_C_make_unknown(&off, sizeof(off));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		/*@ assert (buf != \null) ==> \valid(buf + (0 .. (len - 1))); */
		off = Frama_C_unsigned_int_interval(0, len);
		/*@ assert off <= len; */
		len -= off;
		/*@ assert (buf != \null) ==> \valid(buf + (off .. (off + len - 1))); */

		ret |= parse_AIA(buf, off, len, critical);
	}

	{ /* parse_ia5_string() */
		uint lb, ub;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&lb, sizeof(lb));
		Frama_C_make_unknown(&ub, sizeof(ub));

		ret |= parse_ia5_string(buf, len, lb, ub);
	}

	{ /* parse_x509_Name() */
		uint eaten;
		int empty;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		Frama_C_make_unknown(&empty, sizeof(empty));

		ret |= parse_x509_Name(buf, len, &eaten, &empty);
	}

	{ /* parse_DisplayText() */
		uint eaten;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));

		ret |= parse_DisplayText(buf, len, &eaten);
	}

	{ /* parse_nine_bit_named_bit_list() */
		ushort val;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&val, sizeof(val));

		ret |= parse_nine_bit_named_bit_list(buf, len, &val);
	}

	{ /* parse_GeneralName() */
		uint eaten;
		int empty;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		Frama_C_make_unknown(&empty, sizeof(empty));

		ret |= parse_GeneralName(buf, len, &eaten, &empty);
	}

	{ /* parse_GeneralNames() */
		tag_class exp_class;
		uint exp_type, eaten;

		Frama_C_make_unknown(&exp_class, sizeof(exp_class));
		Frama_C_make_unknown(&exp_type, sizeof(exp_type));
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);

		ret |= parse_GeneralNames(buf, len, exp_class, exp_type,
					  &eaten);
	}

	{ /* time_components_to_comparable_u64() */
		ulong val;
		ushort na_year;
		uchar na_month, na_day, na_hour, na_min, na_sec;

		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		na_year = Frama_C_unsigned_int_interval(0, 9999);
		na_month = Frama_C_unsigned_int_interval(0, 12);
		na_day = Frama_C_unsigned_int_interval(0, 31);
		na_hour = Frama_C_unsigned_int_interval(0, 23);
		na_min = Frama_C_unsigned_int_interval(0, 59);
		na_sec = Frama_C_unsigned_int_interval(0, 59);

		val = time_components_to_comparable_u64(na_year, na_month, na_day, na_hour, na_min, na_sec);
		ret |= val != 0;
	}

	{ /* parse_x509_cert() */
		cert_parsing_ctx cert_ctx;

		Frama_C_make_unknown(&cert_ctx, sizeof(cert_ctx));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		ret |= parse_x509_cert(&cert_ctx, buf, len);
	}

	{ /* parse_x509_cert_relaxed() */
		cert_parsing_ctx cert_ctx;
		uint eaten;

		Frama_C_make_unknown(&cert_ctx, sizeof(cert_ctx));
		Frama_C_make_unknown(&eaten, sizeof(eaten));
		rand_buf_or_null(main_buf, main_buf_len, &buf, &len);
		ret |= parse_x509_cert_relaxed(&cert_ctx, buf, len, &eaten);
	}

	return ret;
}


#endif /* defined(__FRAMAC__) */
