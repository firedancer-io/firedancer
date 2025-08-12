#include "fd_sysvar_rent.h"

static void
test_sysvar_rent_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x98, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x64
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_RENT_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = { .data=data, .dataend=data+sizeof(data) };
  ulong obj_sz = 0UL;
  FD_TEST( fd_rent_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_RENT_FOOTPRINT );
  FD_TEST( fd_rent_align()==FD_SYSVAR_RENT_ALIGN );
}

struct fd_rent_exempt_fixture {
  /* Inputs */
  ulong data_len;
  ulong lamports_per_byte_year;
  union {
    double exemption_threshold;
    ulong  exemption_threshold_bits;
  };
  /* Output */
  ulong min_balance;
};

typedef struct fd_rent_exempt_fixture fd_rent_exempt_fixture_t;


static fd_rent_exempt_fixture_t const
test_rent_exempt_vector[] = {
  { .data_len=     0, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=    890880UL },
  { .data_len=    10, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=    960480UL },
  { .data_len=131097, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance= 913326000UL },
  { .data_len= 16392, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance= 114979200UL },
  { .data_len=    17, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   1009200UL },
  { .data_len=   200, .lamports_per_byte_year=    3480, .exemption_threshold_bits=0x4000000000000000UL, .min_balance=   2282880UL },
  { .data_len=   200, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   2282880UL },
  { .data_len= 20488, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance= 143487360UL },
  { .data_len=    24, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   1057920UL },
  { .data_len=    33, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   1120560UL },
  { .data_len=  3731, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=  26858640UL },
  { .data_len=  3762, .lamports_per_byte_year=    3480, .exemption_threshold_bits=0x4000000000000000UL, .min_balance=  27074400UL },
  { .data_len=  3762, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=  27074400UL },
  { .data_len=395693, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=2754914160UL },
  { .data_len=    40, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   1169280UL },
  { .data_len=  6008, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=  42706560UL },
  { .data_len=    82, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=   1461600UL },
  { .data_len=     8, .lamports_per_byte_year=    3480, .exemption_threshold_bits=0x4000000000000000UL, .min_balance=    946560UL },
  { .data_len=     8, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=    946560UL },
  { .data_len=     9, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=    953520UL }
};
#define test_rent_exempt_vector_end (fd_rent_exempt_fixture_t const *)( (uchar const *)test_rent_exempt_vector + sizeof(test_rent_exempt_vector) )

void
test_sysvar_rent( void ) {
  test_sysvar_rent_bounds();
  for( fd_rent_exempt_fixture_t const * iter = test_rent_exempt_vector;
       iter < test_rent_exempt_vector_end;
       iter++ ) {
    fd_rent_t rent = {
      .lamports_per_uint8_year = iter->lamports_per_byte_year,
      .exemption_threshold     = iter->exemption_threshold,
    };
    ulong min_balance = fd_rent_exempt_minimum_balance( &rent, iter->data_len );
    FD_TEST( min_balance == iter->min_balance );
  }
}
