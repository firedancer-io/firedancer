#include "fd_sysvar_rent.h"

FD_STATIC_ASSERT( alignof ( fd_rent_t                          )==0x01UL,                    layout );
FD_STATIC_ASSERT( offsetof( fd_rent_t, lamports_per_uint8_year )==0x00UL,                    layout );
FD_STATIC_ASSERT( offsetof( fd_rent_t, exemption_threshold     )==0x08UL,                    layout );
FD_STATIC_ASSERT( offsetof( fd_rent_t, burn_percent            )==0x10UL,                    layout );
FD_STATIC_ASSERT( sizeof  ( fd_rent_t                          )==0x11UL,                    layout );
FD_STATIC_ASSERT( sizeof  ( fd_rent_t                          )==FD_SYSVAR_RENT_BINCODE_SZ, layout );

static void
test_sysvar_rent_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x98, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x64
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_RENT_BINCODE_SZ );
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
  { .data_len=     9, .lamports_per_byte_year=46980000, .exemption_threshold_bits=0x3f236b06e70b7421UL, .min_balance=    953520UL },

  /* Thresholds 1.0 and 2.0 with a product exceeding 2^53, where integer
     and double arithmetic disagree.  lamports_per_byte_year sits at the
     largest value each threshold admits, and 10485760 is the largest
     account data length. */
  { .data_len=    4993, .lamports_per_byte_year=1759197129867UL, .exemption_threshold_bits=0x3ff0000000000000UL, .min_balance=    9008848502048907UL },
  { .data_len=10485760, .lamports_per_byte_year=1759197129867UL, .exemption_threshold_bits=0x3ff0000000000000UL, .min_balance=18446744073706816896UL },
  { .data_len=   10113, .lamports_per_byte_year= 879598564933UL, .exemption_threshold_bits=0x4000000000000000UL, .min_balance=   18015937806957706UL },
  { .data_len=10485760, .lamports_per_byte_year= 879598564933UL, .exemption_threshold_bits=0x4000000000000000UL, .min_balance=18446744073696331008UL },
  { .data_len=10485760, .lamports_per_byte_year= 116163352091UL, .exemption_threshold_bits=0x3ff0000000000000UL, .min_balance= 1218075899730791808UL },
  { .data_len=10485760, .lamports_per_byte_year= 116163352091UL, .exemption_threshold_bits=0x4000000000000000UL, .min_balance= 2436151799461583616UL },
  { .data_len=10485760, .lamports_per_byte_year=         6960UL, .exemption_threshold_bits=0x3ff0000000000000UL, .min_balance=         72981780480UL },

  /* Any other threshold keeps the double computation, saturating like a
     Rust `as u64` cast. */
  { .data_len=     200, .lamports_per_byte_year=         3480UL, .exemption_threshold_bits=0x3ff8000000000000UL, .min_balance=             1712160UL },
  { .data_len=10485760, .lamports_per_byte_year=1759197129867UL, .exemption_threshold_bits=0x3ff8000000000000UL, .min_balance=18446744073709551615UL }
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
