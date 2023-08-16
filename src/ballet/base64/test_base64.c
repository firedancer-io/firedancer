#include "fd_base64.h"
#include <string.h>
#include <stdio.h>

void
decode_test( void ) {
  const char * expected_string = "Hello World!";
  const char * encoded_string  = "SGVsbG8gV29ybGQh";
  uchar decoded[ 100 ]; /* Assuming the decoded data won't exceed 100 bytes */

  int decoded_length = fd_base64_decode( encoded_string, decoded );

  FD_TEST( (uint)decoded_length == strlen( expected_string ) );
  FD_TEST( memcmp( decoded, expected_string, strlen(expected_string) ) == 0 );
}

void
decode_test_equals( void ) {
  const char * encoded_string  = "AZCML352XGjOwgIwMGsRf8oa2IoWzSvgWlJwcAEtLtwk3/h2VIe7n+YbPrAwpbIiK3KOM/G4XiNAKyhHbn2VBQ0BAAEGUn3G2+sjJ+xarkiI77ZYW6CEGHzEjzovKWoUG3/TSKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACdPJdmqIA5PfVdI4dCMAMKH7z7U0fpkodPhLfE54yrfhMa9sJylZdraDb38lv6aISwi7GkOXsRZ8PQnKkkbFarB08LBYexRVX/v3EVfNeQk9z+WMTKqR0tc/WtXBjQP+v5pDHP1tYUMPTA8WZARvn8XTCjSs+9iPlPPYBWQrEspMZwcluFwA/afVpAczCo7+IJMw5/a0W/kR2EsJRNuF3IBBQUCAwAEAYgEJgW58JTT/VUQEAERERERARABAREBEBERERERABEBEQAQABARAAAREQEREBAQEBERERABERABEBAREBEQEQARAAERABARAQEQABABABAQAQABABEBAREQAAARAAAREREREAERARAAAREQEBAAEAAAEAAQEBEAEREAAAEQEBERAQAAAQEAABABABAQAAEBAAAQEBEAERAQEAAQAREBEQAREREAARAAAREAEAAAAREBEQEQEAAAEQEBEREREBABAQEQAQEQAAEQAREAERAAEAEQARABEBAAAQAQEAABEQEBEAAAEAABEBAAEAEAAQAQEBEQAQABABAREREBAQEAABEBARAAEAABEBAQEREAEBAREQEAAAEBEAEREREQARERAQEQAAEBEQEQARABEBAQAAAAEBEBAQEREQEQEQEAEQAQEBERARAQAQEBABAAAAEAERABAAAAAAEBEAEAAREREBEQEQARAREBEBEREAABABEAEBEBERAQABAAEQEAEAAQABEBEAAAABABAAABEAAAEQAQAQEBAQARAAEREAAAAQAQAREAAQAQAAEQEAEQEAAAARABEAEREBEBAQAQAQEREQEAAAEBAAAQEQABEAABEAEBEBAQABEREAAAABEBAAAQEQEQAAARERAQABERERABEAARABABEBAQAQEAEAARARERABABAREQEBAAAA==";
  uchar decoded[ 1500 ]; /* Assuming the decoded data won't exceed 1500 bytes */

  int decoded_length = fd_base64_decode( encoded_string, decoded );

  FD_TEST( decoded_length != -1 );
}

void encode_test( void ) {
  uchar binary_data[] = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33}; /* "Hello World!" */
  const char * expected_string  = "SGVsbG8gV29ybGQh";

  char encoded[100]; /* Assuming the encoded data won't exceed 100 characters */

  ulong encoded_length = fd_base64_encode(binary_data, sizeof(binary_data), encoded);
  printf("%lu %ld\n", sizeof(binary_data), strlen((char*)binary_data));

  FD_TEST( (uint)encoded_length == strlen( expected_string ) );
  FD_TEST( memcmp( encoded, expected_string, strlen(encoded) ) == 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  decode_test();
  decode_test_equals();
  encode_test();
  fd_halt();
  return 0;
}
