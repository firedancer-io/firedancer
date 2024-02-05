#include "../fd_util.h"

/* FIXME: COVERAGE FOR FD_CSTR_CASECMP, FD_CSTR_TO_ULONG_OCTAL,
   FD_CSTR_APPEND_PRINTF, FD_CSTR_APPEND_CSTR, FD_CSTR_APPEND_CSTR_SAFE,
   FD_CSTR_HASH, FD_CSTR_HASH_APPEND */

char const *ref_text = "\n\nThe quick brown fox jumps over the lazy dog\nThe "
                       "quick brown fox jumps over the lazy dog.\n";
char const *ref_uchar =
    "0\n0\n+0\n-0\n1\n1\n+1\n-1\n 9\n09\n +9\n -9\n10\n10\n+10\n-10\n "
    "99\n099\n +99\n -99\n100\n100\n+100\n-100\n 254\n0254\n +254\n -254\n "
    "255\n0255\n +255\n -255\n";
char const *ref_ushort =
    "0\n0\n+0\n-0\n1\n1\n+1\n-1\n 9\n09\n +9\n -9\n10\n10\n+10\n-10\n "
    "99\n099\n +99\n -99\n100\n100\n+100\n-100\n 999\n0999\n +999\n "
    "-999\n1000\n1000\n+1000\n-1000\n 9999\n09999\n +9999\n "
    "-9999\n10000\n10000\n+10000\n-10000\n 65534\n065534\n +65534\n -65534\n "
    "65535\n065535\n +65535\n -65535\n";
char const *ref_uint =
    "0\n0\n+0\n-0\n1\n1\n+1\n-1\n 9\n09\n +9\n -9\n10\n10\n+10\n-10\n "
    "99\n099\n +99\n -99\n100\n100\n+100\n-100\n 999\n0999\n +999\n "
    "-999\n1000\n1000\n+1000\n-1000\n 9999\n09999\n +9999\n "
    "-9999\n10000\n10000\n+10000\n-10000\n 99999\n099999\n +99999\n "
    "-99999\n100000\n100000\n+100000\n-100000\n 999999\n0999999\n +999999\n "
    "-999999\n1000000\n1000000\n+1000000\n-1000000\n 9999999\n09999999\n "
    "+9999999\n -9999999\n10000000\n10000000\n+10000000\n-10000000\n "
    "99999999\n099999999\n +99999999\n "
    "-99999999\n100000000\n100000000\n+100000000\n-100000000\n "
    "999999999\n0999999999\n +999999999\n "
    "-999999999\n1000000000\n1000000000\n+1000000000\n-1000000000\n "
    "4294967294\n04294967294\n +4294967294\n -4294967294\n "
    "4294967295\n04294967295\n +4294967295\n -4294967295\n";
char const *ref_ulong =
    "0\n0\n+0\n-0\n1\n1\n+1\n-1\n 9\n09\n +9\n -9\n10\n10\n+10\n-10\n "
    "99\n099\n +99\n -99\n100\n100\n+100\n-100\n 999\n0999\n +999\n "
    "-999\n1000\n1000\n+1000\n-1000\n 9999\n09999\n +9999\n "
    "-9999\n10000\n10000\n+10000\n-10000\n 99999\n099999\n +99999\n "
    "-99999\n100000\n100000\n+100000\n-100000\n 999999\n0999999\n +999999\n "
    "-999999\n1000000\n1000000\n+1000000\n-1000000\n 9999999\n09999999\n "
    "+9999999\n -9999999\n10000000\n10000000\n+10000000\n-10000000\n "
    "99999999\n099999999\n +99999999\n "
    "-99999999\n100000000\n100000000\n+100000000\n-100000000\n "
    "999999999\n0999999999\n +999999999\n "
    "-999999999\n1000000000\n1000000000\n+1000000000\n-1000000000\n "
    "9999999999\n09999999999\n +9999999999\n "
    "-9999999999\n10000000000\n10000000000\n+10000000000\n-10000000000\n "
    "99999999999\n099999999999\n +99999999999\n "
    "-99999999999\n100000000000\n100000000000\n+100000000000\n-100000000000\n "
    "999999999999\n0999999999999\n +999999999999\n "
    "-999999999999\n1000000000000\n1000000000000\n+1000000000000\n-"
    "1000000000000\n 9999999999999\n09999999999999\n +9999999999999\n "
    "-9999999999999\n10000000000000\n10000000000000\n+10000000000000\n-"
    "10000000000000\n 99999999999999\n099999999999999\n +99999999999999\n "
    "-99999999999999\n100000000000000\n100000000000000\n+100000000000000\n-"
    "100000000000000\n 999999999999999\n0999999999999999\n +999999999999999\n "
    "-999999999999999\n1000000000000000\n1000000000000000\n+1000000000000000\n-"
    "1000000000000000\n 9999999999999999\n09999999999999999\n "
    "+9999999999999999\n "
    "-9999999999999999\n10000000000000000\n10000000000000000\n+"
    "10000000000000000\n-10000000000000000\n "
    "99999999999999999\n099999999999999999\n +99999999999999999\n "
    "-99999999999999999\n100000000000000000\n100000000000000000\n+"
    "100000000000000000\n-100000000000000000\n "
    "999999999999999999\n0999999999999999999\n +999999999999999999\n "
    "-999999999999999999\n1000000000000000000\n1000000000000000000\n+"
    "1000000000000000000\n-1000000000000000000\n "
    "9999999999999999999\n09999999999999999999\n +9999999999999999999\n "
    "-9999999999999999999\n10000000000000000000\n10000000000000000000\n+"
    "10000000000000000000\n-10000000000000000000\n "
    "18446744073709551614\n018446744073709551614\n +18446744073709551614\n "
    "-18446744073709551614\n 18446744073709551615\n018446744073709551615\n "
    "+18446744073709551615\n -18446744073709551615\n";
char const *ref_fxp10[4] = {
    /* f=0 */
    "0.\n0.\n+0.\n-0.\n1.\n1.\n+1.\n-1.\n 9.\n09.\n +9.\n "
    "-9.\n10.\n10.\n+10.\n-10.\n 99.\n099.\n +99.\n "
    "-99.\n100.\n100.\n+100.\n-100.\n 999.\n0999.\n +999.\n "
    "-999.\n1000.\n1000.\n+1000.\n-1000.\n 9999.\n09999.\n +9999.\n "
    "-9999.\n10000.\n10000.\n+10000.\n-10000.\n 99999.\n099999.\n +99999.\n "
    "-99999.\n100000.\n100000.\n+100000.\n-100000.\n 999999.\n0999999.\n "
    "+999999.\n -999999.\n1000000.\n1000000.\n+1000000.\n-1000000.\n "
    "9999999.\n09999999.\n +9999999.\n "
    "-9999999.\n10000000.\n10000000.\n+10000000.\n-10000000.\n "
    "99999999.\n099999999.\n +99999999.\n "
    "-99999999.\n100000000.\n100000000.\n+100000000.\n-100000000.\n "
    "999999999.\n0999999999.\n +999999999.\n "
    "-999999999.\n1000000000.\n1000000000.\n+1000000000.\n-1000000000.\n "
    "9999999999.\n09999999999.\n +9999999999.\n "
    "-9999999999.\n10000000000.\n10000000000.\n+10000000000.\n-10000000000.\n "
    "99999999999.\n099999999999.\n +99999999999.\n "
    "-99999999999.\n100000000000.\n100000000000.\n+100000000000.\n-"
    "100000000000.\n 999999999999.\n0999999999999.\n +999999999999.\n "
    "-999999999999.\n1000000000000.\n1000000000000.\n+1000000000000.\n-"
    "1000000000000.\n 9999999999999.\n09999999999999.\n +9999999999999.\n "
    "-9999999999999.\n10000000000000.\n10000000000000.\n+10000000000000.\n-"
    "10000000000000.\n 99999999999999.\n099999999999999.\n +99999999999999.\n "
    "-99999999999999.\n100000000000000.\n100000000000000.\n+100000000000000.\n-"
    "100000000000000.\n 999999999999999.\n0999999999999999.\n "
    "+999999999999999.\n "
    "-999999999999999.\n1000000000000000.\n1000000000000000.\n+"
    "1000000000000000.\n-1000000000000000.\n "
    "9999999999999999.\n09999999999999999.\n +9999999999999999.\n "
    "-9999999999999999.\n10000000000000000.\n10000000000000000.\n+"
    "10000000000000000.\n-10000000000000000.\n "
    "99999999999999999.\n099999999999999999.\n +99999999999999999.\n "
    "-99999999999999999.\n100000000000000000.\n100000000000000000.\n+"
    "100000000000000000.\n-100000000000000000.\n "
    "999999999999999999.\n0999999999999999999.\n +999999999999999999.\n "
    "-999999999999999999.\n1000000000000000000.\n1000000000000000000.\n+"
    "1000000000000000000.\n-1000000000000000000.\n "
    "9999999999999999999.\n09999999999999999999.\n +9999999999999999999.\n "
    "-9999999999999999999.\n10000000000000000000.\n10000000000000000000.\n+"
    "10000000000000000000.\n-10000000000000000000.\n "
    "18446744073709551614.\n018446744073709551614.\n +18446744073709551614.\n "
    "-18446744073709551614.\n 18446744073709551615.\n018446744073709551615.\n "
    "+18446744073709551615.\n -18446744073709551615.\n",
    /* f=3 */
    "0.000\n0.000\n+0.000\n-0.000\n0.001\n0.001\n+0.001\n-0.001\n0.009\n0."
    "009\n+0.009\n-0.009\n0.010\n0.010\n+0.010\n-0.010\n0.099\n0.099\n+0.099\n-"
    "0.099\n0.100\n0.100\n+0.100\n-0.100\n0.999\n0.999\n+0.999\n-0.999\n1."
    "000\n1.000\n+1.000\n-1.000\n 9.999\n09.999\n +9.999\n "
    "-9.999\n10.000\n10.000\n+10.000\n-10.000\n 99.999\n099.999\n +99.999\n "
    "-99.999\n100.000\n100.000\n+100.000\n-100.000\n 999.999\n0999.999\n "
    "+999.999\n -999.999\n1000.000\n1000.000\n+1000.000\n-1000.000\n "
    "9999.999\n09999.999\n +9999.999\n "
    "-9999.999\n10000.000\n10000.000\n+10000.000\n-10000.000\n "
    "99999.999\n099999.999\n +99999.999\n "
    "-99999.999\n100000.000\n100000.000\n+100000.000\n-100000.000\n "
    "999999.999\n0999999.999\n +999999.999\n "
    "-999999.999\n1000000.000\n1000000.000\n+1000000.000\n-1000000.000\n "
    "9999999.999\n09999999.999\n +9999999.999\n "
    "-9999999.999\n10000000.000\n10000000.000\n+10000000.000\n-10000000.000\n "
    "99999999.999\n099999999.999\n +99999999.999\n "
    "-99999999.999\n100000000.000\n100000000.000\n+100000000.000\n-100000000."
    "000\n 999999999.999\n0999999999.999\n +999999999.999\n "
    "-999999999.999\n1000000000.000\n1000000000.000\n+1000000000.000\n-"
    "1000000000.000\n 9999999999.999\n09999999999.999\n +9999999999.999\n "
    "-9999999999.999\n10000000000.000\n10000000000.000\n+10000000000.000\n-"
    "10000000000.000\n 99999999999.999\n099999999999.999\n +99999999999.999\n "
    "-99999999999.999\n100000000000.000\n100000000000.000\n+100000000000.000\n-"
    "100000000000.000\n 999999999999.999\n0999999999999.999\n "
    "+999999999999.999\n "
    "-999999999999.999\n1000000000000.000\n1000000000000.000\n+1000000000000."
    "000\n-1000000000000.000\n 9999999999999.999\n09999999999999.999\n "
    "+9999999999999.999\n "
    "-9999999999999.999\n10000000000000.000\n10000000000000.000\n+"
    "10000000000000.000\n-10000000000000.000\n "
    "99999999999999.999\n099999999999999.999\n +99999999999999.999\n "
    "-99999999999999.999\n100000000000000.000\n100000000000000.000\n+"
    "100000000000000.000\n-100000000000000.000\n "
    "999999999999999.999\n0999999999999999.999\n +999999999999999.999\n "
    "-999999999999999.999\n1000000000000000.000\n1000000000000000.000\n+"
    "1000000000000000.000\n-1000000000000000.000\n "
    "9999999999999999.999\n09999999999999999.999\n +9999999999999999.999\n "
    "-9999999999999999.999\n10000000000000000.000\n10000000000000000.000\n+"
    "10000000000000000.000\n-10000000000000000.000\n "
    "18446744073709551.614\n018446744073709551.614\n +18446744073709551.614\n "
    "-18446744073709551.614\n 18446744073709551.615\n018446744073709551.615\n "
    "+18446744073709551.615\n -18446744073709551.615\n",
    /* f=6 */
    "0.000000\n0.000000\n+0.000000\n-0.000000\n0.000001\n0.000001\n+0.000001\n-"
    "0.000001\n0.000009\n0.000009\n+0.000009\n-0.000009\n0.000010\n0.000010\n+"
    "0.000010\n-0.000010\n0.000099\n0.000099\n+0.000099\n-0.000099\n0."
    "000100\n0.000100\n+0.000100\n-0.000100\n0.000999\n0.000999\n+0.000999\n-0."
    "000999\n0.001000\n0.001000\n+0.001000\n-0.001000\n0.009999\n0.009999\n+0."
    "009999\n-0.009999\n0.010000\n0.010000\n+0.010000\n-0.010000\n0.099999\n0."
    "099999\n+0.099999\n-0.099999\n0.100000\n0.100000\n+0.100000\n-0.100000\n0."
    "999999\n0.999999\n+0.999999\n-0.999999\n1.000000\n1.000000\n+1.000000\n-1."
    "000000\n 9.999999\n09.999999\n +9.999999\n "
    "-9.999999\n10.000000\n10.000000\n+10.000000\n-10.000000\n "
    "99.999999\n099.999999\n +99.999999\n "
    "-99.999999\n100.000000\n100.000000\n+100.000000\n-100.000000\n "
    "999.999999\n0999.999999\n +999.999999\n "
    "-999.999999\n1000.000000\n1000.000000\n+1000.000000\n-1000.000000\n "
    "9999.999999\n09999.999999\n +9999.999999\n "
    "-9999.999999\n10000.000000\n10000.000000\n+10000.000000\n-10000.000000\n "
    "99999.999999\n099999.999999\n +99999.999999\n "
    "-99999.999999\n100000.000000\n100000.000000\n+100000.000000\n-100000."
    "000000\n 999999.999999\n0999999.999999\n +999999.999999\n "
    "-999999.999999\n1000000.000000\n1000000.000000\n+1000000.000000\n-1000000."
    "000000\n 9999999.999999\n09999999.999999\n +9999999.999999\n "
    "-9999999.999999\n10000000.000000\n10000000.000000\n+10000000.000000\n-"
    "10000000.000000\n 99999999.999999\n099999999.999999\n +99999999.999999\n "
    "-99999999.999999\n100000000.000000\n100000000.000000\n+100000000.000000\n-"
    "100000000.000000\n 999999999.999999\n0999999999.999999\n "
    "+999999999.999999\n "
    "-999999999.999999\n1000000000.000000\n1000000000.000000\n+1000000000."
    "000000\n-1000000000.000000\n 9999999999.999999\n09999999999.999999\n "
    "+9999999999.999999\n "
    "-9999999999.999999\n10000000000.000000\n10000000000.000000\n+10000000000."
    "000000\n-10000000000.000000\n 99999999999.999999\n099999999999.999999\n "
    "+99999999999.999999\n "
    "-99999999999.999999\n100000000000.000000\n100000000000.000000\n+"
    "100000000000.000000\n-100000000000.000000\n "
    "999999999999.999999\n0999999999999.999999\n +999999999999.999999\n "
    "-999999999999.999999\n1000000000000.000000\n1000000000000.000000\n+"
    "1000000000000.000000\n-1000000000000.000000\n "
    "9999999999999.999999\n09999999999999.999999\n +9999999999999.999999\n "
    "-9999999999999.999999\n10000000000000.000000\n10000000000000.000000\n+"
    "10000000000000.000000\n-10000000000000.000000\n "
    "18446744073709.551614\n018446744073709.551614\n +18446744073709.551614\n "
    "-18446744073709.551614\n 18446744073709.551615\n018446744073709.551615\n "
    "+18446744073709.551615\n -18446744073709.551615\n",
    /* f=9 */
    "0.000000000\n0.000000000\n+0.000000000\n-0.000000000\n0.000000001\n0."
    "000000001\n+0.000000001\n-0.000000001\n0.000000009\n0.000000009\n+0."
    "000000009\n-0.000000009\n0.000000010\n0.000000010\n+0.000000010\n-0."
    "000000010\n0.000000099\n0.000000099\n+0.000000099\n-0.000000099\n0."
    "000000100\n0.000000100\n+0.000000100\n-0.000000100\n0.000000999\n0."
    "000000999\n+0.000000999\n-0.000000999\n0.000001000\n0.000001000\n+0."
    "000001000\n-0.000001000\n0.000009999\n0.000009999\n+0.000009999\n-0."
    "000009999\n0.000010000\n0.000010000\n+0.000010000\n-0.000010000\n0."
    "000099999\n0.000099999\n+0.000099999\n-0.000099999\n0.000100000\n0."
    "000100000\n+0.000100000\n-0.000100000\n0.000999999\n0.000999999\n+0."
    "000999999\n-0.000999999\n0.001000000\n0.001000000\n+0.001000000\n-0."
    "001000000\n0.009999999\n0.009999999\n+0.009999999\n-0.009999999\n0."
    "010000000\n0.010000000\n+0.010000000\n-0.010000000\n0.099999999\n0."
    "099999999\n+0.099999999\n-0.099999999\n0.100000000\n0.100000000\n+0."
    "100000000\n-0.100000000\n0.999999999\n0.999999999\n+0.999999999\n-0."
    "999999999\n1.000000000\n1.000000000\n+1.000000000\n-1.000000000\n "
    "9.999999999\n09.999999999\n +9.999999999\n "
    "-9.999999999\n10.000000000\n10.000000000\n+10.000000000\n-10.000000000\n "
    "99.999999999\n099.999999999\n +99.999999999\n "
    "-99.999999999\n100.000000000\n100.000000000\n+100.000000000\n-100."
    "000000000\n 999.999999999\n0999.999999999\n +999.999999999\n "
    "-999.999999999\n1000.000000000\n1000.000000000\n+1000.000000000\n-1000."
    "000000000\n 9999.999999999\n09999.999999999\n +9999.999999999\n "
    "-9999.999999999\n10000.000000000\n10000.000000000\n+10000.000000000\n-"
    "10000.000000000\n 99999.999999999\n099999.999999999\n +99999.999999999\n "
    "-99999.999999999\n100000.000000000\n100000.000000000\n+100000.000000000\n-"
    "100000.000000000\n 999999.999999999\n0999999.999999999\n "
    "+999999.999999999\n "
    "-999999.999999999\n1000000.000000000\n1000000.000000000\n+1000000."
    "000000000\n-1000000.000000000\n 9999999.999999999\n09999999.999999999\n "
    "+9999999.999999999\n "
    "-9999999.999999999\n10000000.000000000\n10000000.000000000\n+10000000."
    "000000000\n-10000000.000000000\n "
    "99999999.999999999\n099999999.999999999\n +99999999.999999999\n "
    "-99999999.999999999\n100000000.000000000\n100000000.000000000\n+100000000."
    "000000000\n-100000000.000000000\n "
    "999999999.999999999\n0999999999.999999999\n +999999999.999999999\n "
    "-999999999.999999999\n1000000000.000000000\n1000000000.000000000\n+"
    "1000000000.000000000\n-1000000000.000000000\n "
    "9999999999.999999999\n09999999999.999999999\n +9999999999.999999999\n "
    "-9999999999.999999999\n10000000000.000000000\n10000000000.000000000\n+"
    "10000000000.000000000\n-10000000000.000000000\n "
    "18446744073.709551614\n018446744073.709551614\n +18446744073.709551614\n "
    "-18446744073.709551614\n 18446744073.709551615\n018446744073.709551615\n "
    "+18446744073.709551615\n -18446744073.709551615\n"};

int main(int argc, char **argv) {

  fd_boot(&argc, &argv);

  /* FIXME: MORE EXPLICIT TESTS OF FD_CSTR_PRINTF */

  fd_rng_t _rng[1];
  fd_rng_t *rng = fd_rng_join(fd_rng_new(_rng, 0U, 0UL));

  int ctr = 0;
  for (long iter = 0; iter < 10000000L; iter++) {
    if (!ctr) {
      FD_LOG_NOTICE(("Completed %li iterations", iter));
      ctr = 1000000;
    }
    ctr--;

    char buf[128];
    char c = (char)fd_rng_uchar(rng);
    buf[0] = c;
    buf[1] = '\0';
    FD_TEST(fd_cstr_to_cstr(buf) == buf);
    /**/ FD_TEST(fd_cstr_to_char(buf) == c);
    schar sc = (schar)fd_rng_uchar(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%i", (int)sc);
    FD_TEST(fd_cstr_to_schar(buf) == sc);
    short s = (short)fd_rng_ushort(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%i", (int)s);
    FD_TEST(fd_cstr_to_short(buf) == s);
    int i = (int)fd_rng_uint(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%i", i);
    FD_TEST(fd_cstr_to_int(buf) == i);
    long l = (long)fd_rng_ulong(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%li", l);
    FD_TEST(fd_cstr_to_long(buf) == l);
    uchar uc = fd_rng_uchar(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%u", (uint)uc);
    FD_TEST(fd_cstr_to_uchar(buf) == uc);
    ushort us = fd_rng_ushort(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%u", (uint)us);
    FD_TEST(fd_cstr_to_ushort(buf) == us);
    uint ui = fd_rng_uint(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%u", ui);
    FD_TEST(fd_cstr_to_uint(buf) == ui);
    ulong ul = fd_rng_ulong(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%lu", ul);
    FD_TEST(fd_cstr_to_ulong(buf) == ul);
    float f = fd_rng_float_c0(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%.21e", (double)f);
    FD_TEST(fd_cstr_to_float(buf) == f);
#if FD_HAS_DOUBLE
    double d = fd_rng_double_c0(rng);
    fd_cstr_printf(buf, 128UL, NULL, "%.21e", d);
    FD_TEST(fd_cstr_to_double(buf) == d);
#endif
  }

  do {

    ulong seq[14];
    static ulong const ref[14] = {1UL, 2UL, 3UL,  4UL,  5UL,  6UL,  7UL,
                                  8UL, 9UL, 10UL, 12UL, 14UL, 16UL, 18UL};

    /* Length */

    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19/2", NULL, 0UL) ==
            14UL); /* traditional style stride */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19:2", NULL, 0UL) ==
            14UL); /* taskset style stride */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 / 2 ", NULL, 0UL) ==
            14UL); /* with lots of whitespace */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(NULL, NULL, 0UL) == 0UL); /* NULL cstr */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" x , 2 - 9 , 10 - 19 : 2 ", NULL, 0UL) ==
            0UL); /* bad range start */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 x 2 - 9 , 10 - 19 : 2 ", NULL, 0UL) ==
            0UL); /* bad range delim */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - x , 10 - 19 : 2 ", NULL, 0UL) ==
            0UL); /* bad range end */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : x ", NULL, 0UL) ==
            0UL); /* bad stride */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 1 , 10 - 19 : 2 ", NULL, 0UL) ==
            0UL); /* bad range */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : 0 ", NULL, 0UL) ==
            0UL); /* inval stride */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-2 - -1", NULL, 0UL) ==
            2UL); /* exact end at ulong max */
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-4 - -1/2", NULL, 0UL) ==
            2UL); /* inexact end at ulong max */

    /* Normal */

    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1", seq, 14UL) == 1UL && seq[0] == 1UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19/2", seq, 14UL) == 14UL &&
            !memcmp(seq, ref, 14UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19:2", seq, 14UL) == 14UL &&
            !memcmp(seq, ref, 14UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 / 2 ", seq, 14UL) ==
                14UL &&
            !memcmp(seq, ref, 14UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(NULL, seq, 14UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" x , 2 - 9 , 10 - 19 : 2 ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 x 2 - 9 , 10 - 19 : 2 ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - x , 10 - 19 : 2 ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : x ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 1 , 10 - 19 : 2 ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : 0 ", seq, 14UL) ==
            0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-2 - -1", seq, 14UL) == 2UL &&
            seq[0] == -2UL && seq[1] == -1UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-4 - -1/2", seq, 14UL) == 2UL);

    /* Truncated */

    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1", seq, 3UL) == 1UL && seq[0] == 1UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19/2", seq, 3UL) == 14UL &&
            !memcmp(seq, ref, 3UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("1,2-9,10-19:2", seq, 3UL) == 14UL &&
            !memcmp(seq, ref, 3UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 / 2 ", seq, 3UL) ==
                14UL &&
            !memcmp(seq, ref, 3UL * sizeof(ulong)));
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(NULL, seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" x , 2 - 9 , 10 - 19 : 2 ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 x 2 - 9 , 10 - 19 : 2 ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - x , 10 - 19 : 2 ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : x ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 1 , 10 - 19 : 2 ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq(" 1 , 2 - 9 , 10 - 19 : 0 ", seq, 3UL) == 0UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-2 - -1", seq, 3UL) == 2UL &&
            seq[0] == -2UL && seq[1] == -1UL);
    memset(seq, 0, 14UL * sizeof(ulong));
    FD_TEST(fd_cstr_to_ulong_seq("-4 - -1/2", seq, 3UL) == 2UL);

  } while (0);

  char const *text = "The quick brown fox jumps over the lazy dog.";
  ulong sz = strlen(text);

  char buf[4096];
  char *p0;
  char *p;

  p = fd_cstr_init(buf);
  p0 = p;
  p = fd_cstr_append_char(fd_cstr_append_text(p, NULL, 0UL), '\n');
  FD_TEST(p0 + 1UL == p);
  p0 = p;
  p = fd_cstr_append_char(fd_cstr_append_text(p, text, 0UL), '\n');
  FD_TEST(p0 + 1UL == p);
  p0 = p;
  p = fd_cstr_append_char(fd_cstr_append_text(p, text, sz - 1UL), '\n');
  FD_TEST(p0 + sz == p);
  p0 = p;
  p = fd_cstr_append_char(fd_cstr_append_text(p, text, sz), '\n');
  FD_TEST(p0 + sz + 1UL == p);
  fd_cstr_fini(p);
  ulong len = strlen(ref_text);
  FD_TEST(strlen(buf) == len && !memcmp(buf, ref_text, len + 1UL));

#define TEST_APPEND(T)                                                         \
  do {                                                                         \
    p = fd_cstr_init(buf);                                                     \
    T x = (T)1UL;                                                              \
    T b = (T)10UL;                                                             \
    ulong d = 1UL;                                                             \
    int stop = 0;                                                              \
    for (;;) {                                                                 \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '\0', (T)(x - (T)1), d), '\n'); \
      FD_TEST(p0 + d + 1UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, '0', '\0', (T)(x - (T)1), d), '\n'); \
      FD_TEST(p0 + d + 1UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '+', (T)(x - (T)1), d + 1UL),   \
          '\n');                                                               \
      FD_TEST(p0 + d + 2UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '-', (T)(x - (T)1), d + 1UL),   \
          '\n');                                                               \
      FD_TEST(p0 + d + 2UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '\0', x, d), '\n');             \
      FD_TEST(p0 + d + 1UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, '0', '\0', x, d), '\n');             \
      FD_TEST(p0 + d + 1UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '+', x, d + 1UL), '\n');        \
      FD_TEST(p0 + d + 2UL == p);                                              \
      p0 = p;                                                                  \
      p = fd_cstr_append_char(                                                 \
          fd_cstr_append_##T##_as_text(p, ' ', '-', x, d + 1UL), '\n');        \
      FD_TEST(p0 + d + 2UL == p);                                              \
      if (stop)                                                                \
        break;                                                                 \
      T y = (T)(x * b);                                                        \
      if ((y / b) == x) {                                                      \
        x = y;                                                                 \
      } else {                                                                 \
        x = (T)~0UL;                                                           \
        stop = 1;                                                              \
      }                                                                        \
      d++;                                                                     \
    }                                                                          \
    fd_cstr_fini(p);                                                           \
    ulong len = strlen(ref_##T);                                               \
    FD_TEST(strlen(buf) == len && !memcmp(buf, ref_##T, len + 1UL));           \
  } while (0)

  TEST_APPEND(uchar);
  TEST_APPEND(ushort);
  TEST_APPEND(uint);
  TEST_APPEND(ulong);

#undef TEST_APPEND

  do {
    ulong b = 10UL;
    ulong fxp_one = 1UL;
    for (ulong f = 0UL; f < 10UL; f += 3UL) {
      char const *ref_buf = ref_fxp10[f / 3UL];

      p = fd_cstr_init(buf);
      ulong x = 1UL;
      ulong d = f + 2UL;
      int stop = 0;
      for (;;) {
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '\0', f, x - 1UL, d), '\n');
        FD_TEST(p0 + d + 1UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, '0', '\0', f, x - 1UL, d), '\n');
        FD_TEST(p0 + d + 1UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '+', f, x - 1UL, d + 1UL),
            '\n');
        FD_TEST(p0 + d + 2UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '-', f, x - 1UL, d + 1UL),
            '\n');
        FD_TEST(p0 + d + 2UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '\0', f, x, d), '\n');
        FD_TEST(p0 + d + 1UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, '0', '\0', f, x, d), '\n');
        FD_TEST(p0 + d + 1UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '+', f, x, d + 1UL), '\n');
        FD_TEST(p0 + d + 2UL == p);
        p0 = p;
        p = fd_cstr_append_char(
            fd_cstr_append_fxp10_as_text(p, ' ', '-', f, x, d + 1UL), '\n');
        FD_TEST(p0 + d + 2UL == p);
        if (stop)
          break;
        ulong y = x * b;
        if ((y / b) == x) {
          x = y;
        } else {
          x = ~0UL;
          stop = 1;
        }
        d += (x > fxp_one);
      }
      fd_cstr_fini(p);
      ulong len = strlen(ref_buf);
      FD_TEST(strlen(buf) == len && !memcmp(buf, ref_buf, len + 1UL));

      fxp_one *= b * b * b;
    }
  } while (0);

  do {
    char *tok[8];

    FD_TEST(!fd_cstr_tokenize(tok, 8UL, NULL, ','));
    strcpy(buf, "");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 0UL);
    strcpy(buf, " ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 0UL);
    strcpy(buf, "|");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], ""));
    strcpy(buf, " |");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], ""));
    strcpy(buf, "| ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], ""));
    strcpy(buf, " | ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], ""));
    strcpy(buf, "a");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a"));
    strcpy(buf, " a");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a"));
    strcpy(buf, "a ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a "));
    strcpy(buf, " a ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a "));
    strcpy(buf, "ab");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "ab"));
    strcpy(buf, " ab");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "ab"));
    strcpy(buf, "ab ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "ab "));
    strcpy(buf, " ab ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "ab "));
    strcpy(buf, "a b");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a b"));
    strcpy(buf, " a b");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a b"));
    strcpy(buf, "a b ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a b "));
    strcpy(buf, " a b ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, '|') == 1UL);
    FD_TEST(!strcmp(tok[0], "a b "));
    strcpy(buf, ";c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], ""));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], ""));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " a;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "a ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " a ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "ab;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "ab"));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " ab;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "ab"));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "ab ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "ab "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " ab ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "ab "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "a b;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a b"));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " a b;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a b"));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "a b ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a b "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, " a b ;c");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[0], "a b "));
    FD_TEST(!strcmp(tok[1], "c"));
    strcpy(buf, "c;");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 1UL);
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 1UL);
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;;");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], ""));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;; ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], ""));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; ;");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], ""));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; ; ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], ""));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;a");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; a");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;a ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; a ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;ab");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "ab"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; ab");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "ab"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;ab ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "ab "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; ab ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "ab "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;a b");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a b"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; a b");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a b"));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c;a b ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a b "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "c; a b ");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 2UL);
    FD_TEST(!strcmp(tok[1], "a b "));
    FD_TEST(!strcmp(tok[0], "c"));
    strcpy(buf, "a;;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], ""));
    strcpy(buf, "a; ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], ""));
    strcpy(buf, "a;b;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b"));
    strcpy(buf, "a; b;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b"));
    strcpy(buf, "a;b ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b "));
    strcpy(buf, "a; b ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b "));
    strcpy(buf, "a;bc;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "bc"));
    strcpy(buf, "a; bc;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "bc"));
    strcpy(buf, "a;bc ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "bc "));
    strcpy(buf, "a; bc ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "bc "));
    strcpy(buf, "a;b c;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b c"));
    strcpy(buf, "a; b c;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b c"));
    strcpy(buf, "a;b c ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b c "));
    strcpy(buf, "a; b c ;d");
    FD_TEST(fd_cstr_tokenize(tok, 8UL, buf, ';') == 3UL);
    FD_TEST(!strcmp(tok[0], "a"));
    FD_TEST(!strcmp(tok[2], "d"));
    FD_TEST(!strcmp(tok[1], "b c "));

    char buf2[16];
    strcpy(buf2, "a; b c ;d");
    FD_TEST(fd_cstr_tokenize(NULL, 0UL, buf2, ';') == 3UL);
    FD_TEST(!strcmp(buf, buf2));
    strcpy(buf2, "a; b c ;d");
    FD_TEST(fd_cstr_tokenize(tok, 1UL, buf2, ';') == 3UL);
    FD_TEST(!strcmp(buf, buf2));
    FD_TEST(!strcmp(tok[0], "a"));
  } while (0);

  /* Test FD_CSTR_CASECMP */
  do {
    FD_TEST(fd_cstr_casecmp("Hello", "hello") ==
            0); // Case-insensitive compare, should be considered equal
    FD_TEST(fd_cstr_casecmp("world", "WORLD") ==
            0); // Case-insensitive compare, should be considered equal
    FD_TEST(fd_cstr_casecmp("OpenAI", "openai") ==
            0); // Case-insensitive compare, should be considered equal
    FD_TEST(fd_cstr_casecmp("Test", "test123") !=
            0); // Not equal, should not return 0
    FD_TEST(fd_cstr_casecmp("Example", "example!") !=
            0); // Not equal, should not return 0
  } while (0);

  fd_rng_delete(fd_rng_leave(rng));

  FD_LOG_NOTICE(("pass"));
  fd_halt();
  return 0;
}
