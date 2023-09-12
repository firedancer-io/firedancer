#include "fd_base64.h"

/* Function to get the index of a character in the Base64 alphabet */
static inline int
base64_decode_char( char c ) {
  if( c >= 'A' && c <= 'Z' ) return c - 'A';
  if( c >= 'a' && c <= 'z' ) return c - 'a' + 26;
  if( c >= '0' && c <= '9' ) return c - '0' + 52;
  if( c == '+' ) return 62;
  if( c == '/' ) return 63;
  return -1; // Invalid character
}

/* Function to decode a base64 encoded string into an unsigned char array
   The function returns the length of the decoded array */
int
fd_base64_decode( const char *  encoded,
                  uchar *       decoded ) {
  int    len = 0;
  int    bits_collected = 0;
  uint   accumulator = 0;

  while ( *encoded ) {
    char c = *encoded++;
    int value = base64_decode_char(c);

    if( value >= 0 ) {
      accumulator = ( accumulator << 6 ) | ( uint ) value;
      bits_collected += 6;

      if( bits_collected >= 8 ) {
        bits_collected -= 8;
        decoded[ len++ ] = ( uchar )( accumulator >> bits_collected );
        accumulator &= ( 1U << bits_collected ) - 1;
      }
    } else if( c == '=' ) {
      /* Padding character, ignore and break the loop */
      break;
    } else {
      /* Fail with invalid characters (e.g., whitespace, padding) */
      return -1;
    }
  }

  return len;
}

ulong
fd_base64_encode( const uchar * data,
                  int           data_len,
                  char *        encoded ) {
  static const char base64_alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  uint encoded_len = 0;
  uint accumulator = 0;
  int bits_collected = 0;

  while( data_len-- ) {
    accumulator = ( accumulator << 8 ) | *data++;
    bits_collected += 8;

    while( bits_collected >= 6 ) {
      encoded[ encoded_len++ ] = base64_alphabet[ ( accumulator >> ( bits_collected - 6) ) & 0x3F ];
      bits_collected -= 6;
    }
  }

  if( bits_collected > 0 ) {
    // If there are remaining bits, pad the last Base64 character with zeroes
    accumulator <<= 6 - bits_collected;
    encoded[ encoded_len++ ] = base64_alphabet[accumulator & 0x3F ];
  }

  // Add padding characters if necessary
  while( encoded_len % 4 != 0 ) {
    encoded[ encoded_len++ ] = '=';
  }

  // Null-terminate the encoded string
  encoded[ encoded_len ] = '\0';

  return encoded_len;
}
