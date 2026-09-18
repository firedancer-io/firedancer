#include <stdint.h>

int
main( void ) {
  uintptr_t volatile addr = UINTPTR_MAX;
  unsigned char * ptr = (unsigned char *)addr;
  ptr++;
  return !!ptr;
}
