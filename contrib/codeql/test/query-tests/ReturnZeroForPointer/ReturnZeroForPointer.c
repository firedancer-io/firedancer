#define NULL 0
#define ZERO 0

struct thing {
  int value;
};

typedef struct thing thing_t;
typedef thing_t * thing_ptr_t;

void *
returns_zero_void_pointer( void ) {
  return 0; // $ Alert
}

thing_t *
returns_zero_struct_pointer( void ) {
  return 0; // $ Alert
}

thing_ptr_t
returns_zero_typedef_pointer( void ) {
  return 0; // $ Alert
}

thing_t *
returns_mixed_pointer( int cond, thing_t * ptr ) {
  if( cond ) {
    return 0; // $ Alert
  }

  return ptr;
}

thing_t *
returns_null_macro( void ) {
  return NULL;
}

thing_t *
returns_zero_macro( void ) {
  return ZERO;
}

thing_t *
returns_casted_zero( void ) {
  return (thing_t *)0; // $ Alert
}

thing_t *
returns_existing_pointer( thing_t * ptr ) {
  return ptr;
}

int
returns_zero_integer( void ) {
  return 0;
}

thing_t *
returns_zero_long_literal( void ) {
  return 0L; // $ Alert
}
