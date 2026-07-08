#ifndef HEADER_fd_src_util_tmpl_fd_unit_test_h
#define HEADER_fd_src_util_tmpl_fd_unit_test_h

struct fd_unit_test {
  char const * name;
  void (* fn)( void );
  struct fd_unit_test * next;
};

typedef struct fd_unit_test fd_unit_test_t;

#define FD_UNIT_TEST( name )                                           \
  static void name( void );                                            \
  static fd_unit_test_t name##_test = { #name, name, NULL };           \
  __attribute__((constructor)) static void register_##name( void ) { register_unit_test( &name##_test ); } \
  static void name( void )

static inline void
register_unit_test( fd_unit_test_t * test );

#endif /* HEADER_fd_src_util_tmpl_fd_unit_test_h */
