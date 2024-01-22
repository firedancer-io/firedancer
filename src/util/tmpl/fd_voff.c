/* Declare a header-only API for fast manipulation of versioned offsets.
   These are useful building blocks of interprocess lockfree algorithms.
   The (ver,off) pair itself is represented in an atomic operation
   friendly primitive unsigned integer type.  Example:

     #define VOFF_NAME my_voff
     #include "util/tmpl/fd_voff.c"

   will declare the following in the compile unit:

     typedef ulong my_voff_t;

     enum {
       my_voff_VER_WIDTH = 20,
       my_voff_OFF_WIDTH = 44
     };

     int       my_voff_ver_width( void );                 // return the version bit width (20)
     int       my_voff_off_width( void );                 // return the offset bit width (44)
     ulong     my_voff_ver_max  ( void );                 // return the maximum version number (2^20-1)
     ulong     my_voff_off_max  ( void );                 // return the maximum offset (2^44-1)
     my_voff_t my_voff          ( ulong ver, ulong off ); // pack the least significant bits of ver and off into a my_voff_t.
     ulong     my_voff_ver      ( my_voff_t voff );       // unpack the version from a my_voff_t, will be in [0,my_voff_ver_max()]
     ulong     my_voff_off      ( my_voff_t voff );       // unpack the version from a my_voff_t, will be in [0,my_voff_off_max()]

   This is safe for multiple inclusion and other options exist for fine
   tuning described below. */

#ifndef VOFF_NAME
#error "Define VOFF_NAME"
#endif

/* VOFF_TYPE is a type that behaves like a primitive integral type, is
   efficient to pass around by value and is ideally atomic operation
   friendly.  Defaults to ulong. */

#ifndef VOFF_TYPE
#define VOFF_TYPE ulong
#endif

/* VOFF_VER_WIDTH is the bit width to use for versions.  All other
   bytes in the VOFF_TYPE will be used for offsets.  As such, this
   should be in [1,width_type) */

#ifndef VOFF_VER_WIDTH
#define VOFF_VER_WIDTH (20)
#endif

#define VOFF_(x)FD_EXPAND_THEN_CONCAT3(VOFF_NAME,_,x)

typedef VOFF_TYPE VOFF_(t);

enum {
  VOFF_(VER_WIDTH) = VOFF_VER_WIDTH,
  VOFF_(OFF_WIDTH) = 8*(int)sizeof(VOFF_TYPE) - VOFF_VER_WIDTH
};

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline int       VOFF_(ver_width)( void ) { return VOFF_VER_WIDTH;                                    }
FD_FN_CONST static inline int       VOFF_(off_width)( void ) { return 8*(int)sizeof(VOFF_TYPE) - VOFF_VER_WIDTH;         }
FD_FN_CONST static inline VOFF_TYPE VOFF_(ver_max)  ( void ) { return (((VOFF_TYPE)1) << VOFF_VER_WIDTH) - (VOFF_TYPE)1; }
FD_FN_CONST static inline VOFF_TYPE VOFF_(off_max)  ( void ) { return (~(VOFF_TYPE)0) >> VOFF_VER_WIDTH;                 }

FD_FN_CONST static inline VOFF_(t)
VOFF_NAME( VOFF_TYPE ver,
           VOFF_TYPE off) {
  return (ver & ((((VOFF_TYPE)1)<<VOFF_VER_WIDTH) - (VOFF_TYPE)1)) | (off << VOFF_VER_WIDTH);
}

FD_FN_CONST static inline VOFF_TYPE VOFF_(ver)( VOFF_(t) voff ) { return voff & ((((VOFF_TYPE)1)<<VOFF_VER_WIDTH) - (VOFF_TYPE)1); }
FD_FN_CONST static inline VOFF_TYPE VOFF_(off)( VOFF_(t) voff ) { return voff >> VOFF_VER_WIDTH;                                   }

FD_PROTOTYPES_END

#undef VOFF_

#undef VOFF_VER_WIDTH
#undef VOFF_TYPE
#undef VOFF_NAME

