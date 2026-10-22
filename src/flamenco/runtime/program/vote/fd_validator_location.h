#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h

#include "../../../fd_flamenco_base.h"

/* fd_validator_location_t is the self-reported location of a
   validator, as described in SIMD-0674.

   A location is a WGS84 ECEF "Earth-Centered, Earth-Fixed" point
   in meters, measured from the center of the Earth. See
   https://en.wikipedia.org/wiki/Earth-centered,_Earth-fixed_coordinate_system

                  +z (North Pole)
                   |
                   |    . (x,y,z)
                   |   /
                   |  /
                   O------------ +y (equator, 90E)
                  /
                 /
               +x (equator, 0E)

   Validators are required to report the ECEF point on the Earth's
   surface directly below them, about 6400km from the center.  Their
   height above the surface should be set to 0:

               validator
                   o
                   |   height h (= 0)
         ----------*----------  the Earth's surface
                   ^
                   reported location

   To get this point:

     1. Look up the validator's latitude and longitude.
     2. Convert them to (x,y,z) with height h = 0, using a GPS library
        or an online converter such as
        https://geodesy.noaa.gov/TOOLS/XYZ/xyz.shtml
     3. Round x, y and z to the nearest meter.

   The conversion with h = 0:
     N = r / sqrt( 1 - e2*sin(lat)^2 )      r  = 6378137
                                            e2 = 0.00669437999014
     x = round( (N+h)        * cos(lat) * cos(lon) )
     y = round( (N+h)        * cos(lat) * sin(lon) )
     z = round( (N*(1-e2)+h) * sin(lat) )

   Frankfurt (50.11N, 8.68E) is (4051542, 618526, 4870645).

   See below for how we validate that the ECEF point reported is a
   valid point on the Earth's surface. */

struct fd_validator_location {
  int x;
  int y;
  int z;
};
typedef struct fd_validator_location fd_validator_location_t;

/* A self-reported location is valid if it describes a point on the
   Earth's surface (not above - in space - or below - underground).
   Here the Earth's surface is defined as being the WGS84 ellipsoid,
   which is roughly sea level. The criteria for checking this are
   defined in SIMD-0674 and explained below.

   The Earth is not a perfect sphere, but slightly flattened. It is
   about 43km wider at the equator than at the poles.
   Cut in half through the poles:

                               z
                               |
             +-----------------+-----------------+  <- COORD_MAX
             |        ..--'''''|'''''--..        |
             |    .-''         b         ''-.    |
             |  .'             |             '.  |
             | /               |               \ |
        -----+-----------------O-------r-------+-----> x, y
             | \               |               / |
             |  '.             |             .'  |
             |    '-..         |         ..-'    |
             |        ''--.....|.....--''        |
             +-----------------+-----------------+

     r = 6378137m, the radius at the equator
     b = 6356752m, the radius at the poles

   To check that a location is indeed a point on the Earth's surface,
   we don't want to do floating point trigonometry, so we instead
   stretch the Earth into a perfect sphere, and then a simple integer
   magnitude check works for all points:
   - Stretch z slightly (FLATTENING_CORRECTION), which turns the
     flattened Earth into an almost perfect sphere of radius r.
   - Check that the stretched point is within a +-1km SURFACE_TOLERANCE
     above or below the Earth's surface (SURFACE_DIST2).

         too low                 valid                too high
       <---------|=================|=================|--------->  dist2
           SURFACE_DIST2     SURFACE_DIST2     SURFACE_DIST2
        - SURFACE_TOLERANCE                 + SURFACE_TOLERANCE
             1km below          ground           1km above

   Example: Frankfurt is at (4051542, 618526, 4870645).  Every
   coordinate is within COORD_MAX (6378138), and:

       x^2                                   16414992577764
     + y^2                                     382574412676
     + z^2                                   23723182716025
     + (FLATTENING_CORRECTION * z^2) >> 16     159998272102
     ------------------------------------------------------
     = dist2                                 40680747978567
     - SURFACE_DIST2                         40680631590769
     ------------------------------------------------------
     = difference                                 116387798

   116387798 is less than SURFACE_TOLERANCE (12756274000), so Frankfurt
   is valid.  A point 2km higher, (4052815, 618720, 4872175), is
   25680309853 away, which is too far:

         too low                 valid                too high
       <---------|=================|=================|--------->  dist2
                                   ^                     ^
                               Frankfurt             2km above
                                                     Frankfurt */
#define FD_VALIDATOR_LOCATION_SURFACE_DIST2         (40680631590769UL)
#define FD_VALIDATOR_LOCATION_FLATTENING_CORRECTION (442UL)
#define FD_VALIDATOR_LOCATION_SURFACE_TOLERANCE     (12756274000UL)

/* The largest allowed magnitude of each coordinate: the Earth's radius
   at the equator (6378137m) plus 1m. */

#define FD_VALIDATOR_LOCATION_COORD_MAX (6378138)

FD_PROTOTYPES_BEGIN

/* Returns the squared distance of loc from the center of the Earth,
   with the flattening correction as described above, treating the
   Earth as a perfect sphere.

   Assumes every coordinate is no larger than
   FD_VALIDATOR_LOCATION_COORD_MAX. */
FD_FN_PURE static inline ulong
fd_validator_location_dist2_on_sphere( fd_validator_location_t const * loc ) {
  ulong x2 = (ulong)( (long)loc->x*(long)loc->x );
  ulong y2 = (ulong)( (long)loc->y*(long)loc->y );
  ulong z2 = (ulong)( (long)loc->z*(long)loc->z );
  return x2 + y2 + z2 + ( ( FD_VALIDATOR_LOCATION_FLATTENING_CORRECTION*z2 )>>16 );
}

/* Returns 1 if loc is a valid location on the Earth's surface,
   0 otherwise. */
FD_FN_PURE static inline int
fd_validator_location_is_valid( fd_validator_location_t const * loc ) {
  if( FD_UNLIKELY( loc->x<-FD_VALIDATOR_LOCATION_COORD_MAX || loc->x>FD_VALIDATOR_LOCATION_COORD_MAX ||
                   loc->y<-FD_VALIDATOR_LOCATION_COORD_MAX || loc->y>FD_VALIDATOR_LOCATION_COORD_MAX ||
                   loc->z<-FD_VALIDATOR_LOCATION_COORD_MAX || loc->z>FD_VALIDATOR_LOCATION_COORD_MAX ) ) return 0;
  ulong dist2 = fd_validator_location_dist2_on_sphere( loc );
  return dist2>=FD_VALIDATOR_LOCATION_SURFACE_DIST2-FD_VALIDATOR_LOCATION_SURFACE_TOLERANCE &&
         dist2<=FD_VALIDATOR_LOCATION_SURFACE_DIST2+FD_VALIDATOR_LOCATION_SURFACE_TOLERANCE;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h */
