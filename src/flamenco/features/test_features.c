#include "fd_features.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_feature_t feature;
  FD_TEST( !fd_feature_decode( &feature, NULL, 0UL ) );

  FD_TEST( fd_feature_decode( &feature, (uchar[]){0}, 1UL ) &&
           feature.is_active==0 && feature.activation_slot==ULONG_MAX );

  FD_TEST( fd_feature_decode( &feature, (uchar[]){0, 0xff}, 2UL ) &&
           feature.is_active==0 && feature.activation_slot==ULONG_MAX );

  FD_TEST( !fd_feature_decode( &feature, (uchar[]){1, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78}, 8UL ) );

  FD_TEST( fd_feature_decode( &feature, (uchar[]){1, 0, 0, 0, 0, 0, 0, 0, 0}, 9UL ) &&
           feature.is_active==1 && feature.activation_slot==0UL );

  FD_TEST( fd_feature_decode( &feature, (uchar[]){1, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89}, 9UL ) &&
           feature.is_active==1 && feature.activation_slot==0x8978675645342312UL );

  FD_TEST( fd_feature_decode( &feature, (uchar[]){1, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0xff}, 10UL ) &&
           feature.is_active==1 && feature.activation_slot==0x8978675645342312UL );

  FD_TEST( !fd_feature_decode( &feature, (uchar[]){2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89}, 9UL ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
