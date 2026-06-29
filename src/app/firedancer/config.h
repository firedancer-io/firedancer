#ifndef HEADER_fd_src_app_firedancer_config_h
#define HEADER_fd_src_app_firedancer_config_h

#include "../shared/fd_config_file.h"

extern uchar const firedancer_default_config[];
extern ulong const firedancer_default_config_sz;

extern uchar const firedancer_testnet_config[];
extern ulong const firedancer_testnet_config_sz;

extern uchar const firedancer_devnet_config[];
extern ulong const firedancer_devnet_config_sz;

extern uchar const firedancer_mainnet_config[];
extern ulong const firedancer_mainnet_config_sz;

extern uchar const firedancer_testnet_jito_config[];
extern ulong const firedancer_testnet_jito_config_sz;

extern uchar const firedancer_mainnet_jito_config[];
extern ulong const firedancer_mainnet_jito_config_sz;

fd_config_file_t
fd_config_file_default( void ) {
  return (fd_config_file_t) {
    .name    = "default",
    .data    = firedancer_default_config,
    .data_sz = firedancer_default_config_sz,
  };
}

fd_config_file_t
fd_config_file_testnet( void ) {
  return (fd_config_file_t) {
    .name    = "testnet",
    .data    = firedancer_testnet_config,
    .data_sz = firedancer_testnet_config_sz,
  };
}

fd_config_file_t
fd_config_file_devnet( void ) {
  return (fd_config_file_t) {
    .name    = "devnet",
    .data    = firedancer_devnet_config,
    .data_sz = firedancer_devnet_config_sz,
  };
}

fd_config_file_t
fd_config_file_mainnet( void ) {
  return (fd_config_file_t) {
    .name    = "mainnet",
    .data    = firedancer_mainnet_config,
    .data_sz = firedancer_mainnet_config_sz,
  };
}

fd_config_file_t
fd_config_file_testnet_jito( void ) {
  return (fd_config_file_t) {
    .name    = "testnet-jito",
    .data    = firedancer_testnet_jito_config,
    .data_sz = firedancer_testnet_jito_config_sz,
  };
}

fd_config_file_t
fd_config_file_mainnet_jito( void ) {
  return (fd_config_file_t) {
    .name    = "mainnet-jito",
    .data    = firedancer_mainnet_jito_config,
    .data_sz = firedancer_mainnet_jito_config_sz,
  };
}

#endif /* HEADER_fd_src_app_firedancer_config_h */
