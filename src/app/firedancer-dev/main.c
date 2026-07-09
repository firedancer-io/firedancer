#include "main.h"
#include "../firedancer/topology.h"
#include "../firedancer/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"

int
main( int     argc,
      char ** argv ) {
  fd_config_file_t _default = fd_config_file_default();
  fd_config_file_t testnet = fd_config_file_testnet();
  fd_config_file_t devnet = fd_config_file_devnet();
  fd_config_file_t mainnet = fd_config_file_mainnet();
  fd_config_file_t testnet_jito = fd_config_file_testnet_jito();
  fd_config_file_t mainnet_jito = fd_config_file_mainnet_jito();

  fd_config_file_t * configs[] = {
    &_default,
    &testnet,
    &devnet,
    &mainnet,
    &testnet_jito,
    &mainnet_jito,
    NULL
  };

  return fd_dev_main( argc, argv, 1, configs, fd_topo_initialize );
}
