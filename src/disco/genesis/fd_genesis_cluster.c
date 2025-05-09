#include "fd_genesis_cluster.h"

FD_FN_PURE ulong
fd_genesis_cluster_identify( char const * expected_genesis_hash ) {
  char const * DEVNET_GENESIS_HASH       = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
  char const * TESTNET_GENESIS_HASH      = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
  char const * MAINNET_BETA_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
  char const * PYTHTEST_GENESIS_HASH     = "EkCkB7RWVrgkcpariRpd3pjf7GwiCMZaMHKUpB5Na1Ve";
  char const * PYTHNET_GENESIS_HASH      = "GLKkBUr6r72nBtGrtBPJLRqtsh8wXZanX4xfnqKnWwKq";

  ulong cluster = FD_CLUSTER_UNKNOWN;
  if( FD_LIKELY( expected_genesis_hash ) ) {
    if( FD_UNLIKELY( !strcmp( expected_genesis_hash, DEVNET_GENESIS_HASH ) ) )            cluster = FD_CLUSTER_DEVNET;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, TESTNET_GENESIS_HASH ) ) )      cluster = FD_CLUSTER_TESTNET;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, MAINNET_BETA_GENESIS_HASH ) ) ) cluster = FD_CLUSTER_MAINNET_BETA;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, PYTHTEST_GENESIS_HASH ) ) )     cluster = FD_CLUSTER_PYTHTEST;
    else if( FD_UNLIKELY( !strcmp( expected_genesis_hash, PYTHNET_GENESIS_HASH ) ) )      cluster = FD_CLUSTER_PYTHNET;
  }

  return cluster;
}

FD_FN_CONST char const *
fd_genesis_cluster_name( ulong cluster ) {
  switch( cluster ) {
    case FD_CLUSTER_UNKNOWN:      return "unknown";
    case FD_CLUSTER_PYTHTEST:     return "pythtest";
    case FD_CLUSTER_TESTNET:      return "testnet";
    case FD_CLUSTER_DEVNET:       return "devnet";
    case FD_CLUSTER_PYTHNET:      return "pythnet";
    case FD_CLUSTER_MAINNET_BETA: return "mainnet-beta";
    default:                      return "unknown";
  }
}
