{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/de408167ede9c2cab0a7831f4079ff9ba8c644d8.tar.gz";
    sha256 = "sha256:05xf26nd4ryyrx9xn3rzpzawf14r1pw8r0ljba0as852w63z4rh9";
  }) {}
}:

pkgs.mkShell {
  packages = with pkgs;[
    # Compiler (GCC)
    gcc9
    gcc9Stdenv

    # Compiler (Clang)
    clang_15

    # Coverage tools
    lcov
    llvm_15

    # C dependencies
    libbpf
    pkg-config
    quictls
    rocksdb
    xdp-tools
    zstd

    # Dev Utils
    git
  ];
}

