{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/de408167ede9c2cab0a7831f4079ff9ba8c644d8.tar.gz";
    sha256 = "sha256:05xf26nd4ryyrx9xn3rzpzawf14r1pw8r0ljba0as852w63z4rh9";
  }) {},
  gcc930chan ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/3b05df1d13c1b315cecc610a2f3180f6669442f0.tar.gz";
  }) {}
}:

pkgs.mkShell {
  packages = with pkgs;[
    # Compiler (GCC)
    gcc930chan.gcc-unwrapped

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

