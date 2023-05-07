{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/cece2880925ae3ef222953859a37055919489474.tar.gz";
    sha256 = "sha256:09xhpzl1p4m6js3pmzcqqmpmz3x47n1jdjzh3mrdi23lp5yb5f73";
  }) {}
}:

pkgs.mkShell {
  packages = with pkgs;[
    # Build system
    pkg-config

    # Compiler (GCC)
    gcc9
    gcc9Stdenv

    # Compiler (Clang)
    clang_15

    # Coverage tools
    lcov
    llvm_15

    # C dependencies
    pkg-config
    (quictls.override { static = true; })
    rocksdb
    zlib.static
    (zstd.override { static = true; })

    # Dev Utils
    git
    xdp-tools
  ];
}

