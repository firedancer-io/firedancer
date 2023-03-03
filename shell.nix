{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/de408167ede9c2cab0a7831f4079ff9ba8c644d8.tar.gz";
    sha256 = "sha256:05xf26nd4ryyrx9xn3rzpzawf14r1pw8r0ljba0as852w63z4rh9";
  }) {}
}:

pkgs.mkShell {
  packages = with pkgs;[
    gcc9
    gcc9Stdenv

    clang_15

    libbpf
    numactl
    pkg-config
    quictls
    xdp-tools
  ];
}

