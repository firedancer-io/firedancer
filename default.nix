{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/de408167ede9c2cab0a7831f4079ff9ba8c644d8.tar.gz";
    sha256 = "sha256:05xf26nd4ryyrx9xn3rzpzawf14r1pw8r0ljba0as852w63z4rh9";
  }) {},
  compiler ? "gcc"
}:

let stdenv = if compiler == "gcc" then pkgs.gcc9Stdenv
        else if compiler == "clang" then pkgs.clang15Stdenv
        else throw "unsupported compiler ${compiler}";
in

stdenv.mkDerivation rec {
  pname = "firedancer";
  version = "0.0.1";
  src = ./.;

  buildInputs = [
    pkgs.libbpf
    pkgs.pkg-config
    pkgs.quictls
  ];

  buildPhase = ''
    export SHELL=${pkgs.bash}
    make -j MACHINE=linux_${compiler}_x86_64
  '';
  installPhase = ''
    mkdir -p $out/bin $out/include
    cp -rv ./build/linux/${compiler}/x86_64/bin/* $out/bin
    cp -rv ./build/linux/${compiler}/x86_64/include/* $out/include
  '';
}
