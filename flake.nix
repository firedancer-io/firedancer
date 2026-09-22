{
  description = "Hermetic Firedancer client build environments";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnsupportedSystem = true;
          };

          # These are deliberately separate package sets.  The first is used for
          # build-time tools; the second supplies the target compiler and libc.
          x86Musl = pkgs.pkgsCross.musl64;
          arm64Musl = pkgs.pkgsCross.aarch64-multiplatform-musl;
          riscv64Musl = pkgs.pkgsCross."riscv64-musl";

          commonTools = with pkgs; [
            gnumake git python3
            clang lld llvm
          ];

          mkShell = { target, triple, machine, extras ? "static lld" }:
            let
              fdMake = pkgs.writeShellScriptBin "fd-make" ''
                exec make MACHINE="${machine}" EXTRAS="${extras}" \
                  CC="${target.stdenv.cc}/bin/${target.stdenv.cc.targetPrefix}gcc" \
                  LD="${target.stdenv.cc}/bin/${target.stdenv.cc.targetPrefix}gcc" \
                  HOSTCC="${pkgs.stdenv.cc}/bin/cc" \
                  AR="${target.stdenv.cc.bintools}/bin/${target.stdenv.cc.targetPrefix}ar" \
                  RANLIB="${target.stdenv.cc.bintools}/bin/${target.stdenv.cc.targetPrefix}ranlib" \
                  "$@"
              '';
              fdBuild = pkgs.writeShellScriptBin "fd-build" ''
                exec fd-make -j"$(${pkgs.coreutils}/bin/nproc)" bin "$@"
              '';
              fdBuildAll = pkgs.writeShellScriptBin "fd-build-all" ''
                exec fd-make -j"$(${pkgs.coreutils}/bin/nproc)" all "$@"
              '';
            in pkgs.mkShell {
              packages = commonTools ++ [
                target.stdenv.cc target.stdenv.cc.bintools
                fdMake fdBuild fdBuildAll
              ];

              # Keep this shell usable from any checkout path.  The Make build
              # still owns its object directory and dependency graph.
              MAKEFLAGS = "--no-builtin-rules --no-builtin-variables";
              SOURCE_DATE_EPOCH = "1";
              FD_REPRODUCIBLE_BUILD = "1";
              NIX_HARDENING_ENABLE = "";
              LC_ALL = "C";
              TZ = "UTC";

              shellHook = ''
                export FD_NIX_TARGET="${triple}"
                export FD_NIX_MACHINE="${machine}"
                export FD_NIX_EXTRAS="${extras}"
                export NIX_CFLAGS_COMPILE="-ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fmacro-prefix-map=$PWD=."

                echo "Firedancer hermetic target: $FD_NIX_TARGET"
                echo "Use fd-build, fd-build-all, or fd-make <goal>"
              '';
            };

          x86Shell = mkShell {
            target = x86Musl;
            triple = "x86_64-linux-musl";
            machine = "linux_gcc_x86_64";
          };

          arm64Shell = mkShell {
            target = arm64Musl;
            triple = "aarch64-linux-musl";
            machine = "linux_gcc_neoverse_n2";
          };

          riscv64Shell = mkShell {
            target = riscv64Musl;
            triple = "riscv64-linux-musl";
            machine = "linux_gcc_riscv";
          };
        in {
          x86_64-linux-musl = x86Shell;
          aarch64-linux-musl = arm64Shell;
          riscv64-linux-musl = riscv64Shell;

          default =
            if system == "aarch64-linux" then arm64Shell
            else if system == "riscv64-linux" then riscv64Shell
            else x86Shell;
        });

    };
}
