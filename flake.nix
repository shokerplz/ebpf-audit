{
  description = "A Nix-flake-based Rust development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    fenix = {
      url = "https://flakehub.com/f/nix-community/fenix/0.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    fenix,
    nixpkgs,
    ...
  }: let
    supportedSystems = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
    forEachSupportedSystem = f:
      nixpkgs.lib.genAttrs supportedSystems (
        system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [
                self.overlays.default
              ];
            };
          }
      );
  in {
    overlays.default = final: prev: {
      rustToolchain = with fenix.packages.${prev.stdenv.hostPlatform.system};
        combine (
          with complete; [
            clippy
            rustc
            cargo
            rustfmt
            rust-src
          ]
        );
    };

    devShells = forEachSupportedSystem (
      {pkgs}: let
        system = pkgs.stdenv.hostPlatform.system;

        llvm-toolchain = pkgs.llvmPackages_21;
        clang-unwrapped = llvm-toolchain.clang-unwrapped;
        libclang = llvm-toolchain.libclang;

        ecc-bpf = pkgs.ecc.overrideAttrs (oldAttrs: {
          postInstall =
            (oldAttrs.postInstall or "")
            + ''
              wrapProgram $out/bin/ecc-rs \
                --prefix PATH : "${pkgs.lib.makeBinPath [clang-unwrapped]}" \
                --set LIBCLANG_PATH "${libclang.lib}/lib" \
                --set LD_LIBRARY_PATH "${libclang.lib}/lib"
            '';
        });

        debug-libclang = pkgs.writeScriptBin "debug-libclang" ''
          echo "=== libclang.so location ==="
          ls -la ${libclang.lib}/lib/libclang.so* 2>/dev/null || echo "libclang not found"
          echo ""
          echo "=== Environment ==="
          echo "LIBCLANG_PATH: $LIBCLANG_PATH"
          echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
          echo "which clang: $(which clang 2>/dev/null || echo 'not found')"
          echo "which ecc-rs: $(which ecc-rs 2>/dev/null || echo 'not found')"
        '';
      in {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            openssl
            pkg-config
            cargo-deny
            cargo-edit
            cargo-watch
            rust-analyzer
            libllvm
            cargo-generate
            rustup

            clang-unwrapped
            libclang
            libbpf
            bpftools
            linuxHeaders
            bpf-linker
            elfutils
              gdb

            ecc-bpf
            debug-libclang
          ];

          env = {
            RUST_SRC_PATH = "${pkgs.rustToolchain}/lib/rustlib/src/rust/library";
            BPF_SYSROOT = "${pkgs.linuxHeaders}";
            CC = "${clang-unwrapped}/bin/clang";
            CXX = "${clang-unwrapped}/bin/clang++";
            CLANG = "${clang-unwrapped}/bin/clang";
            LIBCLANG_PATH = "${libclang.lib}/lib";
            LIBBPF_PATH = "${pkgs.libbpf}/include";
          };

          # I have no idea how to set LIBs properly
          shellHook = ''
            export PATH="${clang-unwrapped}/bin:$PATH"
            export LD_LIBRARY_PATH="${libclang.lib}/lib:${pkgs.zlib}/lib:/nix/store/k4h3ala5bwydm5lbg961690gppv3qwad-elfutils-0.194/lib/:$LD_LIBRARY_PATH"
            build_ebpf() {
              ${clang-unwrapped}/bin/clang -g -O2 -target bpf -I${pkgs.libbpf}/include -c src-bpf/$1.bpf.c -o build/$1.bpf.o && \
              ${pkgs.bpftools}/bin/bpftool gen skeleton build/$1.bpf.o > build/$1.skel.h && \
              echo "Finished building build/$1.bpf.o + skel file"
            }
            echo "BPF Development Environment"
            echo "To build BPF binary and skel - run build_ebpf prog_name"
            debug-libclang
          '';
        };
      }
    );
  };
}
