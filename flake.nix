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

            clang-unwrapped
            libclang
            libbpf
            bpftools
            linuxHeaders
            bpf-linker
            elfutils
            gdb
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

          shellHook = ''
            export PATH="${clang-unwrapped}/bin:$PATH"
            export LD_LIBRARY_PATH="${libclang.lib}/lib:${pkgs.zlib}/lib:${pkgs.elfutils.out}/lib/:$LD_LIBRARY_PATH"
            build_ebpf() {
              ${clang-unwrapped}/bin/clang -g -O2 -target bpf -I${pkgs.libbpf}/include -c src-bpf/$1.bpf.c -o build/$1.bpf.o && \
              ${pkgs.bpftools}/bin/bpftool gen skeleton build/$1.bpf.o > build/$1.skel.h && \
              echo "Finished building build/$1.bpf.o + skel file"
            }
            if [ ! -f src-bpf/vmlinux.h ]; then
              ${pkgs.bpftools}/bin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > src-bpf/vmlinux.h
            fi
          '';
        };
      }
    );
  };
}
