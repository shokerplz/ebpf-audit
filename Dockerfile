FROM nixos/nix:latest

RUN mkdir -p ~/.config/nix && echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

RUN git config --global --add safe.directory /app

WORKDIR /app

COPY flake.nix flake.lock ./

RUN mkdir -p src-bpf && touch src-bpf/vmlinux.h

RUN nix develop --command echo "Dependencies installed"

RUN rm src-bpf/vmlinux.h

COPY . .

ENTRYPOINT ["nix", "develop", "--command"]

CMD ["bash"]
