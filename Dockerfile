FROM nixos/nix:latest

RUN mkdir -p ~/.config/nix && echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

RUN git config --global --add safe.directory /app

WORKDIR /app

COPY flake.nix flake.lock ./

RUN nix develop --command echo "Dependencies installed"

COPY . .

ENTRYPOINT ["nix", "develop", "--command"]

CMD ["bash"]
