{
  description = "SerenLink edge: wire protocol, edge engine and the Linux agent";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAll (pkgs: rec {
        sl-agent = pkgs.rustPlatform.buildRustPackage {
          pname = "sl-agent";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "sl-agent" ];
          cargoTestFlags = [ "-p" "sl-agent" ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          meta.mainProgram = "sl-agent";
        };
        default = sl-agent;
      });
    };
}
