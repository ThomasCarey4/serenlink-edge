# nix-shell -> dev env for the public SerenLink edge crates (sl-proto, sl-core).
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    rustc
    cargo
    clippy
    rustfmt
    rust-analyzer
  ];

  env = {
    RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
    RUST_BACKTRACE = "1";
  };
}
