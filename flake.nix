{
  description = "Flake for argo pr generator";

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        pkgsCross = pkgs.pkgsCross;
        dev-shell-path = ./shell.nix;
      in
      {
        devShells = {
          default = pkgs.callPackage dev-shell-path { };
          aarch64-unknown-linux-musl = pkgsCross.aarch64-multiplatform-musl.callPackage dev-shell-path { };
        };
      });
}
