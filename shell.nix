{ nixpkgs ? fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-23.11"
, pkgs ? import nixpkgs { config = { }; overlays = [ ]; }
, targetSystem ? builtins.currentSystem
}:
let
  crossPkgs =
    if targetSystem != builtins.currentSystem then
      import nixpkgs
        {
          localSystem = builtins.currentSystem;
          crossSystem = { config = targetSystem; };
        }
    else pkgs;
in

# mkShellNoCC creates a shell without also grabbing a compiler toolchain
pkgs.mkShellNoCC {
  packages = [ crossPkgs.pkgsBuildHost.protobuf ];
}
