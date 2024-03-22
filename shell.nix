{ nixpkgs ? fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-23.11"
, pkgs ? import nixpkgs { config = { }; overlays = [ ]; }
, targetSystem ? builtins.currentSystem
, system ? builtins.currentSystem # local system
}:
let
  crossPkgs =
    if targetSystem != system then
      import nixpkgs
        {
          localSystem = system;
          crossSystem = { config = targetSystem; };
        }
    else pkgs;
in

# mkShellNoCC creates a shell without also grabbing a compiler toolchain
pkgs.mkShellNoCC {
  packages = [ crossPkgs.pkgsBuildHost.protobuf ];
}
