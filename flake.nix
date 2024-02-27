{
  description = "Flake for argo pr generator";

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };

      in
      {
        devShells = {
          # default = with pkgs; mkShellNoCC { packages = [ protobuf ]; };
          default = import ./shell.nix { inherit pkgs; };
        };
      });
}
