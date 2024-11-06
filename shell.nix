{ mkShellNoCC, protobuf, bacon }:

# mkShellNoCC creates a shell without also grabbing a compiler toolchain
mkShellNoCC {
  packages = [ protobuf bacon ];
}
