{ mkShell, protobuf, bacon }:

# mkShellNoCC creates a shell without also grabbing a compiler toolchain
# mkShellNoCC {
# We actually need a normal shell sadly (because MacOS clang seems to break this)
mkShell {
  packages = [ protobuf bacon ];
}
