{ pkgs ? import <nixpkgs> {}}: with pkgs;

mkShell {
    buildInputs = [ nodejs ];
    shellHook = ''
        export NODE_PATH=$PWD/node_modules:$NODE_PATH
    '';
}