{
  description = "gsts: AWS STS credentials via Google Workspace";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs";
    npmlock2nixSrc = {
      url = "github:nix-community/npmlock2nix";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, npmlock2nixSrc, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        npmlock2nix = import npmlock2nixSrc { inherit pkgs; lib = pkgs.lib; };

      in rec {
        packages.gsts = npmlock2nix.v2.build {
          src = ./.;
          installPhase = ''
            mkdir -p $out/bin
            cp -r * $out
            ln -sf $out/index.js $out/bin/gsts
          '';

          node_modules_attrs = {
            PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = 1;
          };

          buildCommands = [];
        };

        defaultPackage = self.packages.${system}.gsts;

        overlays = final: prev: {
          inherit (packages) gsts;
        };

        devShell = pkgs.mkShell {

          CHROMIUM_PATH = "${pkgs.chromium}/bin/chromium";

          buildInputs = [
            defaultPackage
            pkgs.chromium
            pkgs.cowsay
          ];
        };
      }
    );
}
