{
  description = "theProtector flake";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        stdenv = pkgs.stdenv;
        theProtectorWrapper = pkgs.writeShellScriptBin "theprotector.sh" ''
          # Contain nix-packaged dependencies in $PATH
          PATH="${pkgs.bpftrace}/bin:${pkgs.coreutils}/bin:${pkgs.inotify-tools}/bin:${pkgs.jq}/bin:${pkgs.netcat-gnu}/bin:${pkgs.python313}/bin:${pkgs.yara}/bin:$PATH"
          ${self}/theprotector.sh "$@"
        '';
        theProtectorPkg = stdenv.mkDerivation {
          name = "theProtector";
          builder = pkgs.bash;
          args = [ "-c" "${pkgs.coreutils}/bin/mkdir -p $out/bin && ${pkgs.coreutils}/bin/cp ${theProtectorWrapper}/bin/theprotector.sh $out/bin/theprotector.sh" ];
        };
      in
      {
        packages = rec {
          default = theprotector;
          theprotector = theProtectorPkg;
        };
        devShell = pkgs.mkShell {
          name = "default";
          buildInputs = with pkgs; [
            theProtectorPkg
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
