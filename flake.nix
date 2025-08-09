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
        # Create Python wrapper for python dependencies
        myPython = pkgs.python313.withPackages (python-pkgs: [
          python-pkgs.bcc
        ]);
        theProtectorWrapper = pkgs.writeShellScriptBin "theprotector.sh" ''
          # Contain nix-packaged dependencies in $PATH
          PATH="${pkgs.bpftrace}/bin:${pkgs.coreutils}/bin:${pkgs.inotify-tools}/bin:${pkgs.jq}/bin:${pkgs.netcat-gnu}/bin:${myPython}/bin:${pkgs.yara}/bin:$PATH"
          ${self}/theprotector.sh "$@"
        '';
        theProtectorPkg = stdenv.mkDerivation {
          name = "theProtector";
          builder = pkgs.bash;
          meta.mainProgram = "theprotector.sh";
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
