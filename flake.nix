{
  description = "Isolated VM environments for running Claude Code and Codex";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      # Match the native release targets: Lima needs Apple Silicon on macOS.
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          coop = rustPlatform.buildRustPackage {
            pname = "coop";
            inherit (manifest.workspace.package) version;
            src = pkgs.lib.cleanSource self;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--workspace" ];
            cargoTestFlags = [ "--workspace" ];
            strictDeps = true;

            nativeBuildInputs = [ pkgs.cmake ];
            nativeCheckInputs = [
              pkgs.gitMinimal
              pkgs.openssh
            ];
            # CMake builds aws-lc-sys through Cargo, not the top-level project.
            dontUseCmakeConfigure = true;

            # The SSH and TLS unit tests bind loopback listeners.
            __darwinAllowLocalNetworking = true;
            # APFS rejects the invalid UTF-8 name before this test can exercise
            # coop's path validation. Keep the test enabled on Linux.
            checkFlags = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
              "--skip=commands::lifecycle::tests::check_reprovision_workspace_source_rejects_a_non_utf8_workspace_dir"
            ];

            # Nix owns upgrades of these immutable binaries. Keep the existing
            # dev-build guard against `coop update` and its background notifier.
            COOP_FORCE_BUILD_KIND = "dev";

            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              "$out/bin/coop" --version
              test -x "$out/bin/coop-proxy"
              runHook postInstallCheck
            '';

            meta = {
              inherit (manifest.package) description;
              homepage = manifest.workspace.package.repository;
              license = pkgs.lib.licenses.asl20;
              mainProgram = "coop";
              platforms = systems;
            };
          };
        in
        {
          inherit coop;
          shell = pkgs.mkShell {
            packages = [
              toolchain
              pkgs.cmake
              pkgs.gitMinimal
              pkgs.openssh
              pkgs.python3
            ];
          };
          formatter = pkgs.nixfmt;
        }
      );
    in
    {
      packages = forAllSystems (system: {
        default = perSystem.${system}.coop;
        coop = perSystem.${system}.coop;
      });
      checks = forAllSystems (system: {
        coop = perSystem.${system}.coop;
      });
      devShells = forAllSystems (system: {
        default = perSystem.${system}.shell;
      });
      formatter = forAllSystems (system: perSystem.${system}.formatter);
    };
}
