# IceVault

IceVault keeps every setting and secret of every environment of a project in **one KeePass database** (KDBX 4, opened with a master password and, if you want, a key file; KeePassXC opens the same file with the same credentials). The deploy scripts of the project get what they need from it when they run, use it from a private temporary directory (the session) and remove that directory when they end.

IceVault knows nothing about a particular project. A project describes itself in `icevault-project.yaml` at the root of its checkout: its products, the variables of each, the site kinds it deploys to, the connections they need, the files its scripts read and when, the files it keeps in the vault, the apps that get an env file. The tool only reads that description. `icevault project check` validates it.

A description may name a script that `status` runs to report required values still to fill. It runs only after `icevault trust` has recorded the SHA-256 of the description and of the script for your user, and it runs again only while neither file has changed. The record covers that one script: it runs alone, from a private copy, with `sh`, `bash` or `python3 -I` and no shell; a file it sources or runs is not covered, so read the script before you trust it.

## Install

With [mise](https://mise.jdx.dev):

```
mise use github:cybericebox/icevault
```

Or download a release: `IceVault-vX.Y.Z-macos.dmg` (the window with the command inside), `.pkg`, or the `icevault` command for macOS and Linux, with `SHA256SUMS`. To build from source: `mise install && mise run install` builds `bin/icevault` and, on macOS, `bin/IceVault.app`.

## Commands

```
icevault init-vault                    a new vault at the path the description names
icevault project check                 validate the project description
icevault project used --env E          which files an environment reads (JSON)
icevault trust [--forget]              trust the description and its required-check script
icevault env create --env E --site KIND --products a,b[=PLACE] | --from-checkout
                                       a new environment: its site, its products and every variable it needs, as empty entries
icevault env fill-missing --env E      add the empty entries an environment lacks (nothing that exists changes)
icevault import --env E [--dry-run]    read the plaintext tree of an environment into the vault
icevault export --env E --to DIR       write the settings files of an environment
icevault export-app --env E --app A    write the env file of an app into <dir>/.env (the app's dir: of the description,
                                       relative to the checkout; ../<name> without one; --to DIR names another)
icevault status --env E                what is set, what is missing, what is still on disk
icevault view --env E                  the variables of an environment (names only, never a value)
icevault session run --env E -- CMD    run CMD with a private tree of the environment
icevault purge-plaintext --env E       remove the plaintext files the vault holds
icevault copies | copy --to DIR        copies of the vault on other volumes
icevault ui                            the window (macOS)
icevault help [COMMAND]                every command and flag
```

Environment variables: `ICEVAULT_ROOT` (the checkout; otherwise the nearest folder above the working directory with `icevault-project.yaml`), `ICEVAULT_PROJECT` (another description file), `ICEVAULT_VAULT` (the vault file; `--vault PATH` wins), `ICEVAULT_KEYFILE`, `ICEVAULT_NO_VAULT=1`, `ICEVAULT_NO_TOUCHID=1`.

## Development

`mise run lint`, `mise run test` (throwaway vaults only, no network), `mise run desktop-check` (the window, macOS), `mise run cross`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License 2.0 (see LICENSE and NOTICE).
