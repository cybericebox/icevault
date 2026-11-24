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
icevault init-vault [--generate]        a new vault at the path the description names; --generate makes a six-word passphrase
icevault init-vault --no-project --vault PATH
                                       a vault without a project, anywhere (no environments)
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

## The master password

A new vault (`init-vault`, or **New vault** in the window) needs a master password of at least 12 characters that a strength estimate ([zxcvbn](https://github.com/trustelem/zxcvbn)) puts at 1e12 guesses or more (about 30 years on one GPU against the vault's Argon2d key derivation; twelve random characters are the shortest password that reaches it), (the estimate is the lower of the password as typed and with its separators, such as space - _ . , removed, so words joined with them count as plain words), so it refuses what is easy to guess: dictionary words (also with digits, case changes and l33t), keyboard walks, repeats, sequences and dates are refused however long the password is, with the reason and a pointer to the generator. A vault that is protected by a key file alone (an empty password and `ICEVAULT_KEYFILE`) stays possible with `init-vault`. The policy applies only when a vault is made: nothing changes in how an existing vault opens.

`icevault init-vault --generate` makes a passphrase of six random words from the [EFF large wordlist](https://www.eff.org/dice) (drawn from the system's random source), shows it once on the terminal and asks for it to be typed back before anything is made. It is never written to a file or a log.

In the window, **New vault** (on the lock screen, beside Open vault) asks for the project folder first (the one with `icevault-project.yaml`), offers the vault file its description names as the place (the system save dialog changes it; the vault still opens with that project), a password with a live strength meter or **Generate**, and the password again. It can also switch on Touch ID for the new vault and save a **recovery kit**: a small text file (mode 0600) with the vault's name and path, the date and the password, to a place you choose with the save dialog. Keep it away from the vault file (another device, paper, a password manager). It is the only time the window writes the password anywhere, and nothing is written until you press Create (the recovery kit only where you choose to save it).

## A vault without a project

A vault normally belongs to a project (the folder with `icevault-project.yaml`: environments, products, the files the deploy scripts read). A vault can also be used **without a project**: it then has no environments, only the shared secrets, the connections and the other secrets, which the window opens and edits. Nothing is written for the project: no `icevault-project.yaml` is made. The vault is marked in its info file next to it (`<vault>.info.json`).

- `icevault init-vault --no-project --vault PATH` makes such a vault anywhere (`--vault PATH` or `ICEVAULT_VAULT` names the file).
- In the window, **New vault** offers **Without a project** beside the project folder; a vault that lies in no project (the lock screen asks for a checkout folder) can be opened with **Open without a project**.
- A command that needs environments (`status`, `view`, `import`, `export`, `export-app`, `env`, `session`, ...) says "this vault has no project" and does nothing. Add a project later and the vault works with it as before.

## Development

`mise run lint`, `mise run test` (throwaway vaults only, no network), `mise run desktop-check` (the window, macOS), `mise run cross`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License 2.0 (see LICENSE and NOTICE).
