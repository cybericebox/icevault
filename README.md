# IceVault

IceVault keeps every setting and secret of every environment of a project in **one KeePass database** (KDBX 4, opened with a master password and, if you want, a key file; KeePassXC opens the same file with the same credentials). The deploy scripts of the project get what they need from it when they run, use it from a private temporary directory (the session) and remove that directory when they end.

IceVault knows nothing about a particular project. A project describes itself in `icevault-project.yaml` at the root of its checkout: its products, the variables of each, the site kinds it deploys to, the connections they need, the files its scripts read and when, the files it keeps in the vault, the apps that get an env file. The tool only reads that description. `icevault project check` validates it.

## Connection kinds a description declares

A connection is an access to one outside service. IceVault has built-in kinds with their own behaviour (`aws`, `google`, `cloudflare`, `dockerhub`, `hcp`, `s3`, `other`); a description adds kinds of its own with a top-level `connection-kinds:` list, one kind per concrete service, and a product then uses them like a built-in one:

```yaml
format: 3                      # connection-kinds needs format 3 (IceVault 0.8 or newer); an older IceVault refuses the file by its format number
connection-kinds:
  - id: mailer                 # lower case letters, digits, dashes; never a built-in id
    title: {en: Mail relay}      # en is required; uk and ru are optional (a missing language falls back to en)
    help: {en: What the service is for.}
    fields:
      - name: host
        label: {en: Host}                # en, uk, ru
        help: {en: Where the relay listens.}
        type: domain                     # string (default), bool, int, email, url, domain, enum
        required: true
      - {name: api_key, label: {en: API key}, secret: true, required: true}
      - {name: mode, type: enum, choices: [live, test]}
      - {name: signing_key, secret: true, multiline: true}   # a value of several lines
      - {name: sender, type: email, pattern: ".+@example\\.org"}
products:
  - name: portal
    connections:
      - kind: mailer
        optional: true
        variables:
          - {name: MAIL_HOST, field: host}
          - {name: MAIL_KEY, field: api_key, secret: true, required-when: "MAIL_PROVIDER=relay"}
```

- A variable of a connection of a declared kind takes the type, choices and pattern of its field when it names none.
- `file-default: <path pattern>` on a variable of a connection (a relative `path.Match` pattern, no `..`) names a file that a site using the connection may keep instead of a value: while the field is empty and such a file exists, the window shows "a file of this site is used" instead of "not set". Only the name of the file is read, never its content.
- `required-when` on a variable of an optional connection makes the connection needed while the condition holds.
- Every field should explain itself (what it is, what it is used for, where to get it, which permissions a token needs). Built-in kinds carry a general help in en, uk and ru without any project name; a help on a variable of a connection (`connections: variables: help`) is more exact and is shown in preference on the connection page and in the field editor. `icevault project check` lists variables and fields without help as `warnings`.
- A vault opened without the project only has the built-in kinds: connections of any other kind are shown as they are and cannot be edited (they can be deleted, and the agent API can read their values to move or copy them out); they are never dropped otherwise.
- When a description starts to take a variable from a connection while an environment still holds it as its own value, `icevault env adopt-connections --env E` (and the banner on the environment screen of the window) moves it: the raw value goes into a connection of that kind that this environment already uses, else the one the description names, else a new one (a connection of another environment is never filled; a reference stays a reference; a sealed value, or a variable held in several places with different values, stays where it is), the product selects it and the own value is removed. A value the connection already holds differently stays where it is. `--dry-run` prints names only.

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
icevault change-password [--generate] [--refresh-copies]
                                       change the master password of the vault (same policy as init-vault)
icevault init-vault --no-project --vault PATH
                                       a vault without a project, anywhere (no environments)
icevault project check                 validate the project description
icevault project used --env E          which files an environment reads (JSON)
icevault trust [--forget]              trust the description and its required-check script
icevault env create --env E --site KIND --products a,b[=PLACE] | --from-checkout
                                       a new environment: its site, its products and every variable it needs, as empty entries
icevault env fill-missing --env E      add the empty entries an environment lacks (nothing that exists changes)
icevault env adopt-connections --env E [--dry-run]
                                       move values an environment holds as its own into the connection the description now gives them (names only are printed)
icevault import --env E [--dry-run]    read the plaintext tree of an environment into the vault
icevault export --env E --to DIR       write the settings files of an environment
icevault status --env E                what is set, what is missing, what is still on disk
icevault view --env E                  the variables of an environment (names only, never a value)
icevault expiring [--days N]           the values that have expired or expire within N days (default 14): names and dates only
icevault session run --env E -- CMD    run CMD with a private tree of the environment
icevault purge-plaintext --env E       remove the plaintext files the vault holds
icevault copies | copy --to DIR        copies of the vault on other volumes
icevault ui                            the window (macOS)
icevault agent OP [JSON]               ask the unlocked window to read the vault or to apply a batch of changes (see "The agent API"; JSON answer, never a secret value)
icevault help [COMMAND]                every command and flag
```

Environment variables: `ICEVAULT_ROOT` (the checkout; otherwise the nearest folder above the working directory with `icevault-project.yaml`), `ICEVAULT_PROJECT` (another description file), `ICEVAULT_VAULT` (the vault file; `--vault PATH` wins), `ICEVAULT_KEYFILE`, `ICEVAULT_NO_VAULT=1`, `ICEVAULT_NO_TOUCHID=1`.

## The agent API

While the window is **unlocked** it serves a local unix socket (`agent.sock` in the application folder of the user's configuration directory: mode 0600, in a folder of mode 0700 owned by the user; any other mode switches the API off). Locked or closed means no socket and no access; a connection of another user is not answered. `icevault agent OP [JSON]` is the client: it asks no password, unlocks nothing and prints one JSON line (exit 0 done, 1 refused or no window, 2 usage, 3 not applied or timed out). `icevault agent help` lists the operations (`icevault help agent` prints the usage of the command). If the connection is lost while a submitted batch waits (the window saves and reopens the vault when it applies it), the client keeps asking; the window keeps the outcome of a finished batch for 30 minutes, also across a lock, and a batch dropped by a lock is answered as `expired` with code `locked`.

- **Reads** answer at once: `help`, `structure` (environments, sites, products, variables, connections with their fields, shared values, other secrets, files and who uses what: names, states (`filled`), expiry dates and the values of plain places; a secret or sealed value is never in any answer) and `batch-status`.
- **Changes are default-deny batches.** No write op is run when it is sent. `batch-begin {"title":T}` answers an id and a random token (the key to that batch: it is shown nowhere else and never logged; every later call about the batch needs it, a connection of another user is not answered at all); every write op (`var-create`, `var-rename`, `var-delete`, `var-meta`, `set-value`, `copy-value`, `move-value`, `connection-*`, `field-*`, `site-*`, `product-*`, `env-*`, `other-*`) takes `"batch":ID` and `"token":TOKEN` and is checked at once, on a copy of the vault where the items before it are done, and recorded (`batch_required` without a batch). `batch-submit {"id":ID,"token":TOKEN}` sends the batch to the window, which shows it in one dialog: the title, who sent it, every item by names and scopes (never a value), what it changes (old to new), and a short reason for every item that needs a close look (a secret value, a delete, a relink, a copy of an environment with secrets, a name the project binds, ...). **Apply batch** runs the items again, in order, on a fresh copy of the vault (every target is found again and every rule is checked again; an item the rules see differently than when it was shown fails) and only when every item passed makes the copy the content of the vault, in one save. Everything Apply uses is in the dialog: every argument of every item (plain values cleaned and cut with a "…", a reference as written, a secret value only as "a secret value"), who added the items, and a mark on names that start alike or have non-Latin letters. The password change and the reload of the vault wait for Apply, and a copy made before a change of the file or the password is never saved over it. **Reject** (the default focus), the first failing item, the expiry and the lock leave the vault as it is. What is deleted goes to the vault's recycle bin.
- **Rules that stay:** the writes need the window in edit mode (also at Apply); visibility only goes up (a secret is never made plain, a sealed one never lowered); a secret is never copied into a plain place; a plain variable never takes the name of a secret one; a value is never an argument of the command: put `"value_file": "/path"` or `"value_stdin": true` in the JSON.
- **Limits:** at most 50 items in a batch, 4 open batches, one submitted batch waiting at a time, a new submit at most every 10 seconds, a batch is dropped after 10 minutes.
- **Journal:** the batch and every item (time, operation, names, who asked, result; never a value) are shown in the window (the robot button) and kept in `agent-journal.log` next to the socket. The window shows the program that really connected, read from the socket.

```
ID=$(icevault agent batch-begin '{"title":"mail relay"}' | jq -r .data.id)
icevault agent connection-create '{"batch":"'$ID'","name":"Mail relay","kind":"s3"}'
echo -n 'new value' | icevault agent set-value '{"batch":"'$ID'","connection":"Mail relay","field":"password","value_stdin":true}'
icevault agent batch-submit '{"id":"'$ID'"}'   # waits for Apply or Reject in the window
```

## The master password

A new vault (`init-vault`, or **New vault** in the window) needs a master password of at least 12 characters that a strength estimate ([zxcvbn](https://github.com/trustelem/zxcvbn)) puts at 1e12 guesses or more (about 30 years on one GPU against the vault's Argon2d key derivation; twelve random characters are the shortest password that reaches it), (the estimate is the lower of the password as typed and with its separators, such as space - _ . , removed, so words joined with them count as plain words), so it refuses what is easy to guess: dictionary words (also with digits, case changes and l33t), keyboard walks, repeats, sequences and dates are refused however long the password is, with the reason and a pointer to the generator. A vault that is protected by a key file alone (an empty password and `ICEVAULT_KEYFILE`) stays possible with `init-vault`. The policy applies only when a vault is made: nothing changes in how an existing vault opens.

`icevault init-vault --generate` makes a passphrase of six random words from the [EFF large wordlist](https://www.eff.org/dice) (drawn from the system's random source), shows it once on the terminal and asks for it to be typed back before anything is made. It is never written to a file or a log.

In the window, **New vault** (on the lock screen, beside Open vault) asks for the project folder first (the one with `icevault-project.yaml`), offers the vault file its description names as the place (the system save dialog changes it; the vault still opens with that project), a password with a live strength meter or **Generate**, and the password again. It can also switch on Touch ID for the new vault and save a **recovery kit**: a small text file (mode 0600) with the vault's name and path, the date and the password, to a place you choose with the save dialog. Keep it away from the vault file (another device, paper, a password manager). It is the only time the window writes the password anywhere, and nothing is written until you press Create (the recovery kit only where you choose to save it).

### Changing it

`icevault change-password` (or the key button of the unlocked window) asks for the current password (typed: the one behind Touch ID is not taken), then the new one under the same policy, or `--generate`, and re-encrypts the vault file in place with the atomic save (the key derivation settings and the key file stay). A refused password writes nothing. After a change:

- the Touch ID binding holds the old password and is removed; `touchid enable` stores the new one (the window offers it in the same dialog);
- the info file records `password_changed` (a date, never a secret);
- copies made before (`copies add` destinations, `copy --to` outputs) still open with the **old** password: they are listed and never deleted, and `--refresh-copies` (a check box in the window) writes the new file to the standing destinations now. A refresh keeps the copy it replaces as `.prev`, which also still opens with the old password and is listed;
- the vault's own previous copy (`<vault>.prev`) opens with the old password too and is removed; if it cannot be removed, it is listed with the copies;
- **after `--refresh-copies`, `<destination>/<file>.prev` stays**: the refresh keeps the copy it replaces under that name, and it opens with the **old** password. It is listed in the output. Delete it yourself when the old password must stop working everywhere (`rm <destination>/<file>.prev`); nothing deletes a file in a destination for you;
- a Touch ID binding that cannot be removed is reported with its file names (it holds the old password): delete the files or run `icevault touchid disable`;
- the window can save a new recovery kit from the new password.

## A vault without a project

A vault normally belongs to a project (the folder with `icevault-project.yaml`: environments, products, the files the deploy scripts read). A vault can also be used **without a project**: it then has no environments, only the shared secrets, the connections and the other secrets, which the window opens and edits. Nothing is written for the project: no `icevault-project.yaml` is made. The vault is marked in its info file next to it (`<vault>.info.json`).

- `icevault init-vault --no-project --vault PATH` makes such a vault anywhere (`--vault PATH` or `ICEVAULT_VAULT` names the file).
- In the window, **New vault** offers **Without a project** beside the project folder; a vault that lies in no project (the lock screen asks for a checkout folder) can be opened with **Open without a project**.
- A command that needs environments (`status`, `view`, `import`, `export`, `env`, `session`, ...) says "this vault has no project" and does nothing. Add a project later and the vault works with it as before.

## Development

`mise run lint`, `mise run test` (throwaway vaults only, no network), `mise run desktop-check` (the window, macOS), `mise run cross`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License 2.0 (see LICENSE and NOTICE).
