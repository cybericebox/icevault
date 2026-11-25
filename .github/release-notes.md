IceVault {{VERSION}}

## Changes since v0.8.4

<!-- The changes of THIS release only, against the release before it. Fill in before the tag; reset to "Changes since <new tag>" after it. -->

- **Agent API.** While the window is unlocked it serves a local socket (mode 0600, in the user's own configuration folder; gone when the window locks or closes) that `icevault agent OP [JSON]` talks to: programs of the user can read the structure of the vault (names, states, plain values, never a secret value) and create, rename and delete variables, connections, fields, sites, products and environments, set labels, expiry and visibility (only upwards), and move or copy a value inside the vault. Deleted things go to the recycle bin.
- The API's writes need the window in edit mode. Every write into a secret place, a move out of a secret, a copy of an environment that holds secrets the delete of a filled secret, of an environment, site, product or used connection, a relink of a site or product, and every "are you sure" of the core wait for the window (the agent's own confirm is ignored): a confirmation shows what, where and who asked (**Deny** has the focus), and the client gets pending, then allowed, denied or expired. The value comes from a file or the standard input of the client, never an argument, and is never echoed or logged.
- **Removed** (they had no user left): the subcommands `export-app`, `export --batches` (with its `--product` and `--all`), `guard env-of-private`, `session open` and `session close`. `session run` and `recover` stay and work as before. The window no longer carries the leftovers of the gone `migrate` command (its plan panel, banner and texts); the messages that sent the reader to `icevault migrate` now point to `icevault project check`.
- A **Journal** panel in the window (the robot button) lists every API action (time, operation, names, who asked, result; no values); the same lines are kept in `agent-journal.log` in the configuration folder.

## What is here

- `IceVault-{{VERSION}}-macos.dmg`: **the recommended way on macOS**. Open it and drag IceVault to Applications. One application for Apple silicon and Intel (the settings window, with the `icevault` command inside it).
- `IceVault-{{VERSION}}-macos.pkg`: the same application as an installer, which also links `/usr/local/bin/icevault` to the command inside it.
- `icevault-{{VERSION}}-darwin-arm64.tar.gz`, `icevault-{{VERSION}}-darwin-amd64.tar.gz`, `icevault-{{VERSION}}-linux-amd64.tar.gz`: the `icevault` command alone.
- `SHA256SUMS`: check the downloads with `shasum -a 256 -c SHA256SUMS` (`sha256sum -c SHA256SUMS` on Linux).

There is no Windows build and no Linux window.

## Installing on macOS

Neither the disk image, the installer nor the application has a **Developer ID signature**, and nothing is notarised (the application is signed ad hoc), so macOS says once that it cannot check the download for malicious software.

**The disk image (.dmg, recommended).**

1. Open it and drag `IceVault` onto `Applications` (a copy there is replaced). Eject the disk image.
2. Start IceVault from Applications. The first time macOS refuses: open **System Settings > Privacy & Security** and press **Open Anyway** (or right-click `IceVault.app`, choose **Open**, then **Open** again). Or, in a terminal: `xattr -dr com.apple.quarantine /Applications/IceVault.app`.

**The installer (.pkg).** Double-click it; when macOS refuses to open it, press **Open Anyway** the same way. The installer asks for an administrator's password, installs `IceVault.app` into /Applications (a copy there is replaced) and links `/usr/local/bin/icevault` to the command inside it. A file at that place that is not a link, or a link to a program that is not an IceVault, is left as it is (the installer log says so; the terminal button in the window installs the command then). An application installed this way opens without a further question.

The terminal button in the window installs the `icevault` command into your PATH. The command alone (the tar.gz files) is not an application and Gatekeeper does not ask about files downloaded with a command-line tool; from a browser, remove the quarantine flag the same way (`xattr -d com.apple.quarantine icevault`).

## The command in a project, pinned with mise

```toml
[tools]
"github:cybericebox/icevault" = "{{VERSION_NUMBER}}"
```

`mise install` downloads `icevault-{{VERSION}}-<os>-<arch>.tar.gz` of this release. `icevault ui` opens the window of the application installed in /Applications (or ~/Applications).

`icevault --version` prints `icevault {{VERSION}}`.
