IceVault {{VERSION}}

## Changes since v0.8.4

<!-- The changes of THIS release only, against the release before it. Fill in before the tag; reset to "Changes since <new tag>" after it. -->

- **Agent API.** While the window is unlocked it serves a local socket (mode 0600, in the user's own configuration folder, mode 0700; gone when the window locks or closes; another user's connection is not answered) that `icevault agent OP [JSON]` talks to. Programs of the user can read the structure of the vault (names, states, plain values, never a secret value). They change it only through **batches**: `batch-begin`, write ops that take `"batch":ID` (each checked at once on a copy of the vault), `batch-submit`. The window shows the whole batch in one dialog (every item by names, what it changes, and why it needs a close look); **Apply batch** runs the items again on a fresh copy and saves the vault in one write only if every item passed, **Reject** (the default) and any failure leave it as it is. Writes need edit mode; visibility only goes up; a secret is never copied into a plain place; a value comes from a file or the standard input of the client, never an argument, and is never echoed or logged.
- A **Journal** panel in the window (the robot button) lists every API action (the batch and each item: time, operation, names, who asked, result; no values); the same lines are kept in `agent-journal.log` in the configuration folder.
- **Removed** (they had no user left): the subcommands `export-app`, `export --batches` (with its `--product` and `--all`), `guard env-of-private`, `session open` and `session close`. `session run` and `recover` stay and work as before. The window no longer carries the leftovers of the gone `migrate` command (its plan panel, banner and texts); the messages that sent the reader to `icevault migrate` now point to `icevault project check`.

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
