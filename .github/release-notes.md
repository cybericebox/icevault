IceVault {{VERSION}}

## Changes since v0.9.5

<!-- The changes of THIS release only, against the release before it. Fill in before the tag; reset to "Changes since <new tag>" after it. -->

- New command `icevault set --env E [--scope SCOPE] [--dry-run] KEY=VALUE ...`: changes plain values of the vault directly from the command line, without the window (unlock and write lock as for `session`). It sets a key that lives in one scope, creates a missing key where the project description places it, and prints `SCOPE KEY: OLD -> NEW` per key. A secret, a system-managed or generated variable, a value with a reference and a value that breaks its type are refused; all keys are checked first, so one refusal writes nothing.

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
