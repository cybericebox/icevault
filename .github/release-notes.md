IceVault {{VERSION}}

## Changes since v0.9.6

<!-- The changes of THIS release only, against the release before it. Fill in before the tag; reset to "Changes since <new tag>" after it. -->

- `icevault set` waits for a running session of the environment: while a run holds a session that is written back into the vault, `set` writes nothing and exits 1 (a change under it made the write-back fail). `--base DIR` names the folder of the session directories, as `session run --base`.
- Window: after an agent batch is applied the navigation and the page are redrawn at once (the new values showed only after a manual refresh).
- Commands removed (the window and the agent API do these jobs, or the step is finished): `env create`, `env fill-missing` (an environment is made and filled in in the window or through the agent API), `import` and `purge-plaintext` (the plaintext trees are gone; delete leftovers by hand), `visibility --apply` (`visibility` only lists; the window changes visibility). A script that calls one of them gets "unknown command" (exit 2) or an unknown flag (exit 2).
- `copy --to DIR` is now `copies now DIR`; `copies add|remove|list` are as before.
- `keyfile new PATH` is now `init-vault --new-keyfile PATH`: it makes the key file and the vault that uses it in one step, and removes the key file again when the vault could not be made.
- The refusal of a vault of the layout before the vault model no longer names the `icevault migrate --apply` command, which does not exist.

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
