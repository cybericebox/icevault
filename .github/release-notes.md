IceVault {{VERSION}}

## From 0.4

IceVault no longer knows anything about a particular project: everything project-specific comes from the project description, `icevault-project.yaml` at the root of the checkout (`icevault project check` validates it).

- The description is in **format 2**: it declares the checkout layout (templates, committed settings, plaintext trees, the vault file), the conditions under which each file is read (`used-when`, `partly-used`), the files kept in the vault (`kept-files`, guards), the files left out, the session, the apps, `required-when` of a variable and `serve-as` of a vault connection. A format 1 description is refused: set `format: 2` and add what `icevault project check` reports.
- The vault format stays 1. A vault still in the layout before the vault model (IceVault 0.2) is refused: move it with IceVault 0.4 first (`icevault migrate --apply`), then open it with this version. `migrate` itself is gone.
- The environment variables are renamed: `ICEVAULT_ROOT`, `ICEVAULT_PROJECT`, `ICEVAULT_VAULT`, `ICEVAULT_KEYFILE`, `ICEVAULT_NO_VAULT`, `ICEVAULT_NO_TOUCHID`, `ICEVAULT_TOUCHID_DIR`, `ICEVAULT_ERROR_FILE`, `ICEVAULT_CONFIG_DIR`. The variables of a session take the names the description gives (`session.variables`).
- The list of vaults of the window keeps the checkout of each vault under the key `checkout`: choose the folder of a vault once more after the update. The window's own choices (language, theme, widths) start from the defaults once.
- The info file next to the vault records the guarded files per guard word (`guards`); the first unlock after the update writes it.
- The required-check of a description is a script inside the checkout run with `sh`, `bash` or `python3 -I`, without a shell, and only after `icevault trust` has recorded the SHA-256 of the description and of the script for your user.

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
