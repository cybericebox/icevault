IceVault {{VERSION}}

## From 0.5

- **A new vault needs a strong master password.** `init-vault` and the window refuse a password shorter than 12 characters or one a strength estimate (zxcvbn) puts under a trillion (1e12) guesses: dictionary words, keyboard walks, repeats, dates, patterns such as `Qwerty123!`. Against the vault's key derivation (Argon2d, 64 MiB) that is about 30 years on one GPU; twelve random characters are the shortest password that reaches it. Separators (space, dash, dot and the like) between words add nothing to the estimate. A password longer than 256 characters is refused too. Only a new vault is checked: an existing vault opens as before, whatever its password. A vault with a key file and no password is still allowed.
- **`icevault init-vault --generate`** makes the password for you: six random words from the EFF large wordlist (about 77 bits), shown once on the terminal and typed back to confirm you recorded it.
- **New vault… in the window**, next to Open vault…: choose the project folder (the vault goes where its description says, and opens with that project; Change place… saves it elsewhere), type a password (with a strength meter) or press Generate, type it once more, then optionally turn on Touch ID and save a **recovery kit**: a small text file (mode 0600) with the vault name, path, date and password. Keep the recovery kit away from the vault file: another device, paper, or your password manager. A new vault joins the list of recent vaults at its first unlock.

Coming from 0.4: read the notes of 0.5.0 first (project description format 2, renamed variables, `migrate` gone).

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
