IceVault {{VERSION}}

## From 0.6

- **References inside an environment**: `${{ self.KEY }}` uses another variable of the same environment (and site), e.g. `SUPPORT_EMAIL = ${{ self.SUPER_ADMIN_EMAIL }}`. `${{ shared.KEY }}` and connection references now work on the environment screen too. Every value field has **Insert reference** (or type `${{`) with a live preview; secret results are never shown. A broken reference is listed in "Missing for deploy" and stops an export with the variable's name. `self` is a reserved name.
- **Value types and choices**: the project description may give a variable a `type` (string, bool, int, email, url, domain, enum), `choices`, `pattern` and `min`/`max`. The window shows a drop-down for an enum, a switch for a bool and checks the others beside the field; `status`, `export`, `export-app` and `session` refuse a value that does not fit (the variable is named, never the value). A description that uses these keys needs IceVault 0.7 or later.
- **"Missing for deploy" follows required-when** and the place of each product (a product on a cluster needs its cluster settings); things shared by the environment are counted once.
- **The environment screen**: collapsible sections and cards, add buttons at the top right, a sticky header, aligned tables with a full frame, a green "ready" state, values set by the system hidden behind **Show set automatically (N)**, secret values typed into masked fields, a service-account key read from a file (one line, up to 64 KiB), field errors beside their field, un-importing a shared value that others use asks first.
- **The window**: the open vault's file name in the sidebar; a new vault shows in Recent at once, marked "not opened yet"; the lock screen and the New vault dialog keep their size; leaving an unsaved recovery kit asks first.

## From 0.5 (in 0.6.x)

- **Change the master password**: `icevault change-password [--generate] [--refresh-copies]` or the key button of an unlocked window. The current password is typed (Touch ID is not accepted for it); the new one follows the same rules as a new vault. The file is rewritten atomically; `<vault>.prev` (which opens with the old password) is removed, the Touch ID binding of the old password is removed (turn Touch ID on again), and every copy that still opens with the old password is listed (`--refresh-copies` rewrites the standing copies; a `.prev` next to a refreshed copy keeps the old password: delete it).
- **New icon**: the Cyber ICE Box crest as the body of a padlock.
- **A vault can be used without a project.** `icevault init-vault --no-project --vault PATH`, **Without a project** in the window's New vault, and **Open without a project** for a vault that lies in no project. Such a vault has no environments, only shared secrets, connections and other secrets; no project file is written. Commands that need environments say so.
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
