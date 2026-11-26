IceVault {{VERSION}}

## Changes since v0.9.0

<!-- The changes of THIS release only, against the release before it. Fill in before the tag; reset to "Changes since <new tag>" after it. -->

- **A connection of a kind the project description does not declare can be deleted** in the window (the usual confirmation) and through the agent API (`connection-delete`, which waits for Apply like other deletes of filled secrets). Editing it stays refused. The API can also read such a connection's fields as the source of `copy-value` and `move-value`, so values can be moved out of it; a move empties the source value.
- **Click a value to copy it.** A click on a value cell copies it and shows a short "copied" note beside it. A secret is copied without being shown: it is read in the program and put on the clipboard there, never drawn in the page. The clipboard is cleared after 30 seconds if it still holds that value. A plain value is copied as it is shown.
- **Own date picker for expiry fields**, in the style of the window: month and day names in the language of the window (uk, en, ru), Monday first, keyboard (arrows, Page Up/Down, Home/End, Enter, Esc), quick month and year switching, **Today** and **Clear**, and presets from today: +30, +60, +90 days and +1 year (29 February gives 28 February).
- **Agent API:** `batch-submit` no longer answers `denied` / `no_window` when the window applied the batch but did not answer for a moment: the waiting client asks again and reports the real outcome (the window keeps the outcome of a finished batch for 30 minutes, also across a lock). A batch dropped because the window locked is reported as `expired` with code `locked`.
- **Agent API:** `move-value` and `copy-value` carry the expiry date of the source field to the target along with the value (a move also clears the date of the source).
- **`icevault agent help`** now asks the window for the operations of the API (it printed the command usage before); `icevault help agent` prints the usage.

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
