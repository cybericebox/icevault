# Contributing

Read [README.md](README.md) first. Everything in this repository is English, except the message tables of the window.

## Work

- Branch from `develop`; `develop` is where finished work lands. Commit messages say what changed and why.
- Before a commit: `mise run lint`, then `mise run test`; for the window `mise run desktop-check` (macOS, cgo) and `mise run desktop-app`; `mise run cross` must stay green (the command line has no cgo); `mise run leaks` and `mise run lint-workflows` after a change of history-relevant files or workflows. The `check` workflow runs lint, test, cross, workflow lint and the leak scan on Linux for every pull request and every push to `develop`.
- The tests and the demo use the made-up example project of `internal/example`; a new feature of the project description is added to its description, with a test that uses it.
- Tests use throwaway vaults only, never a real one.

## The browser test harness of the window

`mise run ui-harness` serves the window's page (index.html, messages.json, adapter.js: the very files the window embeds, with the same
Content-Security-Policy) on `127.0.0.1` and stands in for the Wails bridge with a small script (`cmd/icevault-desktop/harnessjs/harness.js`):
every call of `window.go.desktop.App` goes over HTTP to the real `internal/desktop` App, and the program's events (`vault-changed`,
`vault-locked`, `vault-selected`) come back as server-sent events. It is the same program as the window built with `-tags harness` instead of
`desktop` (`cmd/icevault-desktop/harness.go`): no cgo, no webview, and never in a release (the release builds use `desktop,production`).

```
mise run ui-harness                                  # the demo vaults of the example project (temp files), password demo
mise run ui-harness -- --mode file                   # a throwaway file vault in a temp folder, a random password
mise run ui-harness -- --addr 127.0.0.1:8765 --idle 30s --quit-after 30m
```

It prints the address to open (with a one-time key that the first load turns into a cookie; any other request, or another Host name, is
refused) and the password. Only `127.0.0.1` is bound. The clipboard is in memory (a copy never reaches the system clipboard). The vaults and
their folder are deleted when the harness ends (Ctrl+C, `--quit-after`, or the page's Close / fifth wrong password, which end the program as the
window does). The page keeps its choices (language, theme, widths) in the browser's storage of its origin: with the default free port every
start is a new origin; `--addr 127.0.0.1:PORT` with a fixed port keeps them between runs.

The demo is the made-up example project of `internal/example` (a checkout with its description, samples and plaintext trees), written into a
temp folder that is removed at the end; `ICEVAULT_ROOT` and the configuration folder point there, so the harness never touches the real list
of vaults or a checkout. Outside changes are tested with the real command on the file vault while the page is open: `ICEVAULT_VAULT=<the
printed file>`, `ICEVAULT_ROOT=<that temp checkout>`, and the password typed when it is asked for (never as an argument).

## Releases

A release is made by a maintainer pushing a tag `vX.Y.Z` (final releases only: there are no release candidates here). Nothing else starts it, and nothing is released by hand: no hand-made release page, no assets uploaded from a machine.

`.github/release-notes.md` has one section of changes, **"Changes since <previous tag>"**: only what changed against the release just before (a patch against the previous patch, a minor against the last release before it), never a history of older versions. Before the tag, write that section; right after the release, reset it to "Changes since <the new tag>" with no items. Steps a reader must take when coming from an older version go into the release that needs them, once.

```
git tag vX.Y.Z      # on the commit to release
git push origin vX.Y.Z
```

The `release` workflow (`.github/workflows/release.yml`) then, with the same mise tasks as a local build and no credential but its own `GITHUB_TOKEN`:

1. builds on a macOS runner the application for arm64 and amd64 (cross-built) and joins the two into one universal `IceVault.app` (lipo, signed ad hoc), then packs `IceVault-vX.Y.Z-macos.dmg` (the recommended download: open, drag to Applications), `IceVault-vX.Y.Z-macos.pkg` (the same application as an installer: into /Applications and the link `/usr/local/bin/icevault` to the command inside it, made by `internal/appbundle/pkg/postinstall` with the rules of `internal/cliinstall`; not signed) and `icevault-vX.Y.Z-darwin-<arch>.tar.gz` for arm64 and amd64 (mise downloads these); on Linux `icevault-vX.Y.Z-linux-amd64.tar.gz`. `mise run release-assets-macos` (with `VERSION=vX.Y.Z`) makes the same files in `dist/` on a Mac; check a package with `pkgutil --payload-files` and `pkgutil --expand` (never install a test package on a working machine);
2. writes `SHA256SUMS`;
3. creates a **draft** release (`.github/release-notes.md`), uploads every asset to it, then publishes it: its assets and tag are immutable once published (its notes stay editable). It is marked as the latest release only when it is the newest final version (`relprune -newest`): a patch of an older minor never takes that place from a newer minor;
4. applies the retention policy below.

The tag is the version: it goes into both programs (`icevault --version`, `icevault-desktop --version`) and into the Info.plist of the application. There is no Windows build and no Linux window. Neither the installer nor the application is signed with a Developer ID, and nothing is notarised; the release text says how to open them (Gatekeeper asks once). If a step before the publish fails, the draft is removed and the tag can be fixed and pushed again only as a new version (a published or attempted tag name is not reused; delete a failed tag only after checking that no release uses it).

### Retention

The rule for the release pages and their assets:

- the git tags of final releases are kept forever, so any version can be rebuilt from source;
- a release candidate (`-rc.N`): tag, page and assets are deleted right after the final release is published (none are made here; the tool still handles them);
- the current (newest) minor keeps all its patch releases;
- an older minor keeps only its latest patch, and only for the 10 previous minors; an older minor drops out of that window: its release page and assets are deleted, the tag stays;
- pruning runs automatically at the end of the release workflow (`cmd/relprune`, the rule is `internal/retention` with its tests): first the release pages, then the tags of release candidates whose final exists (`relprune -rc-tags`); manual cleanup is only for the moment the policy was introduced.

## Security

- Actions are pinned by commit SHA with the version in a comment; a job has only the permission it needs (`contents: write` only in the job that publishes), and the token is given only to the steps that call `gh`, not to the tool installation or a build.
- Tools are pinned with their download URL and checksum in `mise.lock` for linux-x64, macos-arm64 and macos-x64; CI installs with `MISE_LOCKED=1`, so a tool missing from the lock or an asset changed upstream fails the run. After a version change in `mise.toml`: `mise lock -p linux-x64,macos-arm64,macos-x64`.
- A secret value never goes into a command argument, a log line, a test failure message or a commit. `mise run leaks` scans the whole history; a false positive is listed with its fingerprint and a reason in `.gitleaksignore`, never silenced by a broad rule.
