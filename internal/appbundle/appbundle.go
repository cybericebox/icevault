// Package appbundle makes the macOS application bundle of the settings window: Contents/MacOS/<binary>, Contents/MacOS/icevault (the command line of the same
// build, which the window can link into a PATH directory), Contents/Info.plist and Contents/Resources/<icon>.icns.
// It does not sign (the build task runs codesign) and it does not draw the icon (the build task makes it from cmd/icevault-desktop/app/icon-1024.png with sips and iconutil).
package appbundle

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The product name: the application is called IceVault.
const (
	Name       = "IceVault"
	Identifier = "com.cybericebox.icevault"
	Category   = "public.app-category.utilities"
	// CLIName is the command line program inside the bundle, next to the window program.
	CLIName = "icevault"
	// VaultExtension is the file type IceVault offers to open (Open With in Finder). The rank is Alternate: KeePassXC (or whatever the owner chose)
	// stays the default application of .kdbx files; IceVault refuses a file that is not one of its vaults after the unlock.
	VaultExtension = "kdbx"
	VaultTypeName  = "KeePass vault (KDBX)"
	VaultRank      = "Alternate"
)

// Info is what Info.plist says about the application.
type Info struct {
	Name          string // CFBundleName and CFBundleDisplayName: Dock, menu bar, Finder, the app menu items
	Identifier    string
	Executable    string // the file in Contents/MacOS
	IconFile      string // the file in Contents/Resources, with its extension
	ShortVersion  string // CFBundleShortVersionString: digits and dots
	Build         string // CFBundleVersion: digits and dots
	SourceVersion string // the exact source version (git describe), kept in IceVaultSourceVersion
	MinSystem     string // LSMinimumSystemVersion
}

var numeric = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,2})(?:-|$)`)

// Versions turns the output of `git describe --tags --always --dirty` into the two numbers macOS wants: the leading dotted number of a tag ("v1.2.3-4-gabc"
// gives 1.2.3; a bare commit hash gives 0.0.0), and the exact text for IceVaultSourceVersion.
func Versions(describe string) (short, source string) {
	describe = strings.TrimSpace(describe)
	if m := numeric.FindStringSubmatch(describe); m != nil {
		return m[1], describe
	}
	return "0.0.0", describe
}

// Validate refuses an Info that would make a bundle macOS does not open.
func (i Info) Validate() error {
	for name, v := range map[string]string{"name": i.Name, "identifier": i.Identifier, "executable": i.Executable, "icon file": i.IconFile, "minimum system": i.MinSystem} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("the %s of the bundle is empty", name)
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(i.Identifier) {
		return fmt.Errorf("%q is not a bundle identifier", i.Identifier)
	}
	if filepath.Base(i.Executable) != i.Executable || filepath.Base(i.IconFile) != i.IconFile {
		return errors.New("the executable and the icon are file names, not paths")
	}
	dotted := regexp.MustCompile(`^\d+(\.\d+)*$`)
	for name, v := range map[string]string{"short version": i.ShortVersion, "build": i.Build, "minimum system": i.MinSystem} {
		if !dotted.MatchString(v) {
			return fmt.Errorf("the %s %q is not a dotted number", name, v)
		}
	}
	return nil
}

// Plist is Info.plist (XML), keys in a fixed order so that two builds of one source are the same bytes.
func (i Info) Plist() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n")
	str := func(k, v string) {
		fmt.Fprintf(&b, "\t<key>%s</key>\n\t<string>%s</string>\n", k, html.EscapeString(v))
	}
	str("CFBundleDevelopmentRegion", "en")
	str("CFBundleDisplayName", i.Name)
	// the documents IceVault can open: the window gets them through the open-file event of Wails (mac.Options.OnFileOpen)
	b.WriteString("\t<key>CFBundleDocumentTypes</key>\n\t<array>\n\t\t<dict>\n")
	fmt.Fprintf(&b, "\t\t\t<key>CFBundleTypeExtensions</key>\n\t\t\t<array>\n\t\t\t\t<string>%s</string>\n\t\t\t</array>\n", VaultExtension)
	fmt.Fprintf(&b, "\t\t\t<key>CFBundleTypeName</key>\n\t\t\t<string>%s</string>\n", html.EscapeString(VaultTypeName))
	b.WriteString("\t\t\t<key>CFBundleTypeRole</key>\n\t\t\t<string>Editor</string>\n")
	fmt.Fprintf(&b, "\t\t\t<key>LSHandlerRank</key>\n\t\t\t<string>%s</string>\n", VaultRank)
	b.WriteString("\t\t</dict>\n\t</array>\n")
	str("CFBundleExecutable", i.Executable)
	str("CFBundleIconFile", i.IconFile)
	str("CFBundleIdentifier", i.Identifier)
	str("CFBundleInfoDictionaryVersion", "6.0")
	str("CFBundleName", i.Name)
	str("CFBundlePackageType", "APPL")
	str("CFBundleShortVersionString", i.ShortVersion)
	str("CFBundleVersion", i.Build)
	str("IceVaultSourceVersion", i.SourceVersion)
	str("LSApplicationCategoryType", Category)
	str("LSMinimumSystemVersion", i.MinSystem)
	str("NSPrincipalClass", "NSApplication")
	b.WriteString("\t<key>NSHighResolutionCapable</key>\n\t<true/>\n</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// Assemble makes <outDir>/<Name>.app from the window binary, the command line binary (Contents/MacOS/icevault), the icon (.icns) and the Info; a bundle of that name already there is replaced. It returns the bundle path.
func Assemble(outDir string, info Info, binary, cli, icns string) (string, error) {
	plist, err := info.Plist()
	if err != nil {
		return "", err
	}
	app := filepath.Join(outDir, info.Name+".app")
	if st, err := os.Lstat(app); err == nil {
		if !st.IsDir() {
			return "", fmt.Errorf("%s is not a bundle: not replaced", app)
		}
		if err := os.RemoveAll(app); err != nil {
			return "", err
		}
	}
	macos, res := filepath.Join(app, "Contents", "MacOS"), filepath.Join(app, "Contents", "Resources")
	for _, d := range []string{macos, res} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	if err := copyFile(binary, filepath.Join(macos, info.Executable), 0o755); err != nil {
		return "", err
	}
	if err := copyFile(cli, filepath.Join(macos, CLIName), 0o755); err != nil {
		return "", err
	}
	if err := copyFile(icns, filepath.Join(res, info.IconFile), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), plist, 0o644); err != nil { // #nosec G306 -- a bundle's plist is world-readable
		return "", err
	}
	return app, nil
}

func copyFile(from, to string, mode os.FileMode) error {
	in, err := os.Open(from) // #nosec G304 -- the build task names the files
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
