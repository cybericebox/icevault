package appbundle

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func goodInfo() Info {
	return Info{Name: Name, Identifier: Identifier, Executable: "icevault-desktop", IconFile: "icon.icns", ShortVersion: "1.2.3", Build: "45", SourceVersion: "v1.2.3-4-gabc", MinSystem: "12.0"}
}

// plistValues reads the flat <dict> of a plist into key -> value ("true" for <true/>).
func plistValues(t *testing.T, data []byte) map[string]string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	got := map[string]string{}
	var key, elem string
	inDict := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the plist is not XML: %v", err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			elem = x.Name.Local
			if elem == "dict" {
				inDict = true
			}
			if inDict && elem == "true" {
				got[key] = "true"
			}
		case xml.EndElement:
			elem = ""
		case xml.CharData:
			if !inDict {
				continue
			}
			switch elem {
			case "key":
				key = string(x)
			case "string":
				got[key] = string(x)
			}
		}
	}
	return got
}

func TestPlistSaysWhatMacOSNeeds(t *testing.T) {
	data, err := goodInfo().Plist()
	if err != nil {
		t.Fatal(err)
	}
	got := plistValues(t, data)
	want := map[string]string{
		"CFBundleName": "IceVault", "CFBundleDisplayName": "IceVault", "CFBundleIdentifier": "com.cybericebox.icevault",
		"CFBundleExecutable": "icevault-desktop", "CFBundleIconFile": "icon.icns", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.2.3",
		"CFBundleVersion": "45", "IceVaultSourceVersion": "v1.2.3-4-gabc", "LSMinimumSystemVersion": "12.0", "NSHighResolutionCapable": "true",
		"LSApplicationCategoryType": "public.app-category.utilities", "NSPrincipalClass": "NSApplication",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	data2, _ := goodInfo().Plist()
	if string(data) != string(data2) {
		t.Error("the plist is not deterministic")
	}
}

func TestPlistIsEscapedAndValidated(t *testing.T) {
	i := goodInfo()
	i.SourceVersion = "v1-dirty <&> \"x\""
	data, err := i.Plist()
	if err != nil {
		t.Fatal(err)
	}
	if got := plistValues(t, data)["IceVaultSourceVersion"]; got != i.SourceVersion {
		t.Errorf("escaped value read back as %q", got)
	}
	for name, mut := range map[string]func(*Info){
		"empty name":      func(i *Info) { i.Name = "" },
		"bad identifier":  func(i *Info) { i.Identifier = "com cyber/box" },
		"path executable": func(i *Info) { i.Executable = "../x" },
		"bad version":     func(i *Info) { i.ShortVersion = "v1" },
		"bad build":       func(i *Info) { i.Build = "" },
		"bad min system":  func(i *Info) { i.MinSystem = "twelve" },
	} {
		bad := goodInfo()
		mut(&bad)
		if _, err := bad.Plist(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestVersionsFromGitDescribe(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3-4-gabc1234": "1.2.3", "1.4": "1.4", "v2-dirty": "2", "e336f50": "0.0.0", "": "0.0.0", "e336f50-dirty": "0.0.0"} {
		if short, src := Versions(in); short != want || src != strings.TrimSpace(in) {
			t.Errorf("Versions(%q) = %q, %q; want %q", in, short, src, want)
		}
	}
	// a hash that starts with digits is not a version: only a tag form is (v?N[.N[.N]] followed by - or the end)
	if short, _ := Versions("4b25288"); short != "0.0.0" {
		t.Errorf("a commit hash read as the version %q", short)
	}
}

func TestAssembleMakesTheBundleAndReplacesAnOldOne(t *testing.T) {
	dir := t.TempDir()
	bin, icon := filepath.Join(dir, "prog"), filepath.Join(dir, "i.icns")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(icon, []byte("icns"), 0o644); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "cli")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\necho cli\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	for range 2 { // the second run replaces the bundle of the first
		app, err := Assemble(out, goodInfo(), bin, cli, icon)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(app) != "IceVault.app" {
			t.Fatalf("bundle %s", app)
		}
		st, err := os.Stat(filepath.Join(app, "Contents", "MacOS", "icevault-desktop"))
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("the executable: %v %v", st, err)
		}
		if st, err := os.Stat(filepath.Join(app, "Contents", "MacOS", "icevault")); err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("the command line program: %v %v", st, err)
		}
		for _, f := range []string{"Contents/Info.plist", "Contents/Resources/icon.icns"} {
			if _, err := os.Stat(filepath.Join(app, f)); err != nil {
				t.Errorf("%s: %v", f, err)
			}
		}
		if runtime.GOOS == "darwin" {
			if p, err := exec.LookPath("plutil"); err == nil {
				if o, err := exec.Command(p, "-lint", filepath.Join(app, "Contents", "Info.plist")).CombinedOutput(); err != nil { // #nosec G204
					t.Errorf("plutil -lint: %v %s", err, o)
				}
			}
		}
	}
	// a plain file of that name is not a bundle and is not replaced
	file := filepath.Join(dir, "o2")
	_ = os.MkdirAll(file, 0o755)
	if err := os.WriteFile(filepath.Join(file, "IceVault.app"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(file, goodInfo(), bin, cli, icon); err == nil {
		t.Error("a plain file was replaced")
	}
	if _, err := Assemble(out, goodInfo(), filepath.Join(dir, "missing"), cli, icon); err == nil {
		t.Error("a missing binary was accepted")
	}
	if _, err := Assemble(out, goodInfo(), bin, filepath.Join(dir, "missing-cli"), icon); err == nil {
		t.Error("a missing command line program was accepted")
	}
}

// Open With: .kdbx is a document type IceVault can open, as an alternate handler (KeePassXC stays the default), in the shape macOS reads.
func TestPlistDeclaresTheVaultDocumentType(t *testing.T) {
	data, err := goodInfo().Plist()
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	i := strings.Index(s, "<key>CFBundleDocumentTypes</key>")
	if i < 0 {
		t.Fatal("no CFBundleDocumentTypes")
	}
	block := s[i:]
	block = block[:strings.Index(block, "\n\t</array>\n")+len("\n\t</array>\n")]
	if !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(block, "<key>CFBundleDocumentTypes</key>")), "<array>\n\t\t<dict>") {
		t.Fatalf("not an array of dicts:\n%s", block)
	}
	got := plistValues(t, data) // the flat reading finds the keys of the dict inside the array too
	want := map[string]string{"CFBundleTypeExtensions": "kdbx", "CFBundleTypeRole": "Editor", "LSHandlerRank": "Alternate", "CFBundleTypeName": "KeePass vault (KDBX)"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if strings.Contains(block, "LSItemContentTypes") {
		t.Error("LSItemContentTypes would make macOS ignore the extension (KeePassXC declares no type of its own)")
	}
	if runtime.GOOS != "darwin" {
		return
	}
	p := filepath.Join(t.TempDir(), "Info.plist")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("plutil", "-extract", "CFBundleDocumentTypes", "json", "-o", "-", p).Output()
	if err != nil {
		t.Fatalf("plutil: %v", err)
	}
	var types []map[string]any
	if err := json.Unmarshal(out, &types); err != nil || len(types) != 1 {
		t.Fatalf("plutil reads %s", out)
	}
	ext, _ := types[0]["CFBundleTypeExtensions"].([]any)
	if len(ext) != 1 || ext[0] != "kdbx" || types[0]["LSHandlerRank"] != "Alternate" || types[0]["CFBundleTypeRole"] != "Editor" {
		t.Fatalf("plutil reads %s", out)
	}
}
