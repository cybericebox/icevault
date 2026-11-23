// Command mkapp assembles the macOS application bundle of the settings window (internal/appbundle). The build task (mise-tasks/desktop-app) runs it between
// making the icon and signing the bundle. It needs no cgo and no macOS tool.
//
//	mkapp --out bin --binary /tmp/icevault-desktop --cli bin/icevault --icon icon.icns --describe "$(git describe --tags --always --dirty)" --build 123 --min-os 12.0
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cybericebox/icevault/internal/appbundle"
)

func main() {
	out := flag.String("out", "bin", "the folder that receives the bundle")
	binary := flag.String("binary", "", "the window program (it ends up inside the bundle only)")
	cli := flag.String("cli", "bin/icevault", "the command line program of the same build")
	icns := flag.String("icon", "", "the .icns file")
	describe := flag.String("describe", "", "git describe of the source")
	build := flag.String("build", "1", "the build number (digits and dots)")
	minOS := flag.String("min-os", "11.0", "LSMinimumSystemVersion")
	flag.Parse()
	short, source := appbundle.Versions(*describe)
	info := appbundle.Info{Name: appbundle.Name, Identifier: appbundle.Identifier, Executable: "icevault-desktop", IconFile: "icon.icns",
		ShortVersion: short, Build: *build, SourceVersion: source, MinSystem: *minOS}
	app, err := appbundle.Assemble(*out, info, *binary, *cli, *icns)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkapp:", err)
		os.Exit(1)
	}
	fmt.Println(app)
}
