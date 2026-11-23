// Command icevault is the command line of the secrets vault (a KeePass KDBX 4 database).
package main

import (
	"os"

	"github.com/cybericebox/icevault/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.DefaultEnv()))
}
