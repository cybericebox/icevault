package cli

import (
	"os"

	"golang.org/x/term"
)

// askTerminal reads a line without echo from the terminal. Without a terminal it stops with NeedsOwner.
func askTerminal(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errExit{NeedsOwner}
	}
	_, _ = os.Stderr.WriteString(prompt)
	pw, err := term.ReadPassword(fd)
	_, _ = os.Stderr.WriteString("\n")
	if err != nil {
		return nil, errExit{"the password could not be read: " + err.Error()}
	}
	return pw, nil
}
