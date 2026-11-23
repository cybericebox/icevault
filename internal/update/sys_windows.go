package update

import "errors"

// The application is updated on macOS only; elsewhere the updater has no bundle and stays Unavailable.
func relaunch(int, string) error { return errors.New("not supported") }

func writable(string) bool { return false }
