//go:build windows

package agentapi

import "errors"

var errUnsupported = errors.New("the agent API is not available on this system")

// CheckDir: the ownership and mode of a folder cannot be checked here, so the API is not offered.
func CheckDir(string) error { return errUnsupported }

func checkSocketFile(string) error { return errUnsupported }

// MakeDir is not available here.
func MakeDir(string) error { return errUnsupported }

// CheckSocketFile is not available here.
func CheckSocketFile(string) error { return errUnsupported }
