//go:build desktop && !darwin

package main

// setDockIcon does nothing outside macOS: the window of another system takes its icon from the system's own means.
func setDockIcon() {}
