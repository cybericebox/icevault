//go:build windows

package cli

// execWindow: there is no window on Windows.
func execWindow(string, []string, []string) error {
	return fail("the settings window is not available on Windows")
}
