//go:build !darwin

package cli

// touchIDPlatform: Touch ID unlock is not available here; the commands say so and the password is asked every time.
const touchIDPlatform = false
