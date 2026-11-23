//go:build darwin

package cli

// touchIDPlatform: macOS has the Secure Enclave. The tools age and age-plugin-se are looked for at run time.
const touchIDPlatform = true
