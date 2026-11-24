//go:build windows

package desktop

// noFollow: Windows has no such flag (the window is a macOS program; this keeps the package building).
const noFollow = 0
