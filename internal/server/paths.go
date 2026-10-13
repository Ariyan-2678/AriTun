package server

import (
	"os"
	"path/filepath"
	"runtime"
)

// defaultDataDir picks a writable location for AriTun's generated certificate
// and token. An explicit --data-dir always overrides this platform fallback.
func defaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		// ProgramData is machine-wide and writable by a service account.
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "AriTun")
		}
		return filepath.Join(os.TempDir(), "aritun")
	case "darwin":
		return "/usr/local/var/aritun"
	default:
		return "/var/lib/aritun"
	}
}
