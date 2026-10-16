package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// serverConfigFile is the on-disk shape of aritund.yaml. Every field mirrors a
// CLI flag of the same name. Command-line flags always win when both are set.
type serverConfigFile struct {
	Domain       string `yaml:"domain"`
	Token        string `yaml:"token"`
	TokenFile    string `yaml:"token_file"`
	ControlAddr  string `yaml:"control_addr"`
	ControlTLS   *bool  `yaml:"control_tls"`
	ControlCert  string `yaml:"control_cert"`
	ControlKey   string `yaml:"control_key"`
	ControlHosts string `yaml:"control_hosts"`
	HTTPAddr     string `yaml:"http_addr"`
	AdminAddr    string `yaml:"admin_addr"`
	TCPRange     string `yaml:"tcp_range"`
	DataDir      string `yaml:"data_dir"`
	TokensFile   string `yaml:"tokens_file"`
	TokenTTL     string `yaml:"token_ttl"` // e.g. "720h" or "0"
	AuditLog     string `yaml:"audit_log"`
	OAuthBase    string `yaml:"oauth_base"`
	Verbose      *bool  `yaml:"verbose"`
}

// defaultServerConfigPaths are searched, in order, when --config is not given
// and ARITUN_CONFIG is unset. The filesystem-style path only exists concept
// per OS; relative names are checked in the working directory on every OS.
func defaultServerConfigPaths() []string {
	paths := []string{}
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			paths = append(paths, filepath.Join(pd, "AriTun", "aritund.yaml"))
		}
	default:
		paths = append(paths, "/etc/aritun/aritund.yaml")
	}
	return append(paths, "aritund.yaml", "aritund.yml")
}

// loadServerConfig reads the config at path. An explicit path must exist and
// be readable; an empty path falls back to the first default that exists and
// returns a nil config when none does (the normal case).
func loadServerConfig(path string) (*serverConfigFile, string, error) {
	if path == "" {
		for _, cand := range defaultServerConfigPaths() {
			if _, err := os.Stat(cand); err == nil {
				path = cand
				break
			}
		}
		if path == "" {
			return nil, "", nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, path, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg serverConfigFile
	// Strict decoding: an unknown or misspelled key must fail the boot instead
	// of silently leaving the matching flag at its default.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && err != io.EOF {
		return nil, path, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, path, nil
}

// apply overlays the config file onto fs for every flag the user did not set
// on the command line. Flag wins over file; file wins over built-in defaults.
// The only exception is token, whose default comes from ARITUN_TOKEN: the
// config value is applied there only when no token came from anywhere else.
func (cfg *serverConfigFile) apply(fs *flag.FlagSet) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	strOverrides := []struct{ name, value string }{
		{"domain", cfg.Domain},
		{"token-file", cfg.TokenFile},
		{"control-addr", cfg.ControlAddr},
		{"control-cert", cfg.ControlCert},
		{"control-key", cfg.ControlKey},
		{"control-hosts", cfg.ControlHosts},
		{"http-addr", cfg.HTTPAddr},
		{"admin-addr", cfg.AdminAddr},
		{"tcp-range", cfg.TCPRange},
		{"data-dir", cfg.DataDir},
		{"tokens-file", cfg.TokensFile},
		{"token-ttl", cfg.TokenTTL},
		{"audit-log", cfg.AuditLog},
		{"oauth-base", cfg.OAuthBase},
	}
	for _, ov := range strOverrides {
		if err := applyFlagIfUnset(fs, set, ov.name, ov.value); err != nil {
			return fmt.Errorf("config: %v", err)
		}
	}

	if cfg.ControlTLS != nil && !set["control-tls"] {
		if err := fs.Lookup("control-tls").Value.Set(fmt.Sprintf("%v", *cfg.ControlTLS)); err != nil {
			return fmt.Errorf("config: control_tls: %v", err)
		}
	}
	if cfg.Verbose != nil && !set["v"] {
		if err := fs.Lookup("v").Value.Set(fmt.Sprintf("%v", *cfg.Verbose)); err != nil {
			return fmt.Errorf("config: verbose: %v", err)
		}
	}

	// Fill an empty token only, so ARITUN_TOKEN (merged into the flag default)
	// keeps priority over the file.
	if cfg.Token != "" && !set["token"] {
		if f := fs.Lookup("token"); f != nil && f.Value.String() == "" {
			if err := f.Value.Set(cfg.Token); err != nil {
				return fmt.Errorf("config: token: %v", err)
			}
		}
	}
	return nil
}

// loadServerConfigAndApply resolves the config path, reads it (nil means "no
// file found") and overlays it onto fs. Returns the applied path for logging.
func loadServerConfigAndApply(path string, fs *flag.FlagSet) (string, error) {
	cfg, resolved, err := loadServerConfig(path)
	if err != nil {
		return resolved, err
	}
	if cfg == nil {
		return "", nil
	}
	if err := cfg.apply(fs); err != nil {
		return resolved, err
	}
	return resolved, nil
}

// applyFlagIfUnset sets named flag to value when the user did not pass the
// flag and the value differs from the current one. Values are written through
// flag.Value, which handles strings, bools and durations uniformly.
func applyFlagIfUnset(fs *flag.FlagSet, set map[string]bool, name, value string) error {
	if value == "" || set[name] {
		return nil
	}
	f := fs.Lookup(name)
	if f == nil {
		return fmt.Errorf("unknown flag %q", name)
	}
	return f.Value.Set(value)
}
