package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestFlags builds a FlagSet with a representative subset of aritund flags
// so each test can observe overlay behavior without the full set.
func newTestFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("aritundtest", flag.ContinueOnError)
	fs.String("domain", "", "")
	fs.String("token", "", "")
	fs.String("token-file", "", "")
	fs.String("control-addr", ":9443", "")
	fs.Bool("control-tls", true, "")
	fs.String("tcp-range", "20000-20999", "")
	fs.Duration("token-ttl", 0, "")
	fs.Bool("v", false, "")
	return fs
}

func TestApplyFillsUnsetFlags(t *testing.T) {
	fs := newTestFlags()
	tlsOff := false
	verbose := false
	cfg := &serverConfigFile{
		Domain:     "aritun.example.com",
		TokenFile:  "/etc/aritun/token",
		ControlTLS: &tlsOff,
		TCPRange:   "21000-21999",
		TokenTTL:   "720h",
		Verbose:    &verbose,
	}
	if err := cfg.apply(fs); err != nil {
		t.Fatalf("apply: %v", err)
	}

	checks := []struct{ name, want string }{
		{"domain", "aritun.example.com"},
		{"token-file", "/etc/aritun/token"},
		{"control-tls", "false"},
		{"tcp-range", "21000-21999"},
		{"token-ttl", "720h0m0s"},
		{"v", "false"},
	}
	for _, c := range checks {
		f := fs.Lookup(c.name)
		if f == nil {
			t.Fatalf("missing flag %q", c.name)
		}
		if got := f.Value.String(); got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestApplyKeepsCLISetFlags(t *testing.T) {
	fs := newTestFlags()
	if err := fs.Parse([]string{"--domain", "from-cli.example", "--control-tls=false"}); err != nil {
		t.Fatal(err)
	}
	tlsOn := true
	cfg := &serverConfigFile{Domain: "from-file.example", ControlTLS: &tlsOn}
	if err := cfg.apply(fs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := fs.Lookup("domain").Value.String(); got != "from-cli.example" {
		t.Errorf("domain = %q, want the CLI value", got)
	}
	if got := fs.Lookup("control-tls").Value.String(); got != "false" {
		t.Errorf("control-tls = %q, want the CLI value false", got)
	}
}

func TestApplyTokenSkipsNonEmptyFlagValue(t *testing.T) {
	// ARITUN_TOKEN is merged into the flag default, so a token present in the
	// flag (even without an explicit CLI flag) must not be overwritten.
	fs := newTestFlags()
	if err := fs.Set("token", "from-env"); err != nil {
		t.Fatal(err)
	}
	cfg := &serverConfigFile{Token: "from-config"}
	if err := cfg.apply(fs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := fs.Lookup("token").Value.String(); got != "from-env" {
		t.Errorf("token = %q, want the flag value preserved", got)
	}

	fs2 := newTestFlags()
	if err := fs2.Parse([]string{"--token", "from-cli"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.apply(fs2); err != nil {
		t.Fatal(err)
	}
	if got := fs2.Lookup("token").Value.String(); got != "from-cli" {
		t.Errorf("token = %q, want the CLI token preserved", got)
	}

	// With nothing set anywhere, the config file token is applied.
	fs3 := newTestFlags()
	if err := cfg.apply(fs3); err != nil {
		t.Fatal(err)
	}
	if got := fs3.Lookup("token").Value.String(); got != "from-config" {
		t.Errorf("token = %q, want the config value applied", got)
	}
}

func TestLoadServerConfigExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aritund.yaml")
	content := "domain: explicit.example\ncontrol_tls: false\ntoken_ttl: 720h\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := newTestFlags()
	applied, err := loadServerConfigAndApply(path, fs)
	if err != nil {
		t.Fatalf("loadServerConfigAndApply: %v", err)
	}
	if applied != path {
		t.Errorf("applied path = %q, want %q", applied, path)
	}
	if got2 := fs.Lookup("domain").Value.String(); got2 != "explicit.example" {
		t.Errorf("domain = %q, want explicit.example", got2)
	}
	if got2 := fs.Lookup("control-tls").Value.String(); got2 != "false" {
		t.Errorf("control-tls = %q, want false", got2)
	}
}

func TestLoadServerConfigExplicitMissing(t *testing.T) {
	_, err := loadServerConfigAndApply(filepath.Join(os.TempDir(), "aritund-no-such.yaml"), newTestFlags())
	const winMsg = "cannot find the file specified"
	const posixMsg = "no such file"
	if err == nil || (!strings.Contains(err.Error(), winMsg) && !strings.Contains(err.Error(), posixMsg)) {
		t.Errorf("error = %v, want a file-not-found style error", err)
	}
}

func TestLoadServerConfigRejectsUnknownKeys(t *testing.T) {
	// A misspelled key must fail the boot rather than silently do nothing —
	// otherwise the server would run on defaults while the operator believes
	// the config took effect.
	dir := t.TempDir()
	path := filepath.Join(dir, "aritund.yaml")
	if err := os.WriteFile(path, []byte("donmain: oops.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadServerConfigAndApply(path, newTestFlags())
	if err == nil || !strings.Contains(err.Error(), "donmain") {
		t.Errorf("error = %v, want an unknown-field error naming the bad key", err)
	}

	path2 := filepath.Join(dir, "aritund2.yaml")
	if err := os.WriteFile(path2, []byte("domain: fine.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs2 := newTestFlags()
	if _, err := loadServerConfigAndApply(path2, fs2); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if got := fs2.Lookup("domain").Value.String(); got != "fine.example" {
		t.Errorf("domain = %q, want fine.example", got)
	}
}

func TestLoadServerConfigEmptyFile(t *testing.T) {
	// An empty (or comment-only) config file is valid and applies nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "aritund.yaml")
	if err := os.WriteFile(path, []byte("# nothing yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err := loadServerConfigAndApply(path, newTestFlags())
	if err != nil {
		t.Fatalf("empty config rejected: %v", err)
	}
	if applied != path {
		t.Errorf("applied = %q, want %q", applied, path)
	}
}

func TestLoadServerConfigNoFile(t *testing.T) {
	// Nonexistent CWD-relative defaults plus an unlikely tempdir make the
	// search fall through to "no config".
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	fs := newTestFlags()
	applied, err := loadServerConfigAndApply("", fs)
	if err != nil {
		t.Fatalf("loadServerConfigAndApply: %v", err)
	}
	if applied != "" {
		t.Errorf("applied = %q, want empty", applied)
	}
}
