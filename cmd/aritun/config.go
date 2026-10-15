package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// configFile is the on-disk shape of aritun.yaml. Every field mirrors a CLI
// flag; CLI flags always win when both are set.
type configFile struct {
	Server   string `yaml:"server"`
	Token    string `yaml:"token"`
	Name     string `yaml:"name"`
	CA       string `yaml:"ca"`
	Proxy    string `yaml:"proxy"`
	Insecure bool   `yaml:"insecure"`
	NoTLS    bool   `yaml:"no_tls"`
	Admin    string `yaml:"admin"`

	// Tunnels is used by `aritun start` (or when no subcommand is given) to
	// bring up a whole set from one file.
	Tunnels []tunnelSpec `yaml:"tunnels"`
}

type tunnelSpec struct {
	Type           string   `yaml:"type"` // http | tcp | multi
	Port           int      `yaml:"port"`
	Subdomain      string   `yaml:"subdomain"`
	BasicAuth      string   `yaml:"basic_auth"`
	OAuth          string   `yaml:"oauth"`
	Allow          []string `yaml:"allow"`
	Deny           []string `yaml:"deny"`
	RateLimit      int      `yaml:"rate_limit"`
	BandwidthLimit int64    `yaml:"bandwidth_limit"`
}

// defaultConfigNames are searched, in order, when --config is not given.
var defaultConfigNames = []string{"aritun.yaml", "aritun.yml", ".aritun.yaml"}

// loadConfig reads path, or the first defaultConfigNames entry that exists
// when path is empty. It returns (nil, nil) when no file is found so callers
// can treat "no config" as a normal case.
func loadConfig(path string) (*configFile, error) {
	if path == "" {
		for _, name := range defaultConfigNames {
			if _, err := os.Stat(name); err == nil {
				path = name
				break
			}
		}
		if path == "" {
			return nil, nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg configFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// applyGlobals overlays the config file onto g for any field the user did not
// set on the command line (empty string / false).
func (c *configFile) applyGlobals(g *globals) {
	if g.server == "" {
		g.server = c.Server
	}
	if g.token == "" {
		g.token = c.Token
	}
	if g.name == "" {
		g.name = c.Name
	}
	if g.ca == "" {
		g.ca = c.CA
	}
	if g.proxy == "" {
		g.proxy = c.Proxy
	}
	if !g.insecure && c.Insecure {
		g.insecure = true
	}
	if !g.noTLS && c.NoTLS {
		g.noTLS = true
	}
}

// addConfigFlag registers --config on a FlagSet. Callers pass the returned
// pointer back to loadConfig after parsing.
func addConfigFlag(fs *flag.FlagSet) *string {
	return fs.String("config", envOr("ARITUN_CONFIG", ""),
		"path to aritun.yaml (default: ./aritun.yaml if present)")
}
