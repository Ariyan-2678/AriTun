package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// cmdPauseResume implements `aritun pause <id>` and `aritun resume <id>` by
// POSTing to the admin API. Pause is server-side: the client's registration
// stays alive, the tunnel just answers 503 until resumed.
func cmdPauseResume(args []string, action string) error {
	var g globals
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	admin := fs.String("admin", envOr("ARITUN_ADMIN", ""),
		"admin base URL; default: derived from --server (port 9090)")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if err := g.loadConfig(); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aritun %s <tunnel-id>  (see aritun status for ids)", action)
	}
	id := fs.Arg(0)

	base := *admin
	if base == "" {
		derived, err := adminURLFromServer(g.server)
		if err != nil {
			return fmt.Errorf("cannot derive the admin URL: %w (pass --admin explicitly)", err)
		}
		base = derived
	}
	base = strings.TrimRight(base, "/")

	httpc := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, base+"/api/tunnels/"+id+"/"+action, nil)
	if err != nil {
		return err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Printf("tunnel %s %sd\n", id, action)
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("tunnel %q not found (see `aritun status`)", id)
	default:
		return fmt.Errorf("server replied %s", resp.Status)
	}
}
