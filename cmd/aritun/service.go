package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// cmdInstallService implements `aritun install-service`: it registers a
// long-running `aritun` invocation with the OS so tunnels survive reboots.
//
//   - Linux/macOS: a systemd *user* unit at ~/.config/systemd/user/aritun.service
//   - Windows: a Scheduled Task via schtasks.exe that runs at logon
//
// It deliberately avoids external dependencies (no winsw, no root required on
// Linux) so `npm i -g aritun-client` users get a working service with zero
// extra downloads.
func cmdInstallService(args []string) error {
	var g globals
	fs := flag.NewFlagSet("install-service", flag.ContinueOnError)
	serviceArgs := fs.String("args", "",
		"the aritun arguments to run forever, e.g. `http 3000 --subdomain demo`")
	uninstall := fs.Bool("uninstall", false, "remove the service instead of installing it")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if err := g.loadConfig(); err != nil {
		return err
	}

	if strings.TrimSpace(*serviceArgs) == "" {
		return fmt.Errorf("--args is required, e.g. --args \"http 3000\"")
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the aritun binary: %w", err)
	}

	if *uninstall {
		return removeService()
	}
	return installService(exe, *serviceArgs, g)
}

func installService(exe, serviceArgs string, g globals) error {
	switch runtime.GOOS {
	case "windows":
		return installWindowsService(exe, serviceArgs, g)
	default:
		return installSystemdService(exe, serviceArgs, g)
	}
}

func removeService() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("schtasks", "/Delete", "/TN", "AriTun", "/F")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("schtasks delete: %w", err)
		}
		fmt.Println("AriTun scheduled task removed")
		return nil
	default:
		return removeSystemdService()
	}
}

// ---- systemd (Linux / macOS with systemd) ----

func installSystemdService(exe, serviceArgs string, g globals) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	unitPath := filepath.Join(dir, "aritun.service")

	var envLines []string
	if g.server != "" {
		envLines = append(envLines, "Environment=ARITUN_SERVER="+g.server)
	}
	if g.token != "" {
		envLines = append(envLines, "Environment=ARITUN_TOKEN="+g.token)
	}
	if g.ca != "" {
		envLines = append(envLines, "Environment=ARITUN_CA="+g.ca)
	}
	if g.proxy != "" {
		envLines = append(envLines, "Environment=ARITUN_PROXY="+g.proxy)
	}

	unit := `[Unit]
Description=AriTun tunnel
After=network-online.target

[Service]
ExecStart=` + exe + ` ` + serviceArgs + `
Restart=on-failure
RestartSec=5
` + strings.Join(envLines, "\n") + `

[Install]
WantedBy=default.target
`
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", unitPath)
	fmt.Println("enable it with:")
	fmt.Println("  systemctl --user daemon-reload")
	fmt.Println("  systemctl --user enable --now aritun")
	fmt.Println("  loginctl enable-linger $USER   # keep it running after logout")
	return nil
}

func removeSystemdService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", "aritun.service")
	_ = exec.Command("systemctl", "--user", "disable", "--now", "aritun").Run()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	fmt.Println("AriTun systemd unit removed")
	return nil
}

// ---- Windows Scheduled Task ----

func installWindowsService(exe, serviceArgs string, g globals) error {
	// schtasks needs a single command line; quote the executable path.
	cmdLine := `"` + exe + `" ` + serviceArgs

	// Environment is baked in via setx-free wrapper: write a small .cmd that
	// exports the vars then execs aritun, and point the task at that.
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	wrapper := filepath.Join(home, "AriTun-service.cmd")

	var b strings.Builder
	b.WriteString("@echo off\r\n")
	if g.server != "" {
		b.WriteString("set ARITUN_SERVER=" + g.server + "\r\n")
	}
	if g.token != "" {
		b.WriteString("set ARITUN_TOKEN=" + g.token + "\r\n")
	}
	if g.ca != "" {
		b.WriteString("set ARITUN_CA=" + g.ca + "\r\n")
	}
	if g.proxy != "" {
		b.WriteString("set ARITUN_PROXY=" + g.proxy + "\r\n")
	}
	b.WriteString(cmdLine + "\r\n")
	if err := os.WriteFile(wrapper, []byte(b.String()), 0o644); err != nil {
		return err
	}

	cmd := exec.Command("schtasks", "/Create", "/TN", "AriTun", "/TR", wrapper,
		"/SC", "ONLOGON", "/RL", "LIMITED", "/F")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks create: %w", err)
	}
	fmt.Println("AriTun scheduled task created (runs at logon).")
	fmt.Println("start it now with:  schtasks /Run /TN AriTun")
	return nil
}
