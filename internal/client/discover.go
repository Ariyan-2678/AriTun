package client

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// DiscoverOptions tunes local port discovery for `aritun all`.
type DiscoverOptions struct {
	// Ports, when non-empty, replaces discovery entirely.
	Ports []int
	// Exclude is subtracted from the result.
	Exclude map[int]bool
	// ExcludeSystem drops well-known Windows service ports that nobody
	// intentionally publishes. On by default.
	ExcludeSystem bool
	// ExcludeEphemeral drops dynamic/short-lived ports (>= 5000) during
	// discovery. On by default; ignored when Ports is set explicitly.
	ExcludeEphemeral bool
}

// systemPorts are listeners that Windows machines always have open and that
// should never be exposed to the internet by accident.
var systemPorts = map[int]bool{
	135:  true, // RPC Endpoint Mapper
	139:  true, // NetBIOS session
	445:  true, // SMB
	5357: true, // WSDAPI
	7680: true, // Delivery Optimization
}

// ephemeralLow is the start of the dynamic port range. Windows allocates
// outbound connections from 49152 upward, so every socket the machine opens
// briefly shows up as a listener for a moment. Publishing those produces a
// dozen bogus tunnels that appear and vanish between two runs of `aritun all`,
// and the low half of the range (1024-5000) is almost always a real service.
const ephemeralLow = 5000

// DiscoverLocalPorts reports the TCP ports this machine is listening on.
func DiscoverLocalPorts(opts DiscoverOptions) ([]int, error) {
	if len(opts.Ports) > 0 {
		// An explicit list is a deliberate choice, so the ephemeral filter
		// does not apply — only the blanket exclusions.
		opts.ExcludeEphemeral = false
		return normalize(opts.Ports, opts), nil
	}

	var raw []int
	var err error
	switch runtime.GOOS {
	case "windows":
		raw, err = discoverWindows()
	case "linux", "darwin":
		raw, err = discoverProcNet()
	default:
		raw, err = discoverDialSweep()
	}
	if err != nil {
		return nil, err
	}
	return normalize(raw, opts), nil
}

func normalize(ports []int, opts DiscoverOptions) []int {
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		if opts.Exclude[p] {
			continue
		}
		if opts.ExcludeSystem && systemPorts[p] {
			continue
		}
		// Ports at or above the dynamic range are, on Windows, almost always a
		// socket that exists because something made an outbound connection.
		// --include-ephemeral opts back in when that is not what you believe.
		if opts.ExcludeEphemeral && p >= ephemeralLow {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// discoverWindows shells out to netstat. There is no portable Go API for
// enumerating listeners on Windows without cgo.
func discoverWindows() ([]int, error) {
	cmd := exec.Command("netstat", "-ano", "-p", "tcp")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	var ports []int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		if !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		if port, ok := portFromAddress(fields[1]); ok {
			ports = append(ports, port)
		}
	}
	return ports, sc.Err()
}

// discoverProcNet reads the kernel's listening sockets directly. It is exact,
// needs no subprocess, and reports nothing we did not ask for.
func discoverProcNet() ([]int, error) {
	var ports []int
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue // tcp6 is optional
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first { // header
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" { // 0A == LISTEN
				continue
			}
			if port, ok := portFromHexAddress(fields[1]); ok {
				ports = append(ports, port)
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return ports, nil
}

// discoverDialSweep is the last-resort fallback for platforms without a cheap
// enumeration API.
func discoverDialSweep() ([]int, error) {
	var ports []int
	for p := 1; p <= 65535; p++ {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		conn.Close()
		ports = append(ports, p)
	}
	return ports, nil
}

// portFromAddress splits "0.0.0.0:3000" or "[::]:3000".
func portFromAddress(addr string) (int, bool) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// portFromHexAddress splits the /proc/net/tcp "0100007F:1F90" form.
func portFromHexAddress(addr string) (int, bool) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return 0, false
	}
	port, err := strconv.ParseUint(addr[i+1:], 16, 16)
	if err != nil || port == 0 {
		return 0, false
	}
	return int(port), true
}

// defaultWebPorts are treated as HTTP services by `aritun all`, so they get a
// https URL in addition to a raw TCP port.
var defaultWebPorts = map[int]bool{
	80: true, 3000: true, 3001: true, 4000: true, 4173: true,
	5000: true, 5001: true, 5173: true, 5174: true, 8000: true,
	8001: true, 8080: true, 8081: true, 8082: true, 8888: true,
	9000: true, 9001: true, 4321: true, 4200: true, 1337: true,
}

// LooksLikeWeb reports whether a port should also get an HTTP tunnel.
func LooksLikeWeb(port int, extra map[int]bool) bool {
	if extra[port] {
		return true
	}
	if port >= 3000 && port <= 3010 {
		return true
	}
	if port >= 8000 && port <= 8090 {
		return true
	}
	return defaultWebPorts[port]
}
