package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
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

// DiscoverLocalUDPPorts reports the UDP ports this machine is bound to.
// UDP has no LISTENING state: a bound, unconnected socket *is* the listener,
// so every platform probe looks for that shape rather than a state word.
func DiscoverLocalUDPPorts(opts DiscoverOptions) ([]int, error) {
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
		raw, err = discoverWindowsUDP()
	case "linux":
		raw, err = discoverProcNetUDP()
		if err == nil && len(raw) == 0 {
			// An empty /proc is usually a container without procfs mounted
			// at the expected path; ss reads the same kernel state.
			if ss, ssErr := discoverSSUDP(); ssErr == nil {
				raw = ss
			}
		}
	case "darwin":
		raw, err = discoverDarwinUDP()
	default:
		raw, err = discoverProcNetUDP()
		if err == nil && len(raw) == 0 {
			// No procfs (BSDs, restricted containers): ss reads the same
			// kernel state when iproute2 is present.
			if ss, ssErr := discoverSSUDP(); ssErr == nil {
				raw = ss
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if opts.ExcludeSystem {
		raw = subtract(raw, udpSystemPorts)
	}
	return normalize(raw, opts), nil
}

// udpSystemPorts are UDP listeners that Windows/desktop machines always have
// bound and that are never worth publishing: NetBIOS name/datagram, SSDP,
// mDNS, LLMNR and Delivery Optimization.
var udpSystemPorts = map[int]bool{
	137:  true, // NetBIOS name service
	138:  true, // NetBIOS datagram
	1900: true, // SSDP / UPnP discovery
	5353: true, // mDNS
	5355: true, // LLMNR
	7680: true, // Delivery Optimization
}

// subtract returns ports without the members of drop.
func subtract(ports []int, drop map[int]bool) []int {
	if len(drop) == 0 {
		return ports
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !drop[p] {
			out = append(out, p)
		}
	}
	return out
}

// discoverWindowsUDP prefers Get-NetUDPEndpoint, which is exact, and falls
// back to netstat when PowerShell or the cmdlet is unavailable (Server Core,
// restricted sessions). Both probes are best-effort by design.
func discoverWindowsUDP() ([]int, error) {
	if ports, err := discoverPowershellUDP(); err == nil && len(ports) > 0 {
		return ports, nil
	}
	return discoverNetstatUDP()
}

// discoverPowershellUDP projects just the port numbers so the output stays
// locale-independent: `(Get-NetUDPEndpoint).LocalPort` prints one integer per
// line no matter the OS language.
func discoverPowershellUDP() ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetUDPEndpoint).LocalPort")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Get-NetUDPEndpoint: %w", err)
	}
	return parsePortLines(string(out)), nil
}

// discoverNetstatUDP shells out to netstat, the same probe `DiscoverLocalPorts`
// uses for TCP. UDP rows carry no state, so every bound endpoint counts.
func discoverNetstatUDP() ([]int, error) {
	cmd := exec.Command("netstat", "-ano", "-p", "udp")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	return parseNetstatUDP(string(out)), nil
}

// discoverDarwinUDP shells out to netstat; macOS has no procfs and no
// Get-NetUDPEndpoint.
func discoverDarwinUDP() ([]int, error) {
	cmd := exec.Command("netstat", "-an", "-p", "udp")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	return parseDarwinNetstatUDP(string(out)), nil
}

// discoverSSUDP reads `ss -uln` for environments without procfs.
func discoverSSUDP() ([]int, error) {
	cmd := exec.Command("ss", "-uln")
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return parseSSUDP(string(out)), nil
}

// discoverProcNetUDP reads bound UDP sockets from the kernel directly. State
// 07 (unconnected) is the server shape; state 01 sockets are clients that
// called connect() and are not offering a service.
func discoverProcNetUDP() ([]int, error) {
	var ports []int
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue // udp6 is optional
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first { // header
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "07" { // 07 == unconnected
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

// parsePortLines reads a bare "one port per line" dump, the shape
// `(Get-NetUDPEndpoint).LocalPort` produces.
func parsePortLines(out string) []int {
	var ports []int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if p, err := strconv.Atoi(strings.TrimSpace(sc.Text())); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	return ports
}

// parseNetstatUDP extracts local ports from Windows `netstat -ano -p udp`
// output; non-UDP rows (and the header) are ignored:
//
//	Active Connections
//
//	Proto  Local Address          Foreign Address        State           PID
//	UDP    0.0.0.0:1900           *:*                                    1234
//	UDP    [::]:4500              *:*                                    5678
func parseNetstatUDP(out string) []int {
	var ports []int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.EqualFold(fields[0], "UDP") {
			continue
		}
		if port, ok := portFromAddress(fields[1]); ok {
			ports = append(ports, port)
		}
	}
	return ports
}

// parseDarwinNetstatUDP reads macOS/BSD `netstat -an` UDP rows, whose local
// address separates the port with a dot: "127.0.0.1.5353", "*.1900".
func parseDarwinNetstatUDP(out string) []int {
	var ports []int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.HasPrefix(strings.ToLower(fields[0]), "udp") {
			continue
		}
		addr := fields[3] // proto recvq sendq local-address ...
		i := strings.LastIndex(addr, ".")
		if i < 0 || i+1 >= len(addr) {
			continue
		}
		if p, err := strconv.Atoi(addr[i+1:]); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	return ports
}

// parseSSUDP reads `ss -uln` rows (with the Netid column modern iproute2
// prints):
//
//	Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
//	udp   UNCONN 0      0      0.0.0.0:5355        0.0.0.0:*
//	udp   UNCONN 0      0      [::]:1900           [::]:*
func parseSSUDP(out string) []int {
	var ports []int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.EqualFold(fields[0], "udp") {
			continue
		}
		// The first host:port column after the queues is the local address.
		for _, f := range fields[1:] {
			if port, ok := portFromAddress(f); ok {
				ports = append(ports, port)
				break
			}
		}
	}
	return ports
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
