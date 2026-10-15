package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// ---- sampler unit ----

func TestBandwidthSamplerDeltasAndRetention(t *testing.T) {
	s := newBandwidthSampler(5*time.Second, 3)
	base := time.Now()

	// First sample: the lifetime totals land as the first delta.
	s.append(base, 100, 200, false)
	got := s.snapshot()
	if len(got) != 1 || got[0].BytesIn != 100 || got[0].BytesOut != 200 {
		t.Fatalf("first sample = %+v, want one {100 200} point", got)
	}

	// The next sample carries the delta since the previous one.
	s.append(base.Add(5*time.Second), 150, 260, false)
	got = s.snapshot()
	if len(got) != 2 || got[1].BytesIn != 50 || got[1].BytesOut != 60 {
		t.Fatalf("second sample = %+v, want delta {50 60}", got)
	}

	// Too soon with nothing new: dropped.
	s.append(base.Add(5*time.Second+time.Millisecond), 150, 260, false)
	if n := len(s.snapshot()); n != 2 {
		t.Fatalf("an idle too-soon sample should be dropped, ring holds %d", n)
	}

	// ...unless forced (first scrape / tests).
	s.append(base.Add(5*time.Second+2*time.Millisecond), 150, 260, true)
	if n := len(s.snapshot()); n != 3 {
		t.Fatalf("force should append regardless of the interval, ring holds %d", n)
	}

	// Totals shrinking (a tunnel disconnected) clamp at zero.
	s.append(base.Add(12*time.Second), 10, 10, false)
	got = s.snapshot()
	if last := got[len(got)-1]; last.BytesIn != 0 || last.BytesOut != 0 {
		t.Errorf("shrinking totals should clamp to zero, got %+v", last)
	}

	// New bytes arriving append even before the interval elapses.
	s.append(base.Add(12*time.Second+time.Millisecond), 20, 15, false)
	got = s.snapshot()
	if last := got[len(got)-1]; last.BytesIn != 10 || last.BytesOut != 5 {
		t.Errorf("new bytes should append immediately, last = %+v, want {10 5}", last)
	}

	// The ring stays bounded at the retention limit.
	for i := 0; i < 10; i++ {
		s.append(base.Add(time.Duration(20+i)*time.Second), int64(100+i), int64(200+i), true)
	}
	if n := len(s.snapshot()); n != 3 {
		t.Fatalf("ring grew to %d samples, want capped at 3", n)
	}
}

func TestNewBandwidthSamplerDefaults(t *testing.T) {
	s := newBandwidthSampler(0, 0)
	if s.interval != bandwidthInterval || s.max != bandwidthRetention {
		t.Errorf("zero args should select the defaults, got interval=%v max=%d", s.interval, s.max)
	}
}

// ---- /api/bandwidth end to end ----

type bwPayload struct {
	IntervalSeconds float64 `json:"interval_seconds"`
	Samples         []struct {
		T        time.Time `json:"t"`
		BytesIn  int64     `json:"bytes_in"`
		BytesOut int64     `json:"bytes_out"`
	} `json:"samples"`
}

// TestAPIBandwidthSeries drives traffic through a real tunnel and checks that
// /api/bandwidth reports a sane series, and that the dashboard ships the
// inline chart wired to the same endpoint.
func TestAPIBandwidthSeries(t *testing.T) {
	env := startE2E(t, Config{})
	const bodyLen = 400
	svc := newLocalService(t, strings.Repeat("b", bodyLen))
	cl := env.startClient(e2eRootToken, protocol.Tunnel{
		Type:      protocol.TypeHTTP,
		LocalPort: localPort(t, svc),
		Subdomain: "bw",
	})
	cl.waitForTunnel("bw")

	// Drive traffic: every response contributes bodyLen bytes of bytes_out.
	for i := 0; i < 3; i++ {
		if resp := env.publicGet("bw", "/"); resp.status != http.StatusOK {
			t.Fatalf("proxied request %d: status = %d, want 200", i, resp.status)
		}
	}

	var payload bwPayload
	fetch := func() bool {
		resp := env.adminGet("/api/bandwidth")
		if resp.status != http.StatusOK {
			return false
		}
		if err := json.Unmarshal([]byte(resp.body), &payload); err != nil {
			t.Fatalf("decode /api/bandwidth: %v (body %q)", err, resp.body)
		}
		for _, s := range payload.Samples {
			if s.BytesOut > 0 {
				return true
			}
		}
		return false
	}
	pollUntil(t, "/api/bandwidth to report the proxied bytes", fetch)

	if payload.IntervalSeconds <= 0 {
		t.Errorf("interval_seconds = %v, want a positive sampling interval", payload.IntervalSeconds)
	}
	if len(payload.Samples) == 0 {
		t.Fatal("series is empty")
	}
	var totalOut int64
	for _, s := range payload.Samples {
		if s.T.IsZero() {
			t.Error("sample is missing its timestamp")
		}
		if s.BytesIn < 0 || s.BytesOut < 0 {
			t.Errorf("negative byte count in %+v", s)
		}
		totalOut += s.BytesOut
	}
	// Each proxied response moved bodyLen bytes out; the deltas across the
	// ring partition the lifetime totals, so they must add up to all of it.
	if want := int64(3 * bodyLen); totalOut < want {
		t.Errorf("aggregated bytes_out = %d, want at least %d", totalOut, want)
	}

	// The dashboard embeds the chart and fetches this same endpoint.
	page := env.adminGet("/")
	if page.status != http.StatusOK {
		t.Fatalf("dashboard: status = %d, want 200", page.status)
	}
	for _, want := range []string{"bwchart", "/api/bandwidth", "bytes_out"} {
		if !strings.Contains(page.body, want) {
			t.Errorf("dashboard is missing %q — chart not embedded?", want)
		}
	}
}

// ---- cumulative Prometheus counters ----

// TestMetricsCumulativeBytes checks the server-wide aritun_bytes_*_total
// counters appear and grow with traffic.
func TestMetricsCumulativeBytes(t *testing.T) {
	env := startE2E(t, Config{})
	svc := newLocalService(t, "cumulative-bytes")
	cl := env.startClient(e2eRootToken, protocol.Tunnel{
		Type:      protocol.TypeHTTP,
		LocalPort: localPort(t, svc),
		Subdomain: "cumbytes",
	})
	cl.waitForTunnel("cumbytes")

	read := func() (in, out float64, okIn, okOut bool) {
		body := env.adminGet("/metrics").body
		in, okIn = promValue(body, "aritun_bytes_in_total")
		out, okOut = promValue(body, "aritun_bytes_out_total")
		if !strings.Contains(body, "aritun_tunnel_bytes_out_total{") {
			t.Error("/metrics lost the per-tunnel byte counters")
		}
		return
	}

	var beforeOut float64
	if resp := env.publicGet("cumbytes", "/"); resp.status != http.StatusOK {
		t.Fatalf("proxied request: status = %d, want 200", resp.status)
	}
	pollUntil(t, "aritun_bytes_out_total to move with traffic", func() bool {
		_, out, okIn, okOut := read()
		if !okIn || !okOut {
			t.Fatalf("/metrics is missing aritun_bytes_in_total / aritun_bytes_out_total")
		}
		beforeOut = out
		return out > 0
	})

	for i := 0; i < 3; i++ {
		if resp := env.publicGet("cumbytes", "/more"); resp.status != http.StatusOK {
			t.Fatalf("proxied request %d: status = %d, want 200", i, resp.status)
		}
	}
	pollUntil(t, "aritun_bytes_out_total to increase", func() bool {
		_, out, _, _ := read()
		return out > beforeOut
	})
}
