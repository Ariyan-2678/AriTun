package server

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// bodyPreviewCap bounds the body bytes retained per request: 2 KiB of a
// response (and of a request, when CaptureBody was used) is enough to
// recognise a payload without ever buffering a large or streaming body.
const bodyPreviewCap = 2048

// headerValueCap bounds one captured header value so a hostile client cannot
// inflate the inspector ring with megabyte-long cookies.
const headerValueCap = 1024

// redactedHeader replaces the value of every credential-bearing header.
const redactedHeader = "[redacted]"

// RequestLog is one proxied request, kept for the inspector and the dashboard.
type RequestLog struct {
	Time        time.Time         `json:"time"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Duration    int64             `json:"duration_ms"`
	Bytes       int64             `json:"bytes"`
	RemoteIP    string            `json:"remote_ip"`
	TunnelID    string            `json:"tunnel_id"`
	Subdomain   string            `json:"subdomain,omitempty"`
	Client      string            `json:"client"`
	ReqHeaders  map[string]string `json:"req_headers,omitempty"`
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	BodyPreview string            `json:"body_preview,omitempty"`
	Curl        string            `json:"curl,omitempty"`
}

// tunnelCounters accumulates per-tunnel lifetime totals for the dashboard and
// Prometheus.
type tunnelCounters struct {
	requests atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	lastCode atomic.Int32
	lastSeen atomic.Int64 // unix nano
}

func (c *tunnelCounters) record(status, bytes int) {
	c.requests.Add(1)
	c.bytesOut.Add(int64(bytes))
	c.lastCode.Store(int32(status))
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *tunnelCounters) addIn(n int64) { c.bytesIn.Add(n) }

// inspector keeps a bounded ring of recent requests plus global counters.
type inspector struct {
	mu       sync.RWMutex
	ring     []RequestLog
	next     int
	size     int
	total    atomic.Int64
	sessions atomic.Int64
}

func newInspector(size int) *inspector {
	if size <= 0 {
		size = 500
	}
	return &inspector{
		ring: make([]RequestLog, size),
		size: size,
	}
}

func (in *inspector) record(rl RequestLog) {
	in.mu.Lock()
	in.ring[in.next] = rl
	in.next = (in.next + 1) % in.size
	in.mu.Unlock()
	in.total.Add(1)
}

// Recent returns up to n of the newest entries, oldest first.
func (in *inspector) Recent(n int) []RequestLog {
	in.mu.RLock()
	defer in.mu.RUnlock()
	if n <= 0 || n > in.size {
		n = in.size
	}
	// Collect the last `n` filled slots in chronological order.
	out := make([]RequestLog, 0, n)
	// next points at the slot that will be written next, so the newest is
	// at next-1.
	for i := n - 1; i >= 0; i-- {
		idx := (in.next - 1 - i + in.size*2) % in.size
		e := in.ring[idx]
		if e.Time.IsZero() {
			continue // empty slot
		}
		out = append(out, e)
	}
	return out
}

// countingWriter captures the status code, byte count, response headers and a
// bounded preview of the body of a proxied response so the inspector can log
// them. The tee never holds a write back: once bodyPreviewCap bytes are kept
// (or the content looks binary) the remaining bytes pass through untouched,
// so SSE, websockets and large downloads keep streaming.
//
// The zero previewMax selects bodyPreviewCap; a negative previewMax disables
// body capture entirely.
type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  int64

	previewMax     int
	preview        []byte
	previewDecided bool
	previewText    bool
	respHeaders    http.Header
}

func (w *countingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.snapHeaders()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.snapHeaders()
	}
	w.tee(p)
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Flush forwards to the underlying writer so SSE and websockets keep working.
func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController, so optional
// interfaces the wrapper does not implement itself (notably Hijack, used by
// websocket upgrades) still work.
func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// snapHeaders copies the response headers at the moment the status line is
// written, so later mutations of the live map cannot change what the log
// shows.
func (w *countingWriter) snapHeaders() {
	if w.respHeaders != nil {
		return
	}
	src := w.Header()
	w.respHeaders = make(http.Header, len(src))
	for k, vs := range src {
		w.respHeaders[k] = append([]string(nil), vs...)
	}
}

// tee retains the leading bytes of p up to previewMax, deciding on the first
// write whether the content type is worth previewing at all. p is never
// buffered beyond the cap and never delayed: the caller writes it through
// immediately either way.
func (w *countingWriter) tee(p []byte) {
	if w.previewMax < 0 || len(p) == 0 {
		return
	}
	if w.previewMax == 0 {
		w.previewMax = bodyPreviewCap
	}
	if !w.previewDecided {
		ct := w.Header().Get("Content-Type")
		if ct == "" {
			// The server sniffs small bodies itself; do the same so an
			// unlabelled text response is still previewed.
			ct = http.DetectContentType(p)
		}
		w.previewDecided = true
		w.previewText = isTextualContentType(ct)
	}
	if !w.previewText || len(w.preview) >= w.previewMax {
		return
	}
	if room := w.previewMax - len(w.preview); len(p) > room {
		w.preview = append(w.preview, p[:room]...)
	} else {
		w.preview = append(w.preview, p...)
	}
}

// bodyPreview is the captured prefix of the response body ("" for binary
// content or an empty body).
func (w *countingWriter) bodyPreview() string { return string(w.preview) }

// responseHeaders returns the captured response headers with credentials
// redacted. Before any write there is nothing to snapshot, so the live map is
// used instead.
func (w *countingWriter) responseHeaders() map[string]string {
	h := w.respHeaders
	if h == nil {
		h = w.Header()
	}
	return captureHeaders(h)
}

func statusOf(w *countingWriter) int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// sensitiveHeaders carry credentials and are never stored or echoed, not even
// in copy-as-curl.
var sensitiveHeaders = map[string]bool{
	"Authorization": true,
	"Cookie":        true,
	"Set-Cookie":    true,
	"X-Api-Key":     true,
}

// captureHeaders flattens a header map for the log: values of
// credential-bearing headers become "[redacted]" and every other value is
// bounded so the ring cannot be blown up by oversized headers. It returns nil
// for an empty map so the JSON stays compact.
func captureHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		key := http.CanonicalHeaderKey(k)
		if sensitiveHeaders[key] {
			out[key] = redactedHeader
			continue
		}
		v := strings.Join(vs, ", ")
		if len(v) > headerValueCap {
			// ToValidUTF8 keeps the cut from leaving half a rune behind.
			v = strings.ToValidUTF8(v[:headerValueCap], "") + "…"
		}
		out[key] = v
	}
	return out
}

// isTextualContentType reports whether a body is text-ish enough to be worth
// previewing and replaying as -d in copy-as-curl.
func isTextualContentType(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript",
		"application/xhtml+xml", "application/x-www-form-urlencoded":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

// curlSkipHeaders are left out of copy-as-curl: curl derives them from the
// URL, the -d body or its own transport, and replaying them would break the
// command (or its gzip decoding).
var curlSkipHeaders = map[string]bool{
	"Host":              true,
	"Content-Length":    true,
	"Connection":        true,
	"Transfer-Encoding": true,
	"Accept-Encoding":   true,
}

// buildCurl renders a copy-as-cURL command. headers must already be redacted
// (pass captureHeaders output): sensitive values are emitted verbatim, so a
// raw header map would leak credentials into the terminal and the log.
// Header order is sorted so the output is stable.
func buildCurl(method, target string, headers map[string]string, body string) string {
	var b strings.Builder
	b.WriteString("curl")
	if method != "" {
		b.WriteString(" -X ")
		b.WriteString(method)
	}
	b.WriteString(" ")
	b.WriteString(shellQuote(target))

	keys := make([]string, 0, len(headers))
	for k := range headers {
		if curlSkipHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(" -H ")
		b.WriteString(shellQuote(k + ": " + headers[k]))
	}
	if body != "" {
		b.WriteString(" -d ")
		b.WriteString(shellQuote(body))
	}
	return b.String()
}

// shellQuote single-quotes s for POSIX shells, which is safe for every byte
// except the quote itself.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// curlURL rebuilds the absolute URL behind an inbound request. Server-side
// requests only carry the path, so the scheme comes from TLS or the
// X-Forwarded-Proto header Caddy sets, and the host from the Host header.
func curlURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		if i := strings.IndexByte(p, ','); i >= 0 {
			p = p[:i]
		}
		if p = strings.TrimSpace(strings.ToLower(p)); p == "http" || p == "https" {
			scheme = p
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	return scheme + "://" + host + uri
}

// bodyCaptureKey is the context key under which CaptureBody parks its tee.
type bodyCaptureKey struct{}

// bodyTee copies the inbound request body into a bounded buffer while letting
// every byte pass straight through to the proxy.
type bodyTee struct {
	rc  io.ReadCloser
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *bodyTee) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.mu.Lock()
		if room := t.max - len(t.buf); room > 0 {
			if n < room {
				room = n
			}
			t.buf = append(t.buf, p[:room]...)
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *bodyTee) Close() error { return t.rc.Close() }

// preview returns the bytes retained so far.
func (t *bodyTee) preview() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// CaptureBody returns a shallow copy of r whose body is teed into a
// bodyPreviewCap-sized buffer that recordRequest turns into the -d argument of
// copy-as-curl. The proxy still reads every byte; only the preview is
// retained. Call it before handing r to the reverse proxy:
//
//	r = server.CaptureBody(r)
//	s.reverseProxy(t).ServeHTTP(cw, r)
//
// Requests without a body are returned unchanged.
func CaptureBody(r *http.Request) *http.Request {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return r
	}
	if _, ok := r.Context().Value(bodyCaptureKey{}).(*bodyTee); ok {
		return r // already capturing
	}
	tee := &bodyTee{rc: r.Body, max: bodyPreviewCap}
	r2 := r.Clone(context.WithValue(r.Context(), bodyCaptureKey{}, tee))
	r2.Body = tee
	return r2
}

// requestBodyPreview returns the bytes CaptureBody retained, or "" when the
// body was not teed (in which case it has already been consumed by the proxy
// and cannot be read again safely).
func requestBodyPreview(r *http.Request) string {
	if r == nil {
		return ""
	}
	if tee, ok := r.Context().Value(bodyCaptureKey{}).(*bodyTee); ok {
		return tee.preview()
	}
	return ""
}

// curlBody picks the payload for copy-as-curl: only a retained, text-ish body
// is safe to hand to a shell, so binary uploads are omitted.
func curlBody(r *http.Request, body string) string {
	if body == "" {
		return ""
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = http.DetectContentType([]byte(body))
	}
	if !isTextualContentType(ct) {
		return ""
	}
	return body
}

// recordRequest builds the full RequestLog for one proxied request — the
// original fields plus redacted request/response headers, a bounded response
// body preview and a copy-as-curl command — and appends it to the inspector.
// It is a drop-in replacement for the inline s.insp.record(...) calls in the
// public proxy handlers: pass the tunnel, the inbound request, the
// countingWriter that wrapped the response and the time the proxy was
// invoked.
func (s *Server) recordRequest(t *Tunnel, r *http.Request, cw *countingWriter, start time.Time) {
	if t == nil || r == nil || cw == nil {
		return
	}
	client := ""
	if t.Session != nil {
		client = t.Session.name
	}
	reqHeaders := captureHeaders(r.Header)
	rl := RequestLog{
		Time:      start,
		Method:    r.Method,
		URL:       r.URL.Path,
		Status:    statusOf(cw),
		Duration:  time.Since(start).Milliseconds(),
		Bytes:     cw.bytes,
		RemoteIP:  visitorIP(r.Header.Get("X-Forwarded-For"), r.RemoteAddr).String(),
		TunnelID:  t.ID,
		Subdomain: t.Subdomain,
		Client:    client,
		// Captured detail:
		ReqHeaders:  reqHeaders,
		RespHeaders: cw.responseHeaders(),
		BodyPreview: cw.bodyPreview(),
	}
	rl.Curl = buildCurl(r.Method, curlURL(r), reqHeaders, curlBody(r, requestBodyPreview(r)))
	s.insp.record(rl)
}

// formatMethodURL gives a compact "GET /path" for the inspector line.
func formatMethodURL(r *http.Request) string {
	p := r.URL.Path
	if p == "" {
		p = "/"
	}
	if len(p) > 120 {
		p = p[:120] + "…"
	}
	return r.Method + " " + p
}
