package protocol

import (
	"net"
	"sync"
	"time"
)

// idleTimeout is how long a half-open proxied connection may sit silent before
// it is torn down. It keeps dead tunnels from pinning goroutines forever.
const idleTimeout = 24 * time.Hour

// Pipe copies bytes in both directions until either side finishes, then closes
// both. It returns when both directions have drained.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); halfCopy(a, b) }()
	go func() { defer wg.Done(); halfCopy(b, a) }()
	wg.Wait()
}

func halfCopy(dst, src net.Conn) {
	defer func() {
		// Tell the peer we are done writing, then let Pipe close everything.
		if t, ok := dst.(*net.TCPConn); ok {
			t.CloseWrite()
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(time.Minute))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
