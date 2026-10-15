package client

import (
	"net"
	"testing"
)

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if !probeTCP("127.0.0.1", port) {
		t.Error("probeTCP should succeed against a listening port")
	}
	if probeTCP("127.0.0.1", 1) {
		t.Error("probeTCP should fail against a closed port")
	}
}
