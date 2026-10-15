package protocol

import (
	"bytes"
	"testing"
)

func TestDatagramRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{
		[]byte("hello"),
		{},                               // empty datagram is legal
		bytes.Repeat([]byte{0xAB}, 1400), // typical MTU-sized payload
	}
	for _, p := range payloads {
		if err := WriteDatagram(&buf, p); err != nil {
			t.Fatalf("WriteDatagram(%d bytes): %v", len(p), err)
		}
	}
	for i, want := range payloads {
		got, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatalf("ReadDatagram #%d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("datagram #%d: got %d bytes, want %d", i, len(got), len(want))
		}
	}
}

func TestUDPStreamHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteUDPStreamHeader(&buf, "t_abc123", 5353); err != nil {
		t.Fatalf("WriteUDPStreamHeader: %v", err)
	}
	id, port, err := ReadUDPStreamHeader(&buf)
	if err != nil {
		t.Fatalf("ReadUDPStreamHeader: %v", err)
	}
	if id != "t_abc123" || port != 5353 {
		t.Errorf("got id=%q port=%d, want t_abc123:5353", id, port)
	}
}

func TestUDPStreamHeaderRejectsWrongKind(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteMultiStreamHeader(&buf, "t_x", 80) // wrong kind on purpose
	if _, _, err := ReadUDPStreamHeader(&buf); err == nil {
		t.Error("expected an error reading a multi header as udp")
	}
}
