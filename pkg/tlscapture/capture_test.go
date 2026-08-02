package tlscapture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCaptureRealHandshake(t *testing.T) {
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var (
		mu       sync.Mutex
		parsed   *ParsedHello
		captured []byte
	)
	done := make(chan struct{})

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		cc := NewConn(raw)
		tlsConn := tls.Server(cc, &tls.Config{Certificates: []tls.Certificate{cert}})
		tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tlsConn.Handshake()
		mu.Lock()
		captured = cc.ClientHello()
		if len(captured) > 0 {
			parsed, _ = ParseClientHello(captured)
		}
		mu.Unlock()
		tlsConn.Close()
		close(done)
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         "example.test",
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	client.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("no ClientHello captured")
	}
	if parsed == nil {
		t.Fatal("ClientHello did not parse")
	}
	if len(parsed.CipherSuites) == 0 {
		t.Error("no cipher suites parsed")
	}
	if !parsed.SNIPresent {
		t.Error("SNI should be detected (client set ServerName)")
	}
	if len(parsed.ALPN) == 0 || parsed.ALPN[0] != "h2" {
		t.Errorf("ALPN not parsed correctly: %v", parsed.ALPN)
	}
	if parsed.GREASEPresent {
		t.Error("Go stdlib client should NOT send GREASE — a real browser would")
	}
	j := parsed.JA4(false)
	if !strings.HasPrefix(j, "t") || strings.Count(j, "_") != 2 {
		t.Errorf("JA4 is malformed: %q", j)
	}
	t.Logf("captured JA4 from Go client: %s (GREASE=%v)", j, parsed.GREASEPresent)
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := ParseClientHello([]byte{0x16, 0x03, 0x01, 0x00}); err == nil {
		t.Error("expected error on truncated record")
	}
	if _, err := ParseClientHello([]byte{0x99, 0x01, 0x02}); err == nil {
		t.Error("expected error on non-ClientHello")
	}
}

func buildHello(extTypes []uint16) []byte {
	var b []byte
	put16 := func(v uint16) { b = append(b, byte(v>>8), byte(v)) }

	b = append(b, 0x03, 0x03)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x00)
	put16(2)
	put16(0x0a0a)
	b = append(b, 0x01, 0x00)

	var ext []byte
	eput16 := func(v uint16) { ext = append(ext, byte(v>>8), byte(v)) }
	for _, t := range extTypes {
		eput16(t)
		eput16(0)
	}
	put16(uint16(len(ext)))
	b = append(b, ext...)

	hdr := []byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(hdr, b...)
}

func TestALPSDetection(t *testing.T) {
	cases := []struct {
		name string
		exts []uint16
		want bool
	}{
		{"alps-v2-current-chromium", []uint16{0x000d, alpsExtV2}, true},
		{"alps-v1-draft", []uint16{alpsExtV1}, true},
		{"no-alps-firefox-like", []uint16{0x000d, 0x0033}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseClientHello(buildHello(tc.exts))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.HasALPS != tc.want {
				t.Errorf("HasALPS = %v, want %v", p.HasALPS, tc.want)
			}
			if !p.GREASEPresent {
				t.Error("GREASE cipher should be detected")
			}
		})
	}
}

func TestMLKEMDetectionViaSupportedGroups(t *testing.T) {
	hello := buildHelloWithExt(0x000a, []byte{0x00, 0x02, 0x11, 0xec})
	p, err := ParseClientHello(hello)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.HasMLKEM {
		t.Error("X25519MLKEM768 in supported_groups should set HasMLKEM")
	}
}

func buildHelloWithExt(extType uint16, body []byte) []byte {
	var b []byte
	put16 := func(v uint16) { b = append(b, byte(v>>8), byte(v)) }
	b = append(b, 0x03, 0x03)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x00)
	put16(2)
	put16(0x1301)
	b = append(b, 0x01, 0x00)

	ext := []byte{byte(extType >> 8), byte(extType), byte(len(body) >> 8), byte(len(body))}
	ext = append(ext, body...)
	put16(uint16(len(ext)))
	b = append(b, ext...)

	hdr := []byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(hdr, b...)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestParseRejectsFragmentedHello(t *testing.T) {
	b := append([]byte{0x01, 0x00, 0x10, 0x00}, make([]byte, 40)...)
	if _, err := ParseClientHello(b); err == nil {
		t.Error("a hello shorter than its declared length must return errShort, not parse a partial/wrong fingerprint")
	}
}

// A ClientHello split across two TLS records (legal per RFC 8446 §5.1) must be
// reassembled before parsing. Taking only record #1 would hand the parser a
// fragment that produces no JA4, silently disabling every TLS check.
func TestConnReassemblesFragmentedHello(t *testing.T) {
	msg := buildHello([]uint16{0x0000, 0x0010, 0x000d, 0x0033, alpsExtV2})
	half := len(msg) / 2
	framed := append(tlsRecord(msg[:half]), tlsRecord(msg[half:])...)

	cc := NewConn(&sliceConn{data: framed})
	buf := make([]byte, 32) // tiny reads, to exercise cross-Read buffering
	for i := 0; i < 1000 && cc.ClientHello() == nil; i++ {
		if _, err := cc.Read(buf); err != nil {
			break
		}
	}
	hs := cc.ClientHello()
	if hs == nil {
		t.Fatal("Conn did not reassemble the fragmented ClientHello (would score as no-TLS = bypass)")
	}
	parsed, err := ParseClientHello(hs)
	if err != nil {
		t.Fatalf("reassembled hello did not parse: %v", err)
	}
	whole, _ := ParseClientHello(msg)
	if got, want := parsed.JA4(false), whole.JA4(false); got != want {
		t.Errorf("reassembled JA4 %q != whole-hello JA4 %q", got, want)
	}
	if !parsed.HasALPS {
		t.Error("ALPS extension lost across record reassembly")
	}
}

// FuzzParseClientHello asserts the hand-written parser never panics or hangs on
// arbitrary input, and never emits a malformed JA4 (the round-1 "raw byte in
// JA4_a" class). Run with: go test -fuzz=FuzzParseClientHello -fuzztime=30s
func FuzzParseClientHello(f *testing.F) {
	f.Add(buildHello([]uint16{0x0000, 0x0010, 0x000d, 0x0033, alpsExtV2}))
	f.Add(buildHelloWithExt(0x000a, []byte{0x00, 0x02, 0x11, 0xec}))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := ParseClientHello(raw)
		if err != nil {
			return
		}
		j := p.JA4(false)
		if strings.Count(j, "_") != 2 {
			t.Fatalf("JA4 has wrong shape for input %x: %q", raw, j)
		}
		for i := 0; i < len(j); i++ {
			if j[i] >= 0x80 {
				t.Fatalf("JA4 has a raw non-ASCII byte for input %x: %q", raw, j)
			}
		}
	})
}

// ClientHello() is read from a second goroutine while Read drives the connection.
// hello is published via an atomic, so this is race-free — `go test -race` would
// flag a regression to a plain field.
func TestConnClientHelloConcurrentRead(t *testing.T) {
	framed := tlsRecord(buildHello([]uint16{0x0000, 0x0010, alpsExtV2}))
	cc := NewConn(&sliceConn{data: framed})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			_ = cc.ClientHello()
		}
	}()
	buf := make([]byte, 16)
	for i := 0; i < 1000 && cc.ClientHello() == nil; i++ {
		if _, err := cc.Read(buf); err != nil {
			break
		}
	}
	<-done
	if cc.ClientHello() == nil {
		t.Fatal("expected ClientHello to be captured")
	}
}

// tlsRecord wraps a payload in a TLS handshake record (type 0x16, version 0x0301).
func tlsRecord(payload []byte) []byte {
	r := []byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}
	return append(r, payload...)
}

// sliceConn is a net.Conn that serves fixed bytes from Read; other methods are
// unused by Conn.Read and left nil.
type sliceConn struct {
	net.Conn
	data []byte
	pos  int
}

func (s *sliceConn) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}
