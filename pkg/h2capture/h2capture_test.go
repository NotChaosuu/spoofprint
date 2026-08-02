package h2capture

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
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestReadRequestAgainstRealH2Client(t *testing.T) {
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		akamai string
		ja4h   string
		pseudo []string
		method string
		hadUA  bool
	}
	resCh := make(chan result, 1)
	clientDone := make(chan struct{})

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(20 * time.Second))
		conn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		})
		if err := conn.Handshake(); err != nil {
			return
		}
		cap, fr, err := ReadRequest(conn)
		if err != nil {
			return
		}
		ua := ""
		for _, h := range cap.Headers {
			if h.Name == "user-agent" {
				ua = h.Value
			}
		}
		resCh <- result{
			akamai: cap.Akamai(),
			ja4h:   cap.JA4H(),
			pseudo: cap.Frames.PseudoOrder,
			method: cap.Method,
			hadUA:  ua != "",
		}
		_ = WriteJSONResponse(fr, cap.StreamID, []byte(`{"ok":true}`))
		<-clientDone
	}()

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}
	req, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/", nil)
	req.Header.Set("User-Agent", "test-h2-client")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	close(clientDone)
	if string(body) != `{"ok":true}` {
		t.Errorf("unexpected response body: %q", body)
	}

	select {
	case r := <-resCh:
		if r.method != "GET" {
			t.Errorf("method = %q, want GET", r.method)
		}
		if len(r.pseudo) != 4 {
			t.Errorf("expected 4 pseudo-headers, got %v", r.pseudo)
		}
		if r.akamai == "" || r.akamai == "0|00|0|" {
			t.Errorf("akamai fingerprint not captured: %q", r.akamai)
		}
		if r.ja4h == "" {
			t.Error("JA4H not computed")
		}
		if !r.hadUA {
			t.Error("user-agent header not captured")
		}
		t.Logf("captured akamai=%s ja4h=%s pseudo=%v", r.akamai, r.ja4h, r.pseudo)
	case <-time.After(15 * time.Second):
		t.Fatal("server did not capture request")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
