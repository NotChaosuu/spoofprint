package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NotChaosuu/spoofprint/pkg/h2capture"
	"github.com/NotChaosuu/spoofprint/pkg/ja4"
	"github.com/NotChaosuu/spoofprint/pkg/model"
	"github.com/NotChaosuu/spoofprint/pkg/profiles"
	"github.com/NotChaosuu/spoofprint/pkg/score"
	"github.com/NotChaosuu/spoofprint/pkg/tlscapture"
)

var dumpSeq atomic.Uint64

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	certFile := flag.String("cert", "", "TLS certificate (PEM); self-signed if empty")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	dumpDir := flag.String("dump", "", "if set, write every captured fingerprint as JSON into this directory (for building reference profiles)")
	profilesFile := flag.String("profiles", "", "load browser reference profiles from a JSON file, overriding the built-ins (keeps spoofprint current between releases)")
	flag.Parse()

	if *dumpDir != "" {
		if err := os.MkdirAll(*dumpDir, 0o755); err != nil {
			log.Fatalf("dump dir: %v", err)
		}
	}

	loadProfiles(*profilesFile)

	cert, err := loadCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("spoofprint collector on https://%s (curl -k, or open in a browser)", *addr)

	var backoff time.Duration
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff *= 2; backoff > time.Second {
					backoff = time.Second
				}
				time.Sleep(backoff)
				continue
			}
			log.Printf("accept: %v; collector stopping", err)
			return
		}
		backoff = 0
		go handle(raw, tlsCfg, *dumpDir)
	}
}

func handle(raw net.Conn, cfg *tls.Config, dumpDir string) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	cc := tlscapture.NewConn(raw)
	conn := tls.Server(cc, cfg)
	hsErr := conn.Handshake()

	fp := model.Fingerprint{}
	if hello := cc.ClientHello(); len(hello) > 0 {
		if parsed, err := tlscapture.ParseClientHello(hello); err == nil {
			fp.JA4 = parsed.JA4(false)
			fp.GREASEPresent = parsed.GREASEPresent
			fp.HasMLKEM = parsed.HasMLKEM
			fp.HasALPS = parsed.HasALPS
			fp.ALPN = parsed.ALPN
		}
	}

	rawHello := cc.ClientHello()

	if hsErr != nil {
		if dumpDir != "" && fp.JA4 != "" {
			dumpCapture(dumpDir, fp, rawHello)
		}
		return
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		fp = serveH2(conn, fp)
	} else {
		fp = serveH1(conn, fp)
	}
	if dumpDir != "" && (fp.JA4 != "" || fp.AkamaiH2 != "") {
		dumpCapture(dumpDir, fp, rawHello)
	}
}

func serveH2(conn *tls.Conn, fp model.Fingerprint) model.Fingerprint {
	cap, fr, err := h2capture.ReadRequest(conn)
	if err != nil {
		return fp
	}
	fp.HTTPVersion = "2"
	fp.AkamaiH2 = cap.Akamai()
	fp.JA4H = cap.JA4H()
	fp.PseudoOrder = pseudoLetters(cap.Frames.PseudoOrder)
	fp.UserAgent = headerValue(cap.Headers, "user-agent")
	fp.SecCHUA = headerValue(cap.Headers, "sec-ch-ua")

	body := render(fp)
	_ = h2capture.WriteJSONResponse(fr, cap.StreamID, body)
	return fp
}

func serveH1(conn *tls.Conn, fp model.Fingerprint) model.Fingerprint {
	method, headers, cookies, ok := readH1(conn)
	if !ok {
		return fp
	}
	fp.HTTPVersion = "1.1"
	fp.JA4H = ja4.JA4H(ja4.HTTPRequest{Method: method, HTTP2: false, Headers: headers, Cookies: cookies})
	fp.UserAgent = headerValue(headers, "user-agent")
	fp.SecCHUA = headerValue(headers, "sec-ch-ua")

	body := render(fp)
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	conn.Write(body)
	return fp
}

type capture struct {
	model.Fingerprint
	RawHelloHex string `json:"raw_hello_hex,omitempty"`
}

func dumpCapture(dir string, fp model.Fingerprint, rawHello []byte) {
	fam := "tls-only"
	if fp.UserAgent != "" {
		if f := profiles.ClaimedBrowser(fp.UserAgent); f != model.Unknown {
			fam = string(f)
		} else {
			fam = "unknown"
		}
	}
	b, err := json.MarshalIndent(capture{Fingerprint: fp, RawHelloHex: hex.EncodeToString(rawHello)}, "", "  ")
	if err != nil {
		return
	}
	b = append(b, '\n')
	for i := 0; i < 100000; i++ {
		name := fmt.Sprintf("%s-%03d.json", fam, dumpSeq.Add(1))
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			log.Printf("dump %s: %v", name, err)
			return
		}
		f.Write(b)
		f.Close()
		log.Printf("captured %s (ja4=%s h2=%q)", name, fp.JA4, fp.AkamaiH2)
		return
	}
}

func render(fp model.Fingerprint) []byte {
	v := score.Score(fp)
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

func readH1(conn *tls.Conn) (method string, headers []ja4.Header, cookies []ja4.Cookie, ok bool) {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", nil, nil, false
	}
	if f := strings.Fields(line); len(f) > 0 {
		method = f[0]
	}
	for {
		hl, err := r.ReadString('\n')
		if err != nil {
			return "", nil, nil, false
		}
		hl = strings.TrimRight(hl, "\r\n")
		if hl == "" {
			break
		}
		name, val, found := strings.Cut(hl, ":")
		if !found {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.TrimSpace(val)
		if name == "cookie" {
			for _, part := range strings.Split(val, ";") {
				part = strings.TrimSpace(part)
				cn, cv, _ := strings.Cut(part, "=")
				if cn != "" {
					cookies = append(cookies, ja4.Cookie{Name: strings.TrimSpace(cn), Value: cv})
				}
			}
		}
		headers = append(headers, ja4.Header{Name: name, Value: val})
	}
	return method, headers, cookies, true
}

func pseudoLetters(order []string) string {
	letters := make([]string, 0, len(order))
	for _, name := range order {
		name = strings.TrimPrefix(name, ":")
		if name != "" {
			letters = append(letters, name[:1])
		}
	}
	return strings.Join(letters, ",")
}

func headerValue(headers []ja4.Header, name string) string {
	for _, h := range headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

// loadProfiles applies a runtime profile override (if given) and logs a warning
// for any profile whose reference values are stale or assumed, so a surprising
// verdict has a visible cause instead of a silent one.
func loadProfiles(path string) {
	if path != "" {
		n, err := profiles.LoadProfilesFile(path)
		if err != nil {
			log.Fatalf("profiles: %v", err)
		}
		log.Printf("loaded %d profile(s) from %s", n, path)
	}
	for _, w := range profiles.StaleProfiles(time.Now(), 180*24*time.Hour) {
		log.Printf("profile warning: %s", w)
	}
}

func loadCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return tls.Certificate{}, fmt.Errorf("both -cert and -key are required to serve a custom certificate")
		}
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spoofprint"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
