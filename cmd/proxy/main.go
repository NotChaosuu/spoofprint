package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/NotChaosuu/spoofprint/pkg/model"
	"github.com/NotChaosuu/spoofprint/pkg/profiles"
	"github.com/NotChaosuu/spoofprint/pkg/score"
	"github.com/NotChaosuu/spoofprint/pkg/tlscapture"
)

type ctxKey struct{}

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	upstream := flag.String("upstream", "", "upstream URL to forward to (empty = return the verdict as JSON)")
	certFile := flag.String("cert", "", "TLS certificate (PEM); self-signed if empty")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	block := flag.Int("block", 0, "if >0, respond 403 when spoof score >= this value")
	profilesFile := flag.String("profiles", "", "load browser reference profiles from a JSON file, overriding the built-ins (keeps spoofprint current between releases)")
	flag.Parse()

	loadProfiles(*profilesFile)

	var proxy *httputil.ReverseProxy
	if *upstream != "" {
		u, err := url.Parse(*upstream)
		if err != nil {
			log.Fatalf("bad upstream: %v", err)
		}
		proxy = httputil.NewSingleHostReverseProxy(u)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := fingerprint(r)
		v := score.Score(fp)

		r.Header.Del("X-Spoofprint-Score")
		r.Header.Del("X-Spoofprint-Label")
		r.Header.Del("X-Spoofprint-JA4")
		r.Header.Set("X-Spoofprint-Score", strconv.Itoa(v.SpoofScore))
		r.Header.Set("X-Spoofprint-Label", v.Label)
		if fp.JA4 != "" {
			r.Header.Set("X-Spoofprint-JA4", fp.JA4)
		}

		if *block > 0 && v.SpoofScore >= *block {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(v)
			return
		}
		if proxy == nil {
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(v)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	cert, err := loadCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	srv := &http.Server{
		Addr:      *addr,
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if cc, ok := tc.NetConn().(*tlscapture.Conn); ok {
					return context.WithValue(ctx, ctxKey{}, cc)
				}
			}
			return ctx
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("spoofprint proxy on https://%s upstream=%q", *addr, *upstream)
	log.Fatal(srv.ServeTLS(captureListener{ln}, "", ""))
}

func fingerprint(r *http.Request) model.Fingerprint {
	fp := model.Fingerprint{
		UserAgent: r.UserAgent(),
		SecCHUA:   r.Header.Get("sec-ch-ua"),
	}
	switch r.ProtoMajor {
	case 2:
		fp.HTTPVersion = "2"
	default:
		fp.HTTPVersion = "1.1"
	}
	if cc, ok := r.Context().Value(ctxKey{}).(*tlscapture.Conn); ok {
		if hello := cc.ClientHello(); len(hello) > 0 {
			if parsed, err := tlscapture.ParseClientHello(hello); err == nil {
				fp.JA4 = parsed.JA4(false)
				fp.GREASEPresent = parsed.GREASEPresent
				fp.HasMLKEM = parsed.HasMLKEM
				fp.HasALPS = parsed.HasALPS
				fp.ALPN = parsed.ALPN
			}
		}
	}
	return fp
}

type captureListener struct{ net.Listener }

func (l captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tlscapture.NewConn(c), nil
}

// loadProfiles applies a runtime profile override (if given) and warns on any
// profile whose reference values are stale or assumed.
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
