package tlscapture

import (
	"encoding/binary"
	"net"
	"sync/atomic"
)

type Conn struct {
	net.Conn
	// buf and captured are touched only from the single per-connection read
	// goroutine. hello is published to it there and read from handler goroutines
	// (net/http2 keeps reading while handlers run), so it crosses goroutines and
	// is guarded by an atomic rather than being a plain field.
	buf      []byte
	hello    atomic.Pointer[[]byte]
	captured bool
}

func NewConn(c net.Conn) *Conn { return &Conn{Conn: c} }

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.captured && n > 0 {
		c.buf = append(c.buf, p[:n]...)
		if hs, ok := reassembleClientHello(c.buf); ok {
			c.hello.Store(&hs)
			c.captured = true
			c.buf = nil
		} else if len(c.buf) > 1<<17 {
			c.captured = true
			c.buf = nil
		}
	}
	return n, err
}

func (c *Conn) ClientHello() []byte {
	if p := c.hello.Load(); p != nil {
		return *p
	}
	return nil
}

// reassembleClientHello concatenates the payloads of the leading TLS handshake
// records (type 0x16) and returns the first complete handshake message — the
// ClientHello, with its own 4-byte handshake header intact so ParseClientHello
// can read it directly. RFC 8446 §5.1 permits a handshake message to span
// several records, so an attacker can split one ClientHello across two records;
// taking only record #1 would hand the parser a fragment. ok=false means the
// message isn't fully buffered yet (wait for more Read data) or the stream isn't
// a handshake at all.
func reassembleClientHello(buf []byte) ([]byte, bool) {
	var hs []byte
	b := buf
	for len(b) >= 5 {
		if b[0] != 0x16 {
			return nil, false
		}
		recLen := int(binary.BigEndian.Uint16(b[3:5]))
		if recLen == 0 || len(b) < 5+recLen {
			return nil, false
		}
		hs = append(hs, b[5:5+recLen]...)
		b = b[5+recLen:]
		if len(hs) >= 4 {
			msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+msgLen {
				return hs[:4+msgLen], true
			}
		}
	}
	return nil, false
}
