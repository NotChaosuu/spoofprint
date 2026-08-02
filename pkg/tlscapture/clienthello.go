package tlscapture

import (
	"encoding/binary"
	"errors"

	"github.com/NotChaosuu/spoofprint/pkg/ja4"
)

type ParsedHello struct {
	TLSVersionMax uint16
	SNIPresent    bool
	CipherSuites  []uint16
	Extensions    []uint16
	SigAlgs       []uint16
	ALPN          []string
	SupportedGrps []uint16
	GREASEPresent bool
	HasMLKEM      bool
	HasALPS       bool
}

// X25519MLKEM768 named group (RFC draft codepoint) — the post-quantum key share
// current Chrome/Firefox/Safari send; its absence is a strong spoof tell.
const mlkemGroup = 0x11ec

// application_settings (ALPS) TLS extension codepoints. Chromium sends one of
// these; Firefox/Safari never do, so presence = a Chromium-family ClientHello.
const (
	alpsExtV1 = 17513
	alpsExtV2 = 17613
)

var errShort = errors.New("clienthello: truncated")

func ParseClientHello(raw []byte) (*ParsedHello, error) {
	b := raw

	if len(b) >= 5 && b[0] == 0x16 {
		recLen := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+recLen {
			return nil, errShort
		}
		b = b[5 : 5+recLen]
	}

	if len(b) < 4 || b[0] != 0x01 {
		return nil, errors.New("clienthello: not a ClientHello handshake")
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) < hsLen {
		return nil, errShort
	}
	b = b[:hsLen]

	p := &ParsedHello{}
	cur := b

	if len(cur) < 34 {
		return nil, errShort
	}
	cur = cur[34:]

	if len(cur) < 1 {
		return nil, errShort
	}
	sidLen := int(cur[0])
	cur = cur[1:]
	if len(cur) < sidLen {
		return nil, errShort
	}
	cur = cur[sidLen:]

	if len(cur) < 2 {
		return nil, errShort
	}
	csLen := int(binary.BigEndian.Uint16(cur))
	cur = cur[2:]
	if len(cur) < csLen {
		return nil, errShort
	}
	for i := 0; i+1 < csLen; i += 2 {
		p.CipherSuites = append(p.CipherSuites, binary.BigEndian.Uint16(cur[i:]))
	}
	cur = cur[csLen:]

	if len(cur) < 1 {
		return nil, errShort
	}
	compLen := int(cur[0])
	cur = cur[1:]
	if len(cur) < compLen {
		return nil, errShort
	}
	cur = cur[compLen:]

	if len(cur) < 2 {
		p.finish()
		return p, nil
	}
	extTotal := int(binary.BigEndian.Uint16(cur))
	cur = cur[2:]
	if len(cur) < extTotal {
		extTotal = len(cur)
	}
	exts := cur[:extTotal]

	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts)
		extLen := int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+extLen {
			break
		}
		data := exts[4 : 4+extLen]
		p.Extensions = append(p.Extensions, extType)
		p.parseExtension(extType, data)
		exts = exts[4+extLen:]
	}

	p.finish()
	return p, nil
}

func (p *ParsedHello) parseExtension(extType uint16, data []byte) {
	switch extType {
	case 0x0000:
		p.SNIPresent = true
	case 0x000a:
		if len(data) >= 2 {
			n := int(binary.BigEndian.Uint16(data))
			for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
				g := binary.BigEndian.Uint16(data[i:])
				p.SupportedGrps = append(p.SupportedGrps, g)
				if g == mlkemGroup {
					p.HasMLKEM = true
				}
			}
		}
	case 0x000d:
		if len(data) >= 2 {
			n := int(binary.BigEndian.Uint16(data))
			for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
				p.SigAlgs = append(p.SigAlgs, binary.BigEndian.Uint16(data[i:]))
			}
		}
	case 0x0010:
		if len(data) >= 2 {
			listLen := int(binary.BigEndian.Uint16(data))
			d := data[2:]
			for len(d) >= 1 && listLen > 0 {
				l := int(d[0])
				if len(d) < 1+l {
					break
				}
				p.ALPN = append(p.ALPN, string(d[1:1+l]))
				d = d[1+l:]
				listLen -= 1 + l
			}
		}
	case 0x002b:
		if len(data) >= 1 {
			n := int(data[0])
			best := uint16(0)
			for i := 1; i+1 < 1+n && i+1 < len(data); i += 2 {
				v := binary.BigEndian.Uint16(data[i:])
				if isGREASE(v) {
					continue
				}
				if v > best {
					best = v
				}
			}
			if best != 0 {
				p.TLSVersionMax = best
			}
		}
	case 0x0033:

		if len(data) >= 2 {
			total := int(binary.BigEndian.Uint16(data))
			d := data[2:]
			if total > len(d) {
				total = len(d)
			}
			for len(d) >= 4 {
				g := binary.BigEndian.Uint16(d)
				kl := int(binary.BigEndian.Uint16(d[2:]))
				if g == mlkemGroup {
					p.HasMLKEM = true
				}
				if len(d) < 4+kl {
					break
				}
				d = d[4+kl:]
			}
		}
	case alpsExtV1, alpsExtV2:
		p.HasALPS = true
	}
}

func (p *ParsedHello) finish() {
	if p.TLSVersionMax == 0 {
		p.TLSVersionMax = 0x0303
	}
	for _, c := range p.CipherSuites {
		if isGREASE(c) {
			p.GREASEPresent = true
			break
		}
	}
	if !p.GREASEPresent {
		for _, e := range p.Extensions {
			if isGREASE(e) {
				p.GREASEPresent = true
				break
			}
		}
	}
}

func (p *ParsedHello) JA4(quic bool) string {
	return ja4.JA4(ja4.ClientHello{
		QUIC:          quic,
		TLSVersionMax: p.TLSVersionMax,
		SNIPresent:    p.SNIPresent,
		CipherSuites:  p.CipherSuites,
		Extensions:    p.Extensions,
		SigAlgs:       p.SigAlgs,
		ALPN:          p.ALPN,
	})
}

func isGREASE(v uint16) bool {
	return (v>>8) == (v&0xff) && (v&0x0f) == 0x0a
}
