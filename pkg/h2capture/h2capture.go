package h2capture

import (
	"fmt"
	"io"
	"strings"

	sph2 "github.com/NotChaosuu/spoofprint/pkg/h2"
	"github.com/NotChaosuu/spoofprint/pkg/ja4"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Captured struct {
	Frames   sph2.Frames
	Headers  []ja4.Header
	Cookies  []ja4.Cookie
	Method   string
	StreamID uint32
}

func ReadRequest(rw io.ReadWriter) (*Captured, *http2.Framer, error) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(rw, preface); err != nil {
		return nil, nil, fmt.Errorf("read preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return nil, nil, fmt.Errorf("bad client preface")
	}

	fr := http2.NewFramer(rw, rw)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	if err := fr.WriteSettings(); err != nil {
		return nil, nil, err
	}

	cap := &Captured{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, nil, err
		}
		switch v := f.(type) {
		case *http2.SettingsFrame:
			if v.IsAck() {
				continue
			}
			v.ForeachSetting(func(s http2.Setting) error {
				cap.Frames.Settings = append(cap.Frames.Settings, sph2.Setting{ID: uint16(s.ID), Val: s.Val})
				return nil
			})
			if err := fr.WriteSettingsAck(); err != nil {
				return nil, nil, err
			}
		case *http2.WindowUpdateFrame:
			if cap.Frames.WindowUpdate == 0 && v.StreamID == 0 {
				cap.Frames.WindowUpdate = v.Increment
			}
		case *http2.PriorityFrame:
			cap.Frames.Priorities = append(cap.Frames.Priorities, sph2.Priority{
				StreamID:    v.StreamID,
				Exclusive:   v.PriorityParam.Exclusive,
				DepStreamID: v.PriorityParam.StreamDep,
				Weight:      uint16(v.PriorityParam.Weight) + 1,
			})
		case *http2.MetaHeadersFrame:
			readHeaders(cap, v)
			cap.StreamID = v.StreamID
			return cap, fr, nil
		}
	}
}

func readHeaders(cap *Captured, mh *http2.MetaHeadersFrame) {
	if mh.HasPriority() {
		p := mh.Priority
		cap.Frames.Priorities = append(cap.Frames.Priorities, sph2.Priority{
			StreamID:    mh.StreamID,
			Exclusive:   p.Exclusive,
			DepStreamID: p.StreamDep,
			Weight:      uint16(p.Weight) + 1,
		})
	}
	for _, hf := range mh.Fields {
		name := strings.ToLower(hf.Name)
		if strings.HasPrefix(name, ":") {
			cap.Frames.PseudoOrder = append(cap.Frames.PseudoOrder, name)
			if name == ":method" {
				cap.Method = hf.Value
			}
			continue
		}
		if name == "cookie" {
			cap.Cookies = append(cap.Cookies, parseCookies(hf.Value)...)
		}
		cap.Headers = append(cap.Headers, ja4.Header{Name: name, Value: hf.Value})
	}
}

func parseCookies(v string) []ja4.Cookie {
	var out []ja4.Cookie
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		out = append(out, ja4.Cookie{Name: strings.TrimSpace(name), Value: val})
	}
	return out
}

func (c *Captured) JA4H() string {
	return ja4.JA4H(ja4.HTTPRequest{
		Method:  c.Method,
		HTTP2:   true,
		Headers: c.Headers,
		Cookies: c.Cookies,
	})
}

func (c *Captured) Akamai() string { return sph2.Akamai(c.Frames) }

func WriteJSONResponse(fr *http2.Framer, streamID uint32, body []byte) error {
	var hb strings.Builder
	enc := hpack.NewEncoder(&hb)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	enc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprintf("%d", len(body))})

	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: []byte(hb.String()),
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	return fr.WriteData(streamID, true, body)
}
