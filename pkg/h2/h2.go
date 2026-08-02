package h2

import (
	"fmt"
	"strings"
)

type Setting struct {
	ID  uint16
	Val uint32
}

type Priority struct {
	StreamID    uint32
	Exclusive   bool
	DepStreamID uint32
	Weight      uint16
}

type Frames struct {
	Settings     []Setting
	WindowUpdate uint32
	Priorities   []Priority
	PseudoOrder  []string
}

func Akamai(f Frames) string {
	return strings.Join([]string{
		settingsPart(f.Settings),
		windowPart(f.WindowUpdate),
		priorityPart(f.Priorities),
		pseudoPart(f.PseudoOrder),
	}, "|")
}

func settingsPart(settings []Setting) string {
	if len(settings) == 0 {
		return "0"
	}
	parts := make([]string, len(settings))
	for i, s := range settings {
		parts[i] = fmt.Sprintf("%d:%d", s.ID, s.Val)
	}
	return strings.Join(parts, ";")
}

func windowPart(inc uint32) string {
	if inc == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", inc)
}

func priorityPart(ps []Priority) string {
	if len(ps) == 0 {
		return "0"
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		excl := 0
		if p.Exclusive {
			excl = 1
		}
		parts[i] = fmt.Sprintf("%d:%d:%d:%d", p.StreamID, excl, p.DepStreamID, p.Weight)
	}
	return strings.Join(parts, ",")
}

func pseudoPart(order []string) string {
	if len(order) == 0 {
		return ""
	}
	letters := make([]string, 0, len(order))
	for _, name := range order {
		name = strings.TrimPrefix(name, ":")
		if name == "" {
			continue
		}
		letters = append(letters, name[:1])
	}
	return strings.Join(letters, ",")
}
