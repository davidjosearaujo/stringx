// Copyright 2025-2026 David Araújo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// maxContextBytes caps a single --context hexdump.
const maxContextBytes = 64 << 10

type jsonContext struct {
	Offset int64  `json:"offset"`
	Hex    string `json:"hex"`
}

type jsonResult struct {
	File           string       `json:"file"`
	String         string       `json:"string"`
	Length         int          `json:"length"`
	Entropy        float64      `json:"entropy"`
	Offset         int64        `json:"offset"`
	Line           int          `json:"line"`
	Column         int          `json:"column"`
	Encoding       string       `json:"encoding"`
	RecursiveDepth int          `json:"recursive_depth,omitempty"`
	Context        *jsonContext `json:"context,omitempty"`
}

// palette holds ANSI escapes, or empty strings when color is off. The
// choices follow grep: magenta file names, green positions, cyan separators,
// bold red matches.
type palette struct{ file, num, sep, match, reset string }

var ansiPalette = palette{"\033[35m", "\033[32m", "\033[36m", "\033[1;31m", "\033[0m"}

func (sp *StringProcessor) palette() palette {
	if sp.cfg.useColor {
		return ansiPalette
	}
	return palette{}
}

func (sp *StringProcessor) emit(h *hit, entropy float64) {
	switch sp.cfg.CountType {
	case "total":
		sp.tracker.totalCount++
		return
	case "freq":
		sp.tracker.counts[h.s]++
		return
	}

	if sp.cfg.JSONOut {
		sp.emitJSON(h, entropy)
	} else {
		sp.emitText(h)
	}
}

func (sp *StringProcessor) emitJSON(h *hit, entropy float64) {
	res := jsonResult{
		File:           h.src.name,
		String:         h.s,
		Length:         h.runes,
		Entropy:        math.Round(entropy*10000) / 10000,
		Offset:         h.start,
		Line:           h.line,
		Column:         h.col,
		Encoding:       h.src.encoding,
		RecursiveDepth: h.src.depth,
	}
	if lo, data := sp.contextBytes(h, false); data != nil {
		res.Context = &jsonContext{Offset: lo, Hex: hex.EncodeToString(data)}
	}
	b, err := json.Marshal(res)
	if err != nil {
		warnf(sp.cfg.QuietOut, "Error marshalling JSON: %v\n", err)
		return
	}
	sp.writer.Write(append(b, '\n'))
}

func (sp *StringProcessor) emitText(h *hit) {
	c := sp.palette()
	b := sp.buf[:0]

	if sp.cfg.QuietOut {
		// Bare strings, optionally prefixed with an offset like strings -t.
		if sp.cfg.Radix != "" {
			off := sp.formatOffset(h.start)
			b = append(b, c.num...)
			for i := len(off); i < 7; i++ {
				b = append(b, ' ')
			}
			b = append(b, off...)
			b = append(b, c.reset...)
			b = append(b, ' ')
		}
	} else {
		for i := 0; i < h.src.depth; i++ {
			b = append(b, "  "...)
		}
		b = append(b, c.file...)
		b = append(b, h.src.name...)
		if sp.showEncoding(h.src) {
			b = append(b, '[')
			b = append(b, h.src.encoding...)
			b = append(b, ']')
		}
		b = append(b, c.reset...)
		b = appendSep(b, c)
		b = append(b, c.num...)
		if sp.cfg.Radix != "" {
			b = append(b, sp.formatOffset(h.start)...)
		} else {
			b = strconv.AppendInt(b, int64(h.line), 10)
			b = append(b, c.reset...)
			b = appendSep(b, c)
			b = append(b, c.num...)
			b = strconv.AppendInt(b, int64(h.col), 10)
		}
		b = append(b, c.reset...)
		b = appendSep(b, c)
	}

	b = sp.appendHighlighted(b, h.s, c)
	b = append(b, '\n')

	if lo, data := sp.contextBytes(h, true); data != nil {
		indent := strings.Repeat("  ", h.src.depth) + "    "
		b = appendHexdump(b, indent, lo, data, h.start, h.end, c)
	}

	sp.writer.Write(b)
	sp.buf = b
}

func appendSep(b []byte, c palette) []byte {
	b = append(b, c.sep...)
	b = append(b, ':')
	return append(b, c.reset...)
}

// showEncoding reports whether a source name should be tagged with its
// encoding: when several are in play, or it differs from the selected one
// (e.g. decoded data detected as UTF-16).
func (sp *StringProcessor) showEncoding(src *source) bool {
	return len(sp.cfg.Encodings) > 1 || src.encoding != sp.cfg.Encodings[0]
}

func (sp *StringProcessor) formatOffset(off int64) string {
	switch sp.cfg.Radix {
	case "x":
		return strconv.FormatInt(off, 16)
	case "o":
		return strconv.FormatInt(off, 8)
	default:
		return strconv.FormatInt(off, 10)
	}
}

// appendHighlighted appends s, coloring the parts matched by include filters.
func (sp *StringProcessor) appendHighlighted(b []byte, s string, c palette) []byte {
	if c.match == "" || len(sp.cfg.includes) == 0 {
		return append(b, s...)
	}
	last := 0
	for _, span := range anyOf(sp.cfg.includes).FindAllStringIndex(s, -1) {
		b = append(b, s[last:span[0]]...)
		b = append(b, c.match...)
		b = append(b, s[span[0]:span[1]]...)
		b = append(b, c.reset...)
		last = span[1]
	}
	return append(b, s[last:]...)
}

// contextBytes returns --context bytes around h and their offset, or nil when
// context is off or the source can't be read at random. With align, the
// range is widened to 16-byte rows for a hexdump.
func (sp *StringProcessor) contextBytes(h *hit, align bool) (int64, []byte) {
	if sp.cfg.Context <= 0 || h.src.ra == nil {
		return 0, nil
	}
	n := int64(sp.cfg.Context)
	lo, hi := max(h.start-n, 0), h.end+n
	if align {
		lo -= lo % 16
		hi = (hi + 15) / 16 * 16
	}
	hi = min(hi, lo+maxContextBytes)
	buf := make([]byte, hi-lo)
	m, _ := h.src.ra.ReadAt(buf, lo)
	if m == 0 {
		return 0, nil
	}
	return lo, buf[:m]
}

// appendHexdump appends data in `hexdump -C` style, highlighting the bytes
// in [hlStart, hlEnd).
func appendHexdump(b []byte, indent string, base int64, data []byte, hlStart, hlEnd int64, c palette) []byte {
	const digits = "0123456789abcdef"
	inHit := func(pos int64) bool { return pos >= hlStart && pos < hlEnd }

	for row := 0; row < len(data); row += 16 {
		off := base + int64(row)
		b = append(b, indent...)
		b = append(b, c.num...)
		b = fmt.Appendf(b, "%08x", off)
		b = append(b, c.reset...)
		b = append(b, "  "...)

		for i := 0; i < 16; i++ {
			if i == 8 {
				b = append(b, ' ')
			}
			if row+i >= len(data) {
				b = append(b, "   "...)
				continue
			}
			v := data[row+i]
			if inHit(off + int64(i)) {
				b = append(b, c.match...)
				b = append(b, digits[v>>4], digits[v&0x0f])
				b = append(b, c.reset...)
			} else {
				b = append(b, digits[v>>4], digits[v&0x0f])
			}
			b = append(b, ' ')
		}

		b = append(b, " |"...)
		for i := 0; i < 16 && row+i < len(data); i++ {
			ch := data[row+i]
			if ch < 32 || ch > 126 {
				ch = '.'
			}
			if inHit(off + int64(i)) {
				b = append(b, c.match...)
				b = append(b, ch)
				b = append(b, c.reset...)
			} else {
				b = append(b, ch)
			}
		}
		b = append(b, "|\n"...)
	}
	return b
}
