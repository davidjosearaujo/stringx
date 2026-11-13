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
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
)

// maxInflateSize caps how much data a single gzip/zlib stream may expand to,
// so a decompression bomb can't exhaust memory.
const maxInflateSize = 128 << 20

const (
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	hexAlphabet    = "0123456789abcdefABCDEF"
)

// minTokenLen is the shortest run of base64/base32/hex characters decoded
// on its own (see tokens).
const minTokenLen = 8

// decodeString runs every enabled string decoder on h and scans the results.
func (sp *StringProcessor) decodeString(h *hit) {
	for _, method := range sp.cfg.stringDecoders {
		for _, data := range decodeWith(method, h.s) {
			if len(data) > 0 {
				name := fmt.Sprintf("%s->%s@%d", h.src.name, method, h.start)
				sp.scanDecoded(data, name, h.src.depth+1)
			}
		}
	}
}

// decodeWith decodes s with method. Encoded data is often embedded in a
// longer string ("key=...", "powershell -enc ...", "0x4865..."), so each
// run of the encoding's alphabet is decoded separately. Strings without such
// a run fall back to decoding all alphabet characters together, which
// handles short values and spaced-out forms like "48 65 6c 6c 6f".
func decodeWith(method, s string) [][]byte {
	var decode func(string) []byte
	var isChar func(byte) bool
	var padded bool

	switch method {
	case "base64":
		decode, isChar, padded = decodeBase64, isBase64Byte, true
	case "base32":
		decode, isChar, padded = decodeBase32, isBase32Byte, true
	case "hex":
		decode, isChar = decodeHex, isHexByte
	case "url":
		if out := percentDecode(s); out != nil {
			return [][]byte{out}
		}
		return nil
	default:
		return nil
	}

	var out [][]byte
	toks := tokens(s, isChar, padded)
	for _, tok := range toks {
		if d := decode(tok); len(d) > 0 {
			out = append(out, d)
		}
	}
	if len(toks) == 0 {
		var clean strings.Builder
		for i := 0; i < len(s); i++ {
			if isChar(s[i]) {
				clean.WriteByte(s[i])
			}
		}
		if d := decode(clean.String()); len(d) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// tokens returns the runs of at least minTokenLen alphabet characters in s,
// including trailing '=' padding when padded.
func tokens(s string, isChar func(byte) bool, padded bool) []string {
	var out []string
	for i := 0; i < len(s); {
		if !isChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isChar(s[j]) {
			j++
		}
		n := j - i
		if padded {
			for j < len(s) && s[j] == '=' {
				j++
			}
		}
		if n >= minTokenLen {
			out = append(out, s[i:j])
		}
		i = j
	}
	return out
}

func isBase64Byte(b byte) bool {
	return strings.IndexByte(base64Alphabet, b) >= 0 || b == '-' || b == '_'
}

func isBase32Byte(b byte) bool {
	return ('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z') || ('2' <= b && b <= '7')
}

// decodeBase64 accepts the standard and URL-safe alphabets, with or without
// padding.
func decodeBase64(s string) []byte {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if len(s)%4 != 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// decodeBase32 accepts upper or lower case, with or without padding.
func decodeBase32(s string) []byte {
	s = strings.ToUpper(strings.TrimRight(s, "="))
	if len(s)%8 != 0 {
		s += strings.Repeat("=", 8-len(s)%8)
	}
	out, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

func decodeHex(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// percentDecode decodes %XX escapes, leaving malformed ones as they are.
// It returns nil if s contains no escapes.
func percentDecode(s string) []byte {
	if !strings.Contains(s, "%") {
		return nil
	}
	out := make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			out = append(out, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			changed = true
			continue
		}
		out = append(out, s[i])
	}
	if !changed {
		return nil
	}
	return out
}

func isHexByte(b byte) bool { return strings.IndexByte(hexAlphabet, b) >= 0 }

func unhex(b byte) byte {
	switch {
	case '0' <= b && b <= '9':
		return b - '0'
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

// scanDecoded scans decoded bytes for strings in every selected encoding,
// plus UTF-16 when the data looks like it (e.g. PowerShell -EncodedCommand,
// which is base64 of UTF-16LE), then tries to decompress them.
func (sp *StringProcessor) scanDecoded(data []byte, name string, depth int) {
	ra := bytes.NewReader(data)
	for _, enc := range sp.decodedEncodings(data) {
		src := &source{name: name, encoding: enc, depth: depth, ra: ra}
		// Reading from memory can't fail.
		_ = sp.FindStringsInStream(bytes.NewReader(data), src, 0)
	}
	sp.inflate(data, name, depth)
}

func (sp *StringProcessor) decodedEncodings(data []byte) []string {
	encs := sp.cfg.Encodings
	for _, guess := range []struct {
		enc string
		le  bool
	}{{"utf-16le", true}, {"utf-16be", false}} {
		if !slices.Contains(encs, guess.enc) && looksUTF16(data, guess.le) {
			encs = append(slices.Clip(encs), guess.enc)
		}
	}
	return encs
}

// looksUTF16 reports whether data starts like ASCII text in UTF-16: most
// code units have a zero high byte and a non-zero low byte.
func looksUTF16(data []byte, littleEndian bool) bool {
	pairs := min(len(data)/2, 256)
	if pairs < 4 {
		return false
	}
	hits := 0
	for i := 0; i < pairs; i++ {
		lo, hi := data[2*i], data[2*i+1]
		if !littleEndian {
			lo, hi = hi, lo
		}
		if hi == 0 && lo != 0 {
			hits++
		}
	}
	return hits*10 >= pairs*7
}

// inflate decompresses gzip or zlib data (when enabled and the header
// matches) and scans the result as a further decoded layer.
func (sp *StringProcessor) inflate(data []byte, name string, depth int) {
	if depth >= maxDecodeDepth {
		return
	}
	if sp.cfg.gunzip && isGzip(data) {
		if zr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if out := readLimited(zr); len(out) > 0 {
				sp.scanDecoded(out, name+"->gzip", depth+1)
			}
		}
	}
	if sp.cfg.zlib && isZlib(data) {
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			if out := readLimited(zr); len(out) > 0 {
				sp.scanDecoded(out, name+"->zlib", depth+1)
			}
		}
	}
}

// inflateSeeker checks whether a whole input is gzip/zlib data and, if so,
// scans its decompressed contents.
func (sp *StringProcessor) inflateSeeker(rs io.ReadSeeker, name string) {
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(rs, head); err != nil {
		return
	}
	if !(sp.cfg.gunzip && isGzip(head)) && !(sp.cfg.zlib && isZlib(head)) {
		return
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return
	}
	// Reading only as much as can be inflated keeps memory bounded too.
	data, _ := io.ReadAll(io.LimitReader(rs, maxInflateSize))
	sp.inflate(data, name, 0)
}

// readLimited reads up to maxInflateSize bytes. Data before an error (e.g. a
// truncated stream) is still returned: partial content is worth scanning.
func readLimited(r io.Reader) []byte {
	out, _ := io.ReadAll(io.LimitReader(r, maxInflateSize))
	return out
}

func isGzip(b []byte) bool { return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b }

// isZlib checks for a valid zlib header: deflate method, window <= 32K, no
// preset dictionary, and a header checksum divisible by 31.
func isZlib(b []byte) bool {
	return len(b) >= 2 && b[0]&0x0f == 8 && b[0]>>4 <= 7 && b[1]&0x20 == 0 &&
		(uint16(b[0])<<8|uint16(b[1]))%31 == 0
}

// xorReader XORs everything read through it with a repeating key. off is the
// position in the underlying data of the next byte to read (see xorBytes).
type xorReader struct {
	r   io.Reader
	key []byte
	off int64
}

func (x *xorReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	xorBytes(p[:n], x.key, x.off)
	x.off += int64(n)
	return n, err
}

type xorReaderAt struct {
	r   io.ReaderAt
	key []byte
}

func (x xorReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := x.r.ReadAt(p, off)
	xorBytes(p[:n], x.key, off)
	return n, err
}

// xorBytes XORs p in place with key, which repeats over the data from
// position 0. p holds the bytes at position off, so phasing the key on off is
// what keeps a streamed scan and a random-access reread of the same data in
// step.
func xorBytes(p, key []byte, off int64) {
	if len(key) == 0 {
		return
	}
	if len(key) == 1 {
		k := key[0]
		for i := range p {
			p[i] ^= k
		}
		return
	}
	k := int(off % int64(len(key)))
	for i := range p {
		p[i] ^= key[k]
		if k++; k == len(key) {
			k = 0
		}
	}
}
