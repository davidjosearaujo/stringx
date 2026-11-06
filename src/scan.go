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
	"bufio"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"unicode"
	"unicode/utf8"
)

// maxDecodeDepth bounds how many times decoded content is decoded again.
const maxDecodeDepth = 10

type StateTracker struct {
	counts     map[string]int
	totalCount int
}

func NewStateTracker() *StateTracker {
	return &StateTracker{counts: make(map[string]int)}
}

func (t *StateTracker) merge(o *StateTracker) {
	t.totalCount += o.totalCount
	for k, v := range o.counts {
		t.counts[k] += v
	}
}

type StringProcessor struct {
	cfg     *Config
	tracker *StateTracker
	writer  io.Writer
	buf     []byte // reused output line buffer
}

func NewStringProcessor(cfg *Config, tracker *StateTracker, writer io.Writer) *StringProcessor {
	return &StringProcessor{cfg: cfg, tracker: tracker, writer: writer}
}

// source describes the data a string was found in.
type source struct {
	name     string
	encoding string
	depth    int         // decode depth; 0 for the input itself
	ra       io.ReaderAt // the data, addressed by reported offsets; nil if unavailable
}

// hit is one string found in a source.
type hit struct {
	s          string // UTF-8 text
	runes      int    // length in characters
	start, end int64  // byte range in the source
	line, col  int
	src        *source
}

func getEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var ascii [utf8.RuneSelf]int
	var other map[rune]int
	n := 0
	for _, r := range s {
		n++
		if r < utf8.RuneSelf {
			ascii[r]++
			continue
		}
		if other == nil {
			other = make(map[rune]int)
		}
		other[r]++
	}

	counts := ascii[:]
	if other != nil {
		counts = append([]int(nil), ascii[:]...)
		// Sorted so the floating-point sum is deterministic.
		for _, r := range slices.Sorted(maps.Keys(other)) {
			counts = append(counts, other[r])
		}
	}

	length := float64(n)
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPrintable(r rune) bool {
	return (32 <= r && r <= 126) || r == 9
}

// matches reports whether s passes the entropy, exclude and include filters.
// It also returns the entropy when it had to be computed.
func (sp *StringProcessor) matches(s string) (bool, float64) {
	var entropy float64
	if sp.cfg.EntropyMin > 0 || sp.cfg.JSONOut {
		entropy = getEntropy(s)
		if sp.cfg.EntropyMin > 0 && entropy < sp.cfg.EntropyMin {
			return false, entropy
		}
	}
	if sp.cfg.exclude != nil && sp.cfg.exclude.MatchString(s) {
		return false, entropy
	}
	for _, m := range sp.cfg.includes {
		if !m.MatchString(s) {
			return false, entropy
		}
	}
	return true, entropy
}

func (sp *StringProcessor) processString(h *hit) {
	if ok, entropy := sp.matches(h.s); ok {
		sp.emit(h, entropy)
	}

	// Decoding is independent of the output filters: a base64 blob rarely
	// matches e.g. `--find url` itself, but the URL hidden inside it should.
	if h.src.depth < maxDecodeDepth {
		sp.decodeString(h)
	}
}

const (
	encASCII = iota
	encUTF8
	encUTF16LE
	encUTF16BE
)

var encodingKinds = map[string]int{
	"ascii":    encASCII,
	"utf-8":    encUTF8,
	"utf-16le": encUTF16LE,
	"utf-16be": encUTF16BE,
}

// FindStringsInStream scans stream for runs of printable characters in
// src.encoding. baseOffset is added to every reported offset, which lets
// callers scanning a slice of a file (e.g. one section) report file offsets.
//
// ascii and utf-16 only accept printable ASCII (like strings(1)); utf-8 also
// accepts printable non-ASCII characters encoded as valid UTF-8.
func (sp *StringProcessor) FindStringsInStream(stream io.Reader, src *source, baseOffset int64) error {
	kind, ok := encodingKinds[src.encoding]
	if !ok {
		return fmt.Errorf("unsupported encoding: %s", src.encoding)
	}

	reader := bufio.NewReaderSize(stream, 64*1024)

	var current []byte
	var runes int
	var offset, startOffset int64
	line, col := 1, 1
	var startLine, startCol int

	flush := func() {
		if runes > 0 && runes >= sp.cfg.MinLength && runes <= sp.cfg.MaxLength {
			sp.processString(&hit{
				s:     string(current),
				runes: runes,
				start: baseOffset + startOffset,
				end:   baseOffset + offset,
				line:  startLine,
				col:   startCol,
				src:   src,
			})
		}
		current = current[:0]
		runes = 0
	}

	for {
		var r rune
		var size int
		var err error

		switch kind {
		case encASCII:
			var b byte
			b, err = reader.ReadByte()
			r, size = rune(b), 1
		case encUTF8:
			r, size, err = reader.ReadRune()
		default:
			var b0, b1 byte
			b0, err = reader.ReadByte()
			if err == nil {
				b1, err = reader.ReadByte()
			}
			if kind == encUTF16BE {
				r = rune(b0)<<8 | rune(b1)
			} else {
				r = rune(b1)<<8 | rune(b0)
			}
			size = 2
		}

		if err != nil {
			// A string running up to the end of the input is still a string.
			flush()
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error reading %s: %w", src.name, err)
		}

		printable := isPrintable(r) ||
			(kind == encUTF8 && size > 1 && r != utf8.RuneError && unicode.IsPrint(r))

		if printable {
			if runes == 0 {
				startOffset, startLine, startCol = offset, line, col
			}
			if r < utf8.RuneSelf {
				current = append(current, byte(r))
			} else {
				current = utf8.AppendRune(current, r)
			}
			runes++
		} else if runes > 0 {
			flush()
		}

		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		offset += int64(size)
	}
}
