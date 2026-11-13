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
	"fmt"
	"math"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/term"
)

var (
	validEncodings     = []string{"ascii", "utf-8", "utf-16le", "utf-16be"}
	validDecodeMethods = []string{"base64", "base32", "hex", "url", "gzip", "zlib", "xor"}
	validCountTypes    = []string{"total", "freq"}
	validRadixes       = []string{"x", "d", "o"}
	validColorModes    = []string{"auto", "always", "never"}

	// Methods that decode a found string into bytes, in the order applied.
	stringDecoders = []string{"base64", "base32", "hex", "url"}

	encodingAliases = map[string]string{
		"utf8": "utf-8", "utf16le": "utf-16le", "utf16be": "utf-16be",
		"utf-16": "utf-16le", "utf16": "utf-16le",
	}
)

type Config struct {
	LengthRange    string
	MinLength      int
	MaxLength      int
	RegexStrs      []string
	FindStrs       []string
	EntropyMin     float64
	JSONOut        bool
	CountType      string
	QuietOut       bool
	WordLists      []string
	ExcludeStrs    []string
	Encodings      []string
	DecodeMethods  []string
	InteractiveOut bool
	Section        string
	Recursive      bool
	Jobs           int
	Radix          string
	Color          string
	Context        int

	// Derived by prepare.
	includes       []matcher // ANDed: --regex group, --find group, --wordlist
	exclude        matcher
	stringDecoders []string
	gunzip         bool
	zlib           bool
	xorBrute       bool     // -d xor was given with no key
	xorKeys        [][]byte // XOR keys to scan with, besides the plain pass
	useColor       bool
}

// singleBytes holds every byte value, so a one-byte XOR key can be sliced out
// of it instead of allocated. Keys are only ever read.
var singleBytes = func() (b [256]byte) {
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// prepare validates the user-supplied options and compiles filters.
// It must be called once before the Config is used for scanning.
func (c *Config) prepare() error {
	var err error
	if c.MinLength, c.MaxLength, err = parseLengthRange(c.LengthRange); err != nil {
		return err
	}

	if c.Encodings, err = normalizeEncodings(c.Encodings); err != nil {
		return err
	}

	c.stringDecoders, c.gunzip, c.zlib = nil, false, false
	c.xorBrute, c.xorKeys = false, nil
	for _, spec := range c.DecodeMethods {
		m, arg, hasArg := strings.Cut(spec, ":")
		m = strings.ToLower(strings.TrimSpace(m))
		arg = strings.TrimSpace(arg)
		switch {
		case !slices.Contains(validDecodeMethods, m):
			return fmt.Errorf("unsupported --decode method %q (choices: %s)", m, strings.Join(validDecodeMethods, ", "))
		case hasArg && m != "xor":
			return fmt.Errorf("--decode %q takes no key (only xor does)", m)
		case slices.Contains(stringDecoders, m):
			if !slices.Contains(c.stringDecoders, m) {
				c.stringDecoders = append(c.stringDecoders, m)
			}
		case m == "gzip":
			c.gunzip = true
		case m == "zlib":
			c.zlib = true
		case m == "xor" && !hasArg:
			c.xorBrute = true
		default: // "xor:KEY"
			key, err := parseXorKey(arg)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(c.xorKeys, func(k []byte) bool { return slices.Equal(k, key) }) {
				c.xorKeys = append(c.xorKeys, key)
			}
		}
	}
	if c.xorBrute {
		keys := make([][]byte, 0, 255+len(c.xorKeys))
		for k := 1; k <= 255; k++ {
			keys = append(keys, singleBytes[k:k+1])
		}
		// Any single-byte key given as well is already in there.
		for _, k := range c.xorKeys {
			if len(k) != 1 {
				keys = append(keys, k)
			}
		}
		c.xorKeys = keys
	}

	if c.CountType != "" && !slices.Contains(validCountTypes, c.CountType) {
		return fmt.Errorf("unsupported --count type %q (choices: %s)", c.CountType, strings.Join(validCountTypes, ", "))
	}
	if c.Radix != "" && !slices.Contains(validRadixes, c.Radix) {
		return fmt.Errorf("unsupported --radix %q (choices: %s)", c.Radix, strings.Join(validRadixes, ", "))
	}
	if c.Context < 0 {
		return fmt.Errorf("invalid --context %d: must be >= 0", c.Context)
	}
	if c.Jobs <= 0 {
		c.Jobs = runtime.NumCPU()
	}

	switch c.Color {
	case "", "never":
		c.useColor = false
	case "always":
		c.useColor = !c.JSONOut
	case "auto":
		c.useColor = !c.JSONOut && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))
	default:
		return fmt.Errorf("unsupported --color %q (choices: %s)", c.Color, strings.Join(validColorModes, ", "))
	}

	c.includes = nil

	var regexes []matcher
	for _, r := range c.RegexStrs {
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("invalid --regex %q: %w", r, err)
		}
		regexes = append(regexes, re)
	}
	if m := combine(regexes); m != nil {
		c.includes = append(c.includes, m)
	}

	var finds []matcher
	for _, name := range c.FindStrs {
		m, err := presetMatcher(name)
		if err != nil {
			return err
		}
		finds = append(finds, m)
	}
	if m := combine(finds); m != nil {
		c.includes = append(c.includes, m)
	}

	if len(c.WordLists) > 0 {
		ws, err := loadWordSet(c.WordLists)
		if err != nil {
			return err
		}
		if ws.Len() == 0 {
			// An empty wordlist used to be ignored; keep that behaviour.
			warnf(c.QuietOut, "Warning: wordlist %s is empty\n", strings.Join(c.WordLists, ", "))
		} else {
			c.includes = append(c.includes, ws)
		}
	}

	var excludes []matcher
	for _, x := range c.ExcludeStrs {
		re, err := regexp.Compile(x)
		if err != nil {
			return fmt.Errorf("invalid --exclude %q: %w", x, err)
		}
		excludes = append(excludes, re)
	}
	c.exclude = combine(excludes)

	if c.xorBrute && len(c.includes) == 0 && c.CountType == "" {
		warnf(c.QuietOut, "Warning: -d xor without a key or -r/-f/-w prints the strings of all 255 XOR keys; pass -d xor:KEY, or add a filter to keep only real hits\n")
	}
	return nil
}

// parseXorKey parses the KEY in "-d xor:KEY". Hex digits are taken as bytes
// ("5a", "deadbeef"); anything else is taken as literal text ("hunter2").
// The "0x" and "s:" prefixes force one reading for values that could be read
// either way: "s:abc" is the text "abc", while "0xabc" is an error.
func parseXorKey(s string) ([]byte, error) {
	if text, ok := strings.CutPrefix(s, "s:"); ok {
		if text == "" {
			return nil, fmt.Errorf(`missing text after "xor:s:"`)
		}
		return []byte(text), nil
	}
	if s == "" {
		return nil, fmt.Errorf(`missing key after "xor:" (e.g. -d xor:5a, or plain -d xor to try every single-byte key)`)
	}

	h, isHex := strings.CutPrefix(strings.ToLower(s), "0x")
	if len(h) == 1 {
		// A lone digit is one byte: "5" is 0x05.
		h = "0" + h
	}
	if key := decodeHex(h); len(key) > 0 {
		return key, nil
	}
	if isHex {
		return nil, fmt.Errorf("invalid hex XOR key %q: expected an even number of hex digits, e.g. 0x5a or 0xdeadbeef", s)
	}
	return []byte(s), nil
}

// normalizeEncodings lowercases, resolves aliases, expands "all" and removes
// duplicates. An empty list means ascii.
func normalizeEncodings(in []string) ([]string, error) {
	var out []string
	add := func(e string) {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if a, ok := encodingAliases[e]; ok {
			e = a
		}
		switch {
		case e == "all":
			add("ascii")
			add("utf-16le")
			add("utf-16be")
		case slices.Contains(validEncodings, e):
			add(e)
		default:
			return nil, fmt.Errorf("unsupported --encoding %q (choices: %s, all)", e, strings.Join(validEncodings, ", "))
		}
	}
	if len(out) == 0 {
		out = []string{"ascii"}
	}
	return out, nil
}

// needsRandomAccess reports whether inputs must be seekable (or buffered in
// memory, for pipes) because they are read more than once or out of order.
func (c *Config) needsRandomAccess() bool {
	return len(c.Encodings) > 1 || len(c.xorKeys) > 0 || c.gunzip || c.zlib || c.Context > 0 || c.Section != ""
}

// parseLengthRange parses "MIN:MAX", "MIN:", ":MAX" or "MIN".
func parseLengthRange(s string) (min, max int, err error) {
	min, max = 0, math.MaxInt32
	minStr, maxStr, hasColon := strings.Cut(strings.TrimSpace(s), ":")

	parse := func(v, which string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid --length %q: %s must be a non-negative integer", s, which)
		}
		return n, nil
	}

	if minStr != "" {
		if min, err = parse(minStr, "MIN"); err != nil {
			return
		}
	}
	if hasColon && maxStr != "" {
		if max, err = parse(maxStr, "MAX"); err != nil {
			return
		}
	}
	if min > max {
		return 0, 0, fmt.Errorf("invalid --length %q: MIN is greater than MAX", s)
	}
	return min, max, nil
}
