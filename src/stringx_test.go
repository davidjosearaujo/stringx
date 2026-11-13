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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
)

// scan runs stringx over input with cfg (defaults filled in), through the
// same input/unit pipeline as the CLI, and returns the output lines.
func scan(t *testing.T, cfg Config, data []byte) []string {
	t.Helper()
	return strings.Split(strings.TrimSuffix(scanRaw(t, cfg, data), "\n"), "\n")
}

func scanRaw(t *testing.T, cfg Config, data []byte) string {
	t.Helper()
	if cfg.LengthRange == "" {
		cfg.LengthRange = "4:"
	}
	if err := cfg.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	ins := []*input{{name: "in", data: data, buffered: true}}
	return runInputs(t, &cfg, ins)
}

func runInputs(t *testing.T, cfg *Config, ins []*input) string {
	t.Helper()
	var out bytes.Buffer
	tracker, _ := runUnits(buildUnits(ins, cfg), cfg, &out, func(in *input, err error) {
		fmt.Fprintf(&out, "ERR %s: %v\n", in.name, err)
	})
	writeCounts(&out, cfg, tracker)
	return out.String()
}

func assertLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) == 1 && got[0] == "" {
		got = nil
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestBasicExtraction(t *testing.T) {
	got := scan(t, Config{}, []byte("\x00\x01hello\x00ab\x00world wide\x02"))
	assertLines(t, got, "in:1:3:hello", "in:1:12:world wide")
}

func TestStringAtEOFIsReported(t *testing.T) {
	assertLines(t, scan(t, Config{}, []byte("hello world")), "in:1:1:hello world")
}

func TestLineAndColumnTracking(t *testing.T) {
	got := scan(t, Config{}, []byte("first\nsecond line\n\x00\x00third"))
	assertLines(t, got, "in:1:1:first", "in:2:1:second line", "in:3:3:third")
}

func TestLengthRange(t *testing.T) {
	in := []byte("abc\x00abcd\x00abcdefgh\x00abcdefghijkl")
	assertLines(t, scan(t, Config{LengthRange: "4:8"}, in), "in:1:5:abcd", "in:1:10:abcdefgh")
	assertLines(t, scan(t, Config{LengthRange: ":3"}, in), "in:1:1:abc")
	assertLines(t, scan(t, Config{LengthRange: "9"}, in), "in:1:19:abcdefghijkl")
}

func TestUTF16(t *testing.T) {
	le := []byte("h\x00e\x00l\x00l\x00o\x00\x00\x00w\x00o\x00r\x00l\x00d\x00")
	assertLines(t, scan(t, Config{Encodings: []string{"utf-16le"}}, le), "in:1:1:hello", "in:1:7:world")

	be := []byte("\x00h\x00e\x00l\x00l\x00o\x01\x00\x00w\x00o\x00r\x00l\x00d")
	assertLines(t, scan(t, Config{Encodings: []string{"utf-16be"}}, be), "in:1:1:hello", "in:1:7:world")

	// A non-ASCII UTF-16 code unit (é = U+00E9) terminates a string.
	assertLines(t, scan(t, Config{Encodings: []string{"utf-16le"}}, []byte("a\x00b\x00c\x00d\x00\xe9\x00")), "in:1:1:abcd")

	// A trailing odd byte must not crash or be treated as a character.
	assertLines(t, scan(t, Config{Encodings: []string{"utf-16le"}}, []byte("a\x00b\x00c\x00d\x00e")), "in:1:1:abcd")
}

func TestFilters(t *testing.T) {
	in := []byte("http://localhost/a\x00https://example.com/b\x00mail me@example.org\x00aaaaaaaa\x00")

	assertLines(t, scan(t, Config{FindStrs: []string{"url"}}, in), "in:1:1:http://localhost/a", "in:1:20:https://example.com/b")
	assertLines(t, scan(t, Config{FindStrs: []string{"url"}, ExcludeStrs: []string{"localhost"}}, in), "in:1:20:https://example.com/b")
	assertLines(t, scan(t, Config{FindStrs: []string{"email"}}, in), "in:1:42:mail me@example.org")
	assertLines(t, scan(t, Config{RegexStrs: []string{"^a+$"}}, in), "in:1:62:aaaaaaaa")
	// Include patterns are ANDed together.
	assertLines(t, scan(t, Config{FindStrs: []string{"url"}, RegexStrs: []string{"example"}}, in), "in:1:20:https://example.com/b")
	// "aaaaaaaa" has zero entropy.
	if got := scan(t, Config{EntropyMin: 1}, in); len(got) != 3 {
		t.Errorf("entropy filter: got %d lines, want 3: %v", len(got), got)
	}
}

func TestQuietPrintsBareStrings(t *testing.T) {
	assertLines(t, scan(t, Config{QuietOut: true}, []byte("hello\x00world")), "hello", "world")
}

func TestJSONOutput(t *testing.T) {
	got := scan(t, Config{JSONOut: true}, []byte("\x00abcd"))
	if len(got) != 1 {
		t.Fatalf("got %d lines", len(got))
	}
	var r jsonResult
	if err := json.Unmarshal([]byte(got[0]), &r); err != nil {
		t.Fatal(err)
	}
	want := jsonResult{File: "in", String: "abcd", Length: 4, Entropy: 2, Offset: 1, Line: 1, Column: 2, Encoding: "ascii"}
	if r != want {
		t.Errorf("got %+v, want %+v", r, want)
	}
	if strings.Contains(got[0], "recursive_depth") {
		t.Errorf("top-level result should omit recursive_depth: %s", got[0])
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestRecursiveDecode(t *testing.T) {
	in := []byte("\x00" + b64("secret password") + "\x00")
	assertLines(t, scan(t, Config{DecodeMethods: []string{"base64"}}, in),
		"in:1:2:c2VjcmV0IHBhc3N3b3Jk",
		"  in->base64@1:1:1:secret password",
	)

	// Two levels deep.
	nested := []byte(b64(b64("deeply hidden")))
	got := scan(t, Config{DecodeMethods: []string{"base64"}, QuietOut: true, RegexStrs: []string{"hidden"}}, nested)
	assertLines(t, got, "deeply hidden")

	hexIn := []byte("68656c6c6f20776f726c64")
	got = scan(t, Config{DecodeMethods: []string{"hex"}, QuietOut: true, RegexStrs: []string{"^hello"}}, hexIn)
	assertLines(t, got, "hello world")
}

func TestDecodeIgnoresOutputFilters(t *testing.T) {
	// The base64 blob itself doesn't match --find url, but its content does.
	in := []byte(b64("see https://evil.example/x"))
	got := scan(t, Config{DecodeMethods: []string{"base64"}, FindStrs: []string{"url"}, QuietOut: true}, in)
	assertLines(t, got, "see https://evil.example/x")
}

func TestCounts(t *testing.T) {
	in := []byte("bbbb\x00aaaa\x00bbbb\x00cccc\x00")
	assertLines(t, scan(t, Config{CountType: "total"}, in), "4")
	assertLines(t, scan(t, Config{CountType: "freq"}, in), "      2 bbbb", "      1 aaaa", "      1 cccc")
	assertLines(t, scan(t, Config{CountType: "total", JSONOut: true}, in), `{"total":4}`)
	assertLines(t, scan(t, Config{CountType: "freq", JSONOut: true}, []byte("aaaa")), `{"string":"aaaa","count":1}`)

	// Decoded strings are counted too.
	dec := []byte(b64("secret password"))
	assertLines(t, scan(t, Config{CountType: "total", DecodeMethods: []string{"base64"}}, dec), "2")
}

func TestPrepareValidation(t *testing.T) {
	bad := []Config{
		{LengthRange: "abc", Encodings: []string{"ascii"}},
		{LengthRange: "-1:", Encodings: []string{"ascii"}},
		{LengthRange: "10:2", Encodings: []string{"ascii"}},
		{LengthRange: "4:", Encodings: []string{"utf-32"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, CountType: "bogus"},
		{LengthRange: "4:", Encodings: []string{"ascii"}, DecodeMethods: []string{"rot13"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, DecodeMethods: []string{"xor:"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, DecodeMethods: []string{"xor:s:"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, DecodeMethods: []string{"xor:0xabc"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, DecodeMethods: []string{"base64:5a"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, FindStrs: []string{"phone"}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, RegexStrs: []string{"("}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, ExcludeStrs: []string{"["}},
		{LengthRange: "4:", Encodings: []string{"ascii"}, WordLists: []string{"/nonexistent/wordlist"}},
	}
	for _, c := range bad {
		if err := c.prepare(); err == nil {
			t.Errorf("expected error for %+v", c)
		}
	}
}

func TestParseLengthRange(t *testing.T) {
	cases := []struct {
		in       string
		min, max int
	}{
		{"4:", 4, math.MaxInt32},
		{":10", 0, 10},
		{"3:7", 3, 7},
		{"8", 8, math.MaxInt32},
		{"", 0, math.MaxInt32},
		{"5:5", 5, 5},
	}
	for _, c := range cases {
		min, max, err := parseLengthRange(c.in)
		if err != nil || min != c.min || max != c.max {
			t.Errorf("parseLengthRange(%q) = %d, %d, %v; want %d, %d", c.in, min, max, err, c.min, c.max)
		}
	}
}

func TestEntropy(t *testing.T) {
	cases := map[string]float64{"": 0, "aaaa": 0, "abab": 1, "abcd": 2}
	for s, want := range cases {
		if got := getEntropy(s); got != want {
			t.Errorf("getEntropy(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestWordSetMatchesRegex checks the wordlist matcher against the regex it
// replaced, `\b(w1|w2|...)\b`, on random inputs including non-word characters.
func TestWordSetMatchesRegex(t *testing.T) {
	words := []string{"word", "ab", "c.d", "@w", "_1", "wo-rd", "a", "x y"}
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = `\b` + regexp.QuoteMeta(w) + `\b`
	}
	re := regexp.MustCompile("(" + strings.Join(quoted, "|") + ")")
	ws := newWordSet(words)

	rng := rand.New(rand.NewSource(1))
	const alphabet = "abcdwordxy_1 .-@!"
	for i := 0; i < 50000; i++ {
		b := make([]byte, rng.Intn(16))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		s := string(b)
		if got, want := ws.MatchString(s), re.MatchString(s); got != want {
			t.Fatalf("MatchString(%q) = %v, regex says %v", s, got, want)
		}
	}
}

func TestWordlistFile(t *testing.T) {
	path := t.TempDir() + "/words.txt"
	if err := os.WriteFile(path, []byte("  password \n\nadmin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := []byte("my password1\x00the password is\x00root admin\x00nothing\x00")
	assertLines(t, scan(t, Config{WordLists: []string{path}, QuietOut: true}, in), "the password is", "root admin")
}

func TestPagerWrite(t *testing.T) {
	p := &FullPager{}
	p.Write([]byte("one\ntw"))
	p.Write([]byte("o\n" + strings.Repeat("x", 100000) + "\nlast"))
	p.finish()
	if len(p.lines) != 4 || p.lines[0] != "one" || p.lines[1] != "two" || len(p.lines[2]) != 100000 || p.lines[3] != "last" {
		t.Errorf("unexpected lines: %d", len(p.lines))
	}
}

func TestOpenSection(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()

	var name string
	magic := make([]byte, 4)
	f.ReadAt(magic, 0)
	switch {
	case bytes.HasPrefix(magic, []byte("\x7fELF")):
		name = ".rodata"
	case bytes.HasPrefix(magic, []byte("MZ")):
		name = ".rdata"
	case isMachOMagic(magic):
		name = "__rodata"
	default:
		t.Skip("unknown executable format")
	}

	r, base, _, err := openSection(f, name)
	if err != nil {
		t.Fatalf("openSection(%s): %v", name, err)
	}
	head := make([]byte, 64)
	n, _ := r.Read(head)
	fromFile := make([]byte, n)
	f.ReadAt(fromFile, base)
	if !bytes.Equal(head[:n], fromFile) {
		t.Errorf("section data doesn't match file contents at reported offset %d", base)
	}

	if _, _, _, err := openSection(f, ".does-not-exist"); err == nil {
		t.Error("expected error for missing section")
	}
	if _, _, _, err := openSection(bytes.NewReader([]byte("not an executable")), ".text"); err == nil {
		t.Error("expected error for non-executable")
	}
}

func TestURLSafeBase64Decode(t *testing.T) {
	// "<<???>>" encodes to "PDw/Pz8+Pg==" in standard base64 and to
	// "PDw_Pz8-Pg" in URL-safe base64 (no padding).
	payload := "<<???>> token=hunter2"
	std := base64.StdEncoding.EncodeToString([]byte(payload))
	url := base64.RawURLEncoding.EncodeToString([]byte(payload))
	if !strings.ContainsAny(url, "-_") {
		t.Fatalf("test payload should exercise the URL-safe alphabet: %s", url)
	}
	for _, enc := range []string{std, url} {
		got := scan(t, Config{DecodeMethods: []string{"base64"}, RegexStrs: []string{"hunter2"}, QuietOut: true}, []byte(enc))
		assertLines(t, got, payload)
	}
}

func TestSectorFlagAlias(t *testing.T) {
	saved := cfg.Section
	t.Cleanup(func() { cfg.Section = saved })

	for _, args := range [][]string{{"--section", ".a"}, {"--sector", ".a"}, {"-s", ".a"}} {
		cfg.Section = ""
		if err := rootCmd.Flags().Parse(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if cfg.Section != ".a" {
			t.Errorf("%v: Section = %q, want .a", args, cfg.Section)
		}
	}
}

// TestVersionMatchesChangelog keeps the binary's default version and the
// Debian package version in sync.
func TestVersionMatchesChangelog(t *testing.T) {
	data, err := os.ReadFile("../debian/changelog")
	if err != nil {
		t.Skip(err)
	}
	m := regexp.MustCompile(`^stringx \(([^)-]+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("could not parse debian/changelog")
	}
	if got := string(m[1]); got != version {
		t.Errorf("debian/changelog says %s, src/main.go says %s", got, version)
	}
}
