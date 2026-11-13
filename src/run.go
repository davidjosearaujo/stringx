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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// input is one thing to scan: a file on disk, data held in memory (stdin or
// a pipe that must be read more than once), or a one-shot stream.
type input struct {
	name     string
	path     string
	data     []byte
	buffered bool
	stream   io.Reader
	err      error

	reported bool // an error for this input was already printed
}

// collectInputs turns command-line arguments into inputs, expanding
// directories when --recursive is set. "-" (or no arguments) means stdin.
func collectInputs(args []string, cfg *Config, stdin io.Reader) []*input {
	if len(args) == 0 {
		args = []string{"-"}
	}
	var ins []*input
	for _, arg := range args {
		if arg == "-" {
			ins = append(ins, readerInput("<stdin>", stdin, cfg))
			continue
		}
		fi, err := os.Stat(arg)
		switch {
		case err != nil:
			ins = append(ins, &input{name: arg, err: err})
		case fi.IsDir():
			if !cfg.Recursive {
				ins = append(ins, &input{name: arg, err: fmt.Errorf("%s: is a directory (use -R to scan directories)", arg)})
				continue
			}
			// Symlinks and special files inside the tree are skipped, so a
			// walk can't wander off or block on a FIFO or device.
			filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					ins = append(ins, &input{name: p, err: err})
					return nil
				}
				if d.Type().IsRegular() {
					ins = append(ins, &input{name: p, path: p})
				}
				return nil
			})
		case fi.Mode().IsRegular():
			ins = append(ins, &input{name: arg, path: arg})
		default:
			// Named explicitly, e.g. a FIFO from <(...): it can only be read
			// once, so treat it like stdin.
			f, err := os.Open(arg)
			if err != nil {
				ins = append(ins, &input{name: arg, err: err})
				continue
			}
			ins = append(ins, readerInput(arg, f, cfg))
		}
	}
	return ins
}

// readerInput wraps a one-shot reader, buffering it in memory when it must
// be read more than once.
func readerInput(name string, r io.Reader, cfg *Config) *input {
	if !cfg.needsRandomAccess() {
		return &input{name: name, stream: r}
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return &input{name: name, err: fmt.Errorf("reading %s: %w", name, err)}
	}
	return &input{name: name, data: data, buffered: true}
}

// unit is one pass over an input: one encoding, one XOR key (nil for the
// plain pass).
type unit struct {
	in       *input
	encoding string
	xorKey   []byte
	inflate  bool // also look for gzip/zlib data (once per input)

	w       orderedWriter
	tracker *StateTracker
	err     error
	done    chan struct{}
}

func buildUnits(ins []*input, cfg *Config) []*unit {
	var units []*unit
	// A nil key is the plain pass over the input itself.
	keys := append([][]byte{nil}, cfg.xorKeys...)
	for _, in := range ins {
		if in.err != nil {
			units = append(units, &unit{in: in})
			continue
		}
		for ei, enc := range cfg.Encodings {
			for _, key := range keys {
				units = append(units, &unit{
					in:       in,
					encoding: enc,
					xorKey:   key,
					inflate:  ei == 0 && key == nil && (cfg.gunzip || cfg.zlib),
				})
			}
		}
	}
	return units
}

func (u *unit) run(cfg *Config) error {
	in := u.in
	if in.err != nil {
		return in.err
	}

	var r io.Reader
	var rs io.ReadSeeker
	var ra io.ReaderAt
	var base int64

	switch {
	case in.path != "":
		f, err := os.Open(in.path)
		if err != nil {
			return err
		}
		defer f.Close()
		rs, ra = f, f
	case in.buffered:
		br := bytes.NewReader(in.data)
		rs, ra = br, br
	default:
		r = in.stream
	}

	if cfg.Section != "" {
		sec, secBase, inFile, err := openSection(ra, cfg.Section)
		if err != nil {
			return fmt.Errorf("%s: section %q: %w", in.name, cfg.Section, err)
		}
		rs, base = sec, secBase
		if !inFile {
			ra = nil
		}
	}
	if rs != nil {
		r = rs
	}

	name := in.name
	if len(u.xorKey) > 0 {
		name = fmt.Sprintf("%s->xor(0x%x)", in.name, u.xorKey)
		// base is where r starts in the input (non-zero with --section).
		r = &xorReader{r: r, key: u.xorKey, off: base}
		if ra != nil {
			ra = xorReaderAt{ra, u.xorKey}
		}
	}

	sp := NewStringProcessor(cfg, u.tracker, &u.w)
	if err := sp.FindStringsInStream(r, &source{name: name, encoding: u.encoding, ra: ra}, base); err != nil {
		return err
	}
	if u.inflate && rs != nil {
		sp.inflateSeeker(rs, name)
	}
	return nil
}

// orderedWriter buffers a unit's output until it's the unit's turn, then
// writes straight through. Output therefore comes out in input order while
// later units are already being scanned.
type orderedWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	direct io.Writer
}

func (w *orderedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.direct != nil {
		return w.direct.Write(p)
	}
	return w.buf.Write(p)
}

func (w *orderedWriter) promote(out io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out.Write(w.buf.Bytes())
	w.buf = bytes.Buffer{}
	w.direct = out
}

// runUnits scans units with cfg.Jobs workers, writing output to out in
// order. onError is called (in order, once per input) for failed units.
func runUnits(units []*unit, cfg *Config, out io.Writer, onError func(*input, error)) (*StateTracker, bool) {
	jobs := max(cfg.Jobs, 1)
	for _, u := range units {
		u.tracker = NewStateTracker()
		u.done = make(chan struct{})
	}

	work := make(chan *unit)
	// At most 2*jobs units may be in flight or waiting to be written, which
	// bounds how much output is buffered behind a slow unit.
	window := make(chan struct{}, 2*jobs)

	for i := 0; i < jobs; i++ {
		go func() {
			for u := range work {
				u.err = u.run(cfg)
				close(u.done)
			}
		}()
	}
	go func() {
		for _, u := range units {
			window <- struct{}{}
			work <- u
		}
		close(work)
	}()

	total := NewStateTracker()
	failed := false
	for _, u := range units {
		u.w.promote(out)
		<-u.done
		<-window
		total.merge(u.tracker)
		if u.err != nil {
			failed = true
			if !u.in.reported {
				u.in.reported = true
				onError(u.in, u.err)
			}
		}
	}
	return total, failed
}
