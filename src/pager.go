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
	"math"
	"os"
	"strings"

	"golang.org/x/term"
)

type FullPager struct {
	lines      []string
	partial    string
	termHeight int
	isTerminal bool
	quiet      bool
	cursorLine int
	out        io.Writer
}

func NewFullPager(quiet bool) *FullPager {
	p := &FullPager{
		quiet: quiet,
		lines: make([]string, 0, 100),
		out:   os.Stdout,
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		p.isTerminal = true
		if _, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil && h > 1 {
			p.termHeight = h - 1
		} else {
			p.termHeight = 24
		}
	} else {
		p.termHeight = math.MaxInt32
	}

	return p
}

// Write buffers output into lines. It never fails, and handles lines of any
// length as well as lines split across several writes.
func (p *FullPager) Write(data []byte) (int, error) {
	s := p.partial + string(data)
	parts := strings.Split(s, "\n")
	p.lines = append(p.lines, parts[:len(parts)-1]...)
	p.partial = parts[len(parts)-1]
	return len(data), nil
}

func (p *FullPager) finish() {
	if p.partial != "" {
		p.lines = append(p.lines, p.partial)
		p.partial = ""
	}
}

func (p *FullPager) dump() {
	w := bufio.NewWriter(p.out)
	for _, line := range p.lines {
		w.WriteString(line)
		w.WriteByte('\n')
	}
	w.Flush()
}

// openKeyboard returns a terminal to read keys from. When the scanned data
// was piped in on stdin, keys are read from the controlling terminal instead.
func openKeyboard() (*os.File, func(), error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, func() {}, nil
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, nil, err
	}
	return tty, func() { tty.Close() }, nil
}

func (p *FullPager) Show() error {
	p.finish()

	if !p.isTerminal {
		p.dump()
		return nil
	}

	kbd, closeKbd, err := openKeyboard()
	if err != nil {
		p.dump()
		return nil
	}
	defer closeKbd()

	oldState, err := term.MakeRaw(int(kbd.Fd()))
	if err != nil {
		p.dump()
		return err
	}
	defer term.Restore(int(kbd.Fd()), oldState)

	fmt.Fprint(p.out, "\033[?1049h")
	defer fmt.Fprint(p.out, "\033[?1049l")

	reader := bufio.NewReader(kbd)
	p.refreshScreen()

	const scrollUp = '\x01'
	const scrollDown = '\x02'

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil
		}

		r := rune(b)

		if b == 27 && reader.Buffered() > 1 {
			sequence, err := reader.Peek(2)
			if err == nil && sequence[0] == '[' {
				reader.ReadByte()
				keyByte, _ := reader.ReadByte()

				switch keyByte {
				case 'A':
					r = scrollUp
				case 'B':
					r = scrollDown
				default:
					continue
				}
			}
		}

		maxScrollLine := max(len(p.lines)-p.termHeight, 0)

		switch r {
		case 'q', 'Q', 3: // 3 = Ctrl-C, which raw mode delivers as a byte
			return nil
		case scrollDown, '\n', '\r', 'j':
			if p.cursorLine < maxScrollLine {
				p.cursorLine++
			}
		case scrollUp, 'k':
			if p.cursorLine > 0 {
				p.cursorLine--
			}
		case ' ':
			p.cursorLine = min(p.cursorLine+p.termHeight, maxScrollLine)
		case 'b', 'B':
			p.cursorLine = max(p.cursorLine-p.termHeight, 0)
		case 'g':
			p.cursorLine = 0
		case 'G':
			p.cursorLine = maxScrollLine
		}

		p.refreshScreen()
	}
}

func (p *FullPager) refreshScreen() {
	w := bufio.NewWriter(p.out)
	defer w.Flush()

	fmt.Fprint(w, "\033[2J\033[H")

	endLine := min(p.cursorLine+p.termHeight, len(p.lines))

	for _, line := range p.lines[p.cursorLine:endLine] {
		fmt.Fprint(w, line+"\r\n")
	}

	for i := endLine - p.cursorLine; i < p.termHeight; i++ {
		fmt.Fprint(w, "~\r\n")
	}

	p.showPrompt(w)
}

func (p *FullPager) showPrompt(w io.Writer) {
	if p.quiet {
		return
	}

	fmt.Fprintf(w, "\033[%d;1H", p.termHeight+1)
	fmt.Fprint(w, "\033[K")

	totalLines := len(p.lines)
	if totalLines == 0 {
		fmt.Fprint(w, "(no strings found)")
		return
	}

	if p.cursorLine+p.termHeight >= totalLines {
		fmt.Fprintf(w, "--- (END) ---")
	} else {
		percent := min(int(math.Round(float64(p.cursorLine+p.termHeight)/float64(totalLines)*100)), 100)
		fmt.Fprintf(w, "--- %d/%d (%d%%) --- (Up/Down/Enter: line, space/b: page, g/G: top/bottom, q: quit)",
			p.cursorLine+1, totalLines, percent)
	}

	fmt.Fprintf(w, "\033[H")
}
