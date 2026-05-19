package kallsyms

import (
	"strings"
	"testing"
)

func TestReaderWords(t *testing.T) {
	input := "ffffffff81000000 T startup_64 [kernel]\n"

	r := newReader(strings.NewReader(input))

	if !r.Line() {
		t.Fatal("expected one line")
	}

	tests := []string{
		"ffffffff81000000",
		"T",
		"startup_64",
		"[kernel]",
	}

	for _, want := range tests {
		if !r.Word() {
			t.Fatalf("expected word %q", want)
		}

		got := r.Text()
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}

	if r.Word() {
		t.Fatalf("expected no more words, got %q", r.Text())
	}

	if err := r.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReaderBytes(t *testing.T) {
	input := "ffffffff81000000 T startup_64 [kernel]\n"

	r := newReader(strings.NewReader(input))

	if !r.Line() {
		t.Fatal("expected one line")
	}

	if !r.Word() {
		t.Fatal("expected first word")
	}

	if got := string(r.Bytes()); got != "ffffffff81000000" {
		t.Fatalf("got %q", got)
	}
}

func TestReaderSkipsExtraSpaces(t *testing.T) {
	input := "  abc   T    symbol_name   [module]  \n"

	r := newReader(strings.NewReader(input))

	if !r.Line() {
		t.Fatal("expected one line")
	}

	tests := []string{
		"abc",
		"T",
		"symbol_name",
		"[module]",
	}

	for _, want := range tests {
		if !r.Word() {
			t.Fatalf("expected word %q", want)
		}

		got := r.Text()
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestReaderMultipleLines(t *testing.T) {
	input := "aaa T first\nbbb T second\n"

	r := newReader(strings.NewReader(input))

	if !r.Line() {
		t.Fatal("expected first line")
	}

	if !r.Word() || r.Text() != "aaa" {
		t.Fatalf("got %q", r.Text())
	}

	if !r.Line() {
		t.Fatal("expected second line")
	}

	if !r.Word() || r.Text() != "bbb" {
		t.Fatalf("got %q", r.Text())
	}

	if r.Line() {
		t.Fatal("expected no more lines")
	}
}
