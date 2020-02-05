package internal

import (
	"io"
	"io/ioutil"
	"testing"
)

func TestParseCPUs(t *testing.T) {
	for str, result := range map[string]int{
		"0-1":        2,
		"0":          1,
		"0,2":        2,
		"0-2,3":      4,
		"0,2-4,7":    5,
		"0,2-4,7-15": 13,
	} {
		fh, err := ioutil.TempFile("", "ebpf")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := io.WriteString(fh, str); err != nil {
			t.Fatal(err)
		}
		fh.Close()

		n, err := parseCPUs(fh.Name())
		if err != nil {
			t.Error("Can't parse", str, err)
		} else if n != result {
			t.Error("Parsing", str, "returns", n, "instead of", result)
		}
	}
}
