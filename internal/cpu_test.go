package internal

import (
	"testing"
)

func TestParseCPUs(t *testing.T) {
	for str, result := range map[string]int{
		"0-1":   2,
		"0-2\n": 3,
		"0":     1,
	} {
		n, err := parseCPUs(str)
		if err != nil {
			t.Errorf("Can't parse `%s`: %v", str, err)
		} else if n != result {
			t.Error("Parsing", str, "returns", n, "instead of", result)
		}
	}

	for _, str := range []string{
		"0,3-4",
		"0-",
		"1,",
		"",
	} {
		_, err := parseCPUs(str)
		if err == nil {
			t.Error("Parsed invalid format:", str)
		}
	}
}
