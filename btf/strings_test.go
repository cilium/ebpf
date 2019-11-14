package btf

import (
	"reflect"
	"strings"
	"testing"
)

func TestReadStrings(t *testing.T) {
	in := strings.NewReader("\x00one\x00two\x00")

	want := map[uint32]string{
		0: "",
		1: "one",
		5: "two",
	}

	have, err := readStrings(in)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(have, want) {
		t.Log("Have:", have)
		t.Log("Want:", want)
		t.Error("Have and want don't match")
	}
}

func TestReadStringsErrors(t *testing.T) {
	in := strings.NewReader("\x00one")
	_, err := readStrings(in)
	if err == nil {
		t.Fatal("Accepted non-terminated string")
	}

	in = strings.NewReader("one\x00")
	_, err = readStrings(in)
	if err == nil {
		t.Fatal("Accepted non-empty first item")
	}
}
