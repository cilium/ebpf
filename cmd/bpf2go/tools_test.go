package main

import (
	"reflect"
	"testing"
)

func TestSplitArguments(t *testing.T) {
	testcases := []struct {
		in  string
		out []string
	}{
		{`foo`, []string{"foo"}},
		{`foo bar`, []string{"foo", "bar"}},
		{`foo  bar`, []string{"foo", "bar"}},
		{`\\`, []string{`\`}},
		{`\\\`, nil},
		{`foo\ bar`, []string{"foo bar"}},
		{`foo "" bar`, []string{"foo", "", "bar"}},
		{`"bar baz"`, []string{"bar baz"}},
		{`'bar baz'`, []string{"bar baz"}},
		{`'bar " " baz'`, []string{`bar " " baz`}},
		{`"bar \" baz"`, []string{`bar " baz`}},
		{`"`, nil},
		{`'`, nil},
	}

	for _, testcase := range testcases {
		have, err := splitArguments(testcase.in)
		if testcase.out == nil {
			if err == nil {
				t.Errorf("Test should fail for: %s", testcase.in)
			}
		} else if !reflect.DeepEqual(testcase.out, have) {
			t.Logf("Have: %q\n", have)
			t.Logf("Want: %q\n", testcase.out)
			t.Errorf("Test fails for: %s", testcase.in)
		}
	}
}
