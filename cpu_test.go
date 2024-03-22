package ebpf

import (
	"os"
	"path/filepath"
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

func TestParseCPUsFromFile(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		expectErr bool
		want      int
	}{
		{
			name:      "suitable_range_0_to_1",
			content:   "0-1",
			expectErr: false,
			want:      2,
		},
		{
			name:      "suitable_range_0_to_2",
			content:   "0-2\n",
			expectErr: false,
			want:      3,
		},
		{
			name:      "suitable_single_cpu",
			content:   "0",
			expectErr: false,
			want:      1,
		},
		{
			name:      "not_suitable_range_0_to_3-4",
			content:   "0,3-4",
			expectErr: true,
			want:      0,
		},
		{
			name:      "not_suitable_single_cpu",
			content:   "1,",
			expectErr: true,
			want:      0,
		},
		{
			name:      "not_suitable_incomplete_range",
			content:   "0-",
			expectErr: true,
			want:      0,
		},
		{
			name:      "not_suitable_empty",
			content:   "",
			expectErr: true,
			want:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			dir := t.TempDir()
			tmpFile := filepath.Join(dir, "cpu_test_"+tt.name)
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write to temporary file: %v", err)
			}
			defer os.Remove(tmpFile)

			got, err := parseCPUsFromFile(tmpFile)
			if tt.expectErr && err == nil {
				t.Error("expected an error, but got none")
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("unexpected result, got: %d, want: %d", got, tt.want)
			}
		})
	}
}
