package platform

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		native   string
		versions []string
		want     string
		wantErr  bool
	}{
		{
			name:    "no versions",
			goos:    Linux,
			native:  Linux,
			wantErr: true,
		},
		{
			name:     "android GOOS",
			goos:     "android",
			native:   Linux,
			versions: []string{"android:14"},
			want:     "14",
		},
		{
			name:     "android native platform",
			goos:     "android",
			native:   Linux,
			versions: []string{"linux:6.1"},
			want:     "6.1",
		},
		{
			name:     "android unprefixed Linux",
			goos:     "android",
			native:   Linux,
			versions: []string{"6.1"},
			want:     "6.1",
		},
		{
			name:     "android ignores Windows",
			goos:     "android",
			native:   Linux,
			versions: []string{"windows:0.20.0"},
		},
		{
			name:     "Linux",
			goos:     Linux,
			native:   Linux,
			versions: []string{"linux:6.1"},
			want:     "6.1",
		},
		{
			name:     "Windows",
			goos:     Windows,
			native:   Windows,
			versions: []string{"windows:0.20.0"},
			want:     "0.20.0",
		},
		{
			name:     "other GOOS",
			goos:     "darwin",
			versions: []string{"darwin:14"},
			want:     "14",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectVersion(test.goos, test.native, test.versions)
			if test.wantErr {
				qt.Assert(t, qt.IsNotNil(err))
				return
			}

			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(got, test.want))
		})
	}
}
