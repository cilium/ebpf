package internal

import (
	"testing"
)

func TestVersion(t *testing.T) {
	a, err := NewVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewVersion("2.2.1")
	if err != nil {
		t.Fatal(err)
	}

	if !a.Less(b) {
		t.Error("A should be less than B")
	}

	if b.Less(a) {
		t.Error("B shouldn't be less than A")
	}

	v200 := Version{2, 0, 0}
	if !a.Less(v200) {
		t.Error("1.2.1 should not be less than 2.0.0")
	}

	if v200.Less(a) {
		t.Error("2.0.0 should not be less than 1.2.1")
	}
}

func TestKernelVersion(t *testing.T) {
	// Kernels 4.4 and 4.9 have a SUBLEVEL of over 255 and clamp it to 255.
	// In our implementation, the other version segments are truncated.
	if v, want := (Version{256, 256, 256}), uint32(255); v.Kernel() != want {
		t.Errorf("256.256.256 should result in a kernel version of %d, got: %d", want, v.Kernel())
	}

	// Known good version.
	if v, want := (Version{4, 9, 128}), uint32(264576); v.Kernel() != want {
		t.Errorf("4.9.1 should result in a kernel version of %d, got: %d", want, v.Kernel())
	}
}

func TestVersionDetection(t *testing.T) {
	var tests = []struct {
		name string
		s    string
		v    Version
		err  bool
	}{
		{"ubuntu version_signature", "Ubuntu 4.15.0-91.92-generic 4.15.18", Version{4, 15, 18}, false},
		{"debian uname version", "#1 SMP Debian 4.19.37-5+deb10u2 (2019-08-08)", Version{4, 19, 37}, false},
		{"debian uname release (missing patch)", "4.19.0-5-amd64", Version{4, 19, 0}, false},
		{"debian uname all", "Linux foo 5.6.0-0.bpo.2-amd64 #1 SMP Debian 5.6.14-2~bpo10+1 (2020-06-09) x86_64 GNU/Linux", Version{5, 6, 14}, false},
		{"debian custom uname version", "#1577309 SMP Thu Dec 31 08:32:02 UTC 2020", Version{}, true},
		{"debian custom uname release (missing patch)", "4.19-ovh-xxxx-std-ipv6-64", Version{4, 19, 0}, false},
		{"arch uname version", "#1 SMP PREEMPT Thu, 11 Mar 2021 21:27:06 +0000", Version{}, true},
		{"arch uname release", "5.5.10-arch1-1", Version{5, 5, 10}, false},
		{"alpine uname version", "#1-Alpine SMP Thu Jan 23 10:58:18 UTC 2020", Version{}, true},
		{"alpine uname release", "4.14.167-0-virt", Version{4, 14, 167}, false},
		{"fedora uname version", "#1 SMP Tue May 14 18:22:28 UTC 2019", Version{}, true},
		{"fedora uname release", "5.0.16-100.fc28.x86_64", Version{5, 0, 16}, false},
		{"centos8 uname version", "#1 SMP Mon Mar 1 17:16:16 UTC 2021", Version{}, true},
		{"centos8 uname release", "4.18.0-240.15.1.el8_3.x86_64", Version{4, 18, 0}, false},
		{"devuan uname version", "#1 SMP Debian 4.19.181-1 (2021-03-19)", Version{4, 19, 181}, false},
		{"devuan uname release", "4.19.0-16-amd64", Version{4, 19, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := findKernelVersion(tt.s)
			if err != nil {
				if !tt.err {
					t.Error("unexpected error:", err)
				}
				return
			}

			if tt.err {
				t.Error("expected error, but got none")
			}

			if v != tt.v {
				t.Errorf("unexpected version for string '%s'. got: %v, want: %v", tt.s, v, tt.v)
			}
		})
	}
}
