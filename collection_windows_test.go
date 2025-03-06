package ebpf

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestLoadNativeImage(t *testing.T) {
	for _, tc := range []struct {
		file     string
		maps     []string
		programs []string
	}{
		{
			"testdata/windows/cgroup_sock_addr.sys",
			[]string{
				"egress_connection_policy_map",
				"ingress_connection_policy_map",
				"socket_cookie_map",
			},
			[]string{
				"authorize_connect4",
				"authorize_connect6",
				"authorize_recv_accept4",
				"authorize_recv_accept6",
			},
		},
	} {
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			coll, err := LoadCollection(tc.file)
			qt.Assert(t, qt.IsNil(err))
			defer coll.Close()

			var mapNames []string
			for name, obj := range coll.Maps {
				qt.Assert(t, qt.Equals(obj.name, name))
				mapNames = append(mapNames, name)
			}
			sort.Strings(mapNames)
			qt.Assert(t, qt.DeepEquals(mapNames, tc.maps))

			var programNames []string
			for name, obj := range coll.Programs {
				qt.Assert(t, qt.Equals(obj.name, name))
				programNames = append(programNames, name)
			}
			sort.Strings(programNames)
			qt.Assert(t, qt.DeepEquals(programNames, tc.programs))
		})
	}
}
