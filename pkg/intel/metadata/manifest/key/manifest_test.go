package key

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest/common/unittest"
)

func TestReadWrite(t *testing.T) {
	unittest.ManifestReadWrite(t, &Manifest{}, "testdata/km.bin")
}
