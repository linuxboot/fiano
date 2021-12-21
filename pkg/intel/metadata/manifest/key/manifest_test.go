package key

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/internal/unittest"
)

func TestReadWrite(t *testing.T) {
	unittest.ManifestReadWrite(t, &Manifest{}, "testdata/km.bin")
}
