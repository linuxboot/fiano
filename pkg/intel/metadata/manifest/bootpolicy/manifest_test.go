package bootpolicy

import (
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/unittest"
)

func TestReadWrite(t *testing.T) {
	unittest.ManifestReadWrite(t, &Manifest{}, "testdata/bpm.bin")
}
