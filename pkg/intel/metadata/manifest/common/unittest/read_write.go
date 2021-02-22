package unittest

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/stretchr/testify/require"
)

func ManifestReadWrite(t *testing.T, m manifest.Manifest, testDataFilePath string) {
	testData, err := ioutil.ReadFile(testDataFilePath)
	require.NoError(t, err)

	nR, err := m.ReadFrom(bytes.NewReader(append(testData, []byte(`extra bytes`)...)))
	require.NoError(t, err)
	require.Equal(t, int64(len(testData)), nR)
	require.Equal(t, nR, int64(m.TotalSize()))

	prettyString := m.PrettyString(0, true)

	var out bytes.Buffer
	nW, err := m.WriteTo(&out)
	require.NoError(t, err)

	newPrettyString := m.PrettyString(0, true)
	require.Equal(t, prettyString, newPrettyString, newPrettyString)
	require.Equal(t, string(testData), out.String())
	require.Equal(t, nW, nR)
	require.Equal(t, nW, int64(out.Len()))
}
