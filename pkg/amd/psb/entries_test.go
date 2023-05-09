package psb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectoryType(t *testing.T) {
	require.Equal(t, allDirectoryTypes, AllDirectoryTypes())
	require.NotEmpty(t, allDirectoryTypes)

	for _, directory := range allDirectoryTypes {
		t.Run(directory.ShortName(), func(t *testing.T) {
			require.NotEmpty(t, directory.ShortName())
			require.NotEmpty(t, directory.String())
			resDirectory, err := DirectoryTypeFromString(strings.ToUpper(directory.ShortName()))
			require.NoError(t, err)
			require.Equal(t, directory, resDirectory)

			resDirectory, err = DirectoryTypeFromString(strings.ToLower(directory.ShortName()))
			require.NoError(t, err)
			require.Equal(t, directory, resDirectory)
		})
	}

	_, err := DirectoryTypeFromString("No such directory type")
	require.Error(t, err)
}
