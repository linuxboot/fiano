package apcb

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func TestParsingTokens(t *testing.T) {
	apcbBinary, err := getFile("apcb_binary.xz")
	require.NoError(t, err)
	require.NotNil(t, apcbBinary)

	tokens, err := ParseAPCBBinaryTokens(apcbBinary)
	require.NoError(t, err)
	require.Len(t, tokens, 40)

	findToken := func(tokenID TokenID) *Token {
		for _, token := range tokens {
			if token.ID == tokenID {
				return &token
			}
		}
		return nil
	}

	token := findToken(0x3E7D5274)
	require.NotNil(t, token)
	require.Equal(t, CreatePriorityMask(PriorityLevelMedium), token.PriorityMask)
	require.Equal(t, uint16(0xFFFF), token.BoardMask)
	require.Equal(t, uint32(2044), token.Value)
	require.Equal(t, uint32(2044), token.NumValue())

	token = findToken(0xE1CC135E)
	require.NotNil(t, token)
	require.Equal(t, CreatePriorityMask(PriorityLevelMedium), token.PriorityMask)
	require.Equal(t, uint16(0xFFFF), token.BoardMask)
	require.Equal(t, false, token.Value)
	require.Equal(t, uint32(0), token.NumValue())
}

func getFile(filename string) ([]byte, error) {
	compressedImage, err := ioutil.ReadFile(path.Join("testdata", filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read firmware image: %w", err)
	}

	r, err := xz.NewReader(bytes.NewReader(compressedImage))
	if err != nil {
		return nil, fmt.Errorf("unable to create an xz reader for a cached image: %w", err)
	}

	decompressedImage, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("unable to decompress the image: %w", err)
	}

	return decompressedImage, nil
}
