// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package apcb

import (
	"bytes"
	"encoding/binary"
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
	require.NotEmpty(t, apcbBinary)

	tokens, err := ParseAPCBBinaryTokens(apcbBinary)
	require.NoError(t, err)
	require.Len(t, tokens, 40)

	token := findToken(0x3E7D5274, tokens)
	require.NotNil(t, token)
	require.Equal(t, CreatePriorityMask(PriorityLevelMedium), token.PriorityMask)
	require.Equal(t, uint16(0xFFFF), token.BoardMask)
	require.Equal(t, uint32(2044), token.Value)
	require.Equal(t, uint32(2044), token.NumValue())

	token = findToken(0xE1CC135E, tokens)
	require.NotNil(t, token)
	require.Equal(t, CreatePriorityMask(PriorityLevelMedium), token.PriorityMask)
	require.Equal(t, uint16(0xFFFF), token.BoardMask)
	require.Equal(t, false, token.Value)
	require.Equal(t, uint32(0), token.NumValue())
}

func TestUpsertToken(t *testing.T) {
	t.Run("update_existing_token", func(t *testing.T) {
		apcbBinary, err := getFile("apcb_binary.xz")
		require.NoError(t, err)
		require.NotEmpty(t, apcbBinary)

		require.NoError(t, UpsertToken(0x3E7D5274, 0xff, 0xffff, uint32(0xffffffff), apcbBinary))

		tokens, err := ParseAPCBBinaryTokens(apcbBinary)
		require.NoError(t, err)
		require.Len(t, tokens, 40)

		token := findToken(0x3E7D5274, tokens)
		require.NotNil(t, token)
		require.Equal(t, uint32(0xffffffff), token.NumValue())
	})

	t.Run("insert_new_token", func(t *testing.T) {
		apcbBinary, err := getFile("apcb_binary.xz")
		require.NoError(t, err)
		require.NotEmpty(t, apcbBinary)

		require.NoError(t, UpsertToken(0xFFFFAAAA, 0xff, 0xffff, uint32(0xffffffff), apcbBinary))

		tokens, err := ParseAPCBBinaryTokens(apcbBinary)
		require.NoError(t, err)
		require.Len(t, tokens, 41)

		token := findToken(0xFFFFAAAA, tokens)
		require.NotNil(t, token)
		require.Equal(t, uint32(0xffffffff), token.NumValue())
	})

	t.Run("insert_new_token_no_type", func(t *testing.T) {
		apcbBinary, err := getFile("apcb_binary.xz")
		require.NoError(t, err)
		require.NotEmpty(t, apcbBinary)

		h, _, err := parseAPCBHeader(apcbBinary)
		require.NoError(t, err)
		h.V2Header.SizeOfAPCB = uint32(binary.Size(h))

		resultBuffer := make([]byte, binary.Size(h)+1000)
		require.NoError(t, writeFixedBuffer(resultBuffer, h))
		tokens, err := ParseAPCBBinaryTokens(resultBuffer)
		require.NoError(t, err)
		require.Empty(t, tokens)

		require.NoError(t, UpsertToken(0xFFFFAAAA, 0xff, 0xffff, uint32(0xffffffff), resultBuffer))

		tokens, err = ParseAPCBBinaryTokens(resultBuffer)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		require.NoError(t, UpsertToken(0xFFFFBBBB, 0xff, 0xffff, bool(true), resultBuffer))
		tokens, err = ParseAPCBBinaryTokens(resultBuffer)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
	})
}

func findToken(tokenID TokenID, tokens []Token) *Token {
	for _, token := range tokens {
		if token.ID == tokenID {
			return &token
		}
	}
	return nil
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
