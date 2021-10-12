package apcb

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TokenID is a unique token identifier
type TokenID uint32

// See: AgesaPkg/Addendum/Apcb/Inc/GN/ApcbV3TokenUid.h
const (
	TokenIDPSPMeasureConfig   TokenID = 0xDD3AD029
	TokenIDPSPEnableDebugMode TokenID = 0xD1091CD0
	TokenIDPSPErrorDisplay    TokenID = 0xDC33FF21
	TokenIDPSPStopOnError     TokenID = 0xE7024A21
)

// See: AgesaPkg/Addendum/Apcb/Inc/CommonV3/ApcbV3Priority.h

// An APCB token may be saved in different instances or purpose levels and can have instances of the token at
// multiple purpose levels. These purpose levels provide a hierarchy of priority such that a token entry at one
// purpose level can be added to override the same token value set at a lower purpose level. The classic example is
// a priority system such that ADMIN -> DEBUGGING -> NORMAL, which means something occurring at a
// higher priority level would override another at a lower one. If the user set a token to TRUE at the debugging
// level and set the same one to FALSE at the normal level, the token readout would be TRUE. The intent is that a
// token can be temporarily changed for debug or evaluation; but should eventually be migrated to the 'Normal'
// purpose.

// PriorityLevel describes APCB BInary token priority level (APCB_PRIORITY_LEVEL in AGESA source code)
type PriorityLevel uint8

// Defines existing APCB token priority levels
const (
	PriorityLevelHardForce    PriorityLevel = 1
	PriorityLevelHigh         PriorityLevel = 2
	PriorityLevelMedium       PriorityLevel = 3
	PriorityLevelEventLogging PriorityLevel = 4
	PriorityLevelLow          PriorityLevel = 5
	PriorityLevelDefault      PriorityLevel = 6
)

// PriorityMask specifies a combined set of APCBPriorityLevels
type PriorityMask uint8

// CreatePriorityMask combines PriorityLevel into a APCBPriorityMask
func CreatePriorityMask(levels ...PriorityLevel) PriorityMask {
	var result uint8
	for _, l := range levels {
		result |= 1 << (uint8(l) - 1)
	}
	return PriorityMask(result)
}

// Token represents an APCB token
type Token struct {
	ID           TokenID
	PriorityMask PriorityMask
	BoardMask    uint16
	Value        interface{} // One of the following bool, uint8, uint16, uint32
}

// NumValue returns Token's value as uint32
func (t Token) NumValue() uint32 {
	if t.Value == nil {
		panic("Value is nil")
	}

	switch v := t.Value.(type) {
	case bool:
		if v {
			return 1
		}
		return 0
	case uint8:
		return uint32(v)
	case uint16:
		return uint32(v)
	case uint32:
		return v
	}
	panic(fmt.Sprintf("unknown value type: %T", t.Value))
}

// ParseAPCBBinaryTokens returns all tokens contained in the APCB Binary
func ParseAPCBBinaryTokens(apcbBinary []byte) ([]Token, error) {
	var header headerV3
	if err := binary.Read(bytes.NewBuffer(apcbBinary), binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read input header: %w", err)
	}

	if header.V2Header.Signature != headerV2Signature {
		return nil, fmt.Errorf(
			"APCB header v2 signature mismatch, got '0x%X', expected: '0x%X'",
			header.V2Header.Signature, headerV2Signature)
	}
	if header.Signature2 != headerV3Signature {
		return nil, fmt.Errorf(
			"APCB header v3 signature mismatch, got '0x%X', expected: '0x%X'",
			header.Signature2, headerV3Signature)
	}
	if header.SignatureEnding != headerV3EndingSignature {
		return nil, fmt.Errorf(
			"APCB header v3 signature ending mismatch, got '0x%X', expected: '0x%X'",
			header.Signature2, headerV3EndingSignature)
	}

	if header.V2Header.SizeOfAPCB > uint32(len(apcbBinary)) {
		return nil, fmt.Errorf("input buffer '%d' is smaller than expected APCB size '%d'",
			len(apcbBinary), header.V2Header.SizeOfAPCB)
	}

	remainBytes := apcbBinary[uint32(binary.Size(header)):header.V2Header.SizeOfAPCB]
	groupHeaderSize := uint32(binary.Size(groupHeader{}))

	var result []Token
	for len(remainBytes) > 0 {
		var groupHeader groupHeader
		if err := binary.Read(bytes.NewBuffer(remainBytes), binary.LittleEndian, &groupHeader); err != nil {
			return nil, fmt.Errorf("failed to read group header: '%v'", err)
		}
		if groupHeader.SizeOfGroup < groupHeaderSize {
			return nil, fmt.Errorf("size of group is less than size of group header: %d < %d", groupHeader.SizeOfGroup, groupHeaderSize)
		}
		if groupHeader.SizeOfGroup > uint32(len(remainBytes)) {
			return nil, fmt.Errorf("size of group exceeds the length of remaining data")
		}
		if groupHeader.GroupID == tokensGroupID {
			groupTokens, err := parseAPCBBinaryGroupTokens(remainBytes[groupHeaderSize:groupHeader.SizeOfGroup])
			if err != nil {
				return nil, err
			}
			result = append(result, groupTokens...)
		}
		remainBytes = remainBytes[groupHeader.SizeOfGroup:]
	}

	return result, nil
}

// See: AgesaModulePkg/Library/ApcbLibV3/CoreApcbInterface.c
func parseAPCBBinaryGroupTokens(group []byte) ([]Token, error) {
	tokenPairSize := uint16(binary.Size(tokenPair{}))
	typeHeaderSize := uint16(binary.Size(typeHeaderV3{}))
	b := bytes.NewBuffer(group)

	var result []Token
	for b.Len() > 0 {
		var typeHeader typeHeaderV3
		if err := binary.Read(b, binary.LittleEndian, &typeHeader); err != nil {
			return nil, fmt.Errorf("failed to read type header: '%v'", err)
		}
		if typeHeader.SizeOfType < typeHeaderSize {
			return nil, fmt.Errorf("size of type is less than size of type header: %d < %d", typeHeader.SizeOfType, typeHeaderSize)
		}

		dataSize := typeHeader.SizeOfType - typeHeaderSize
		if dataSize%tokenPairSize != 0 {
			return nil, fmt.Errorf("incorrect APCB type header SizeOfType: '%d'", typeHeader.SizeOfType)
		}

		tokensCount := int(dataSize / tokenPairSize)
		for i := 0; i < tokensCount; i++ {
			var token tokenPair
			if err := binary.Read(b, binary.LittleEndian, &token); err != nil {
				return nil, fmt.Errorf("failed to read token pair: '%v'", err)
			}
			val, err := processValue(typeHeader.TypeID, token.Value)
			if err != nil {
				return nil, err
			}
			result = append(result, Token{
				ID:           token.ID,
				PriorityMask: typeHeader.PriorityMask,
				BoardMask:    typeHeader.BoardMask,
				Value:        val,
			})
		}
	}
	return result, nil
}

func processValue(tokenType tokenType, val uint32) (interface{}, error) {
	switch tokenType {
	case booleanTokenType:
		return val&1 != 0, nil
	case oneByteTokenType:
		return uint8(val & 0xff), nil
	case twoBytesTokenType:
		return uint16(val & 0xffff), nil
	case fourBytesTokenType:
		return val, nil
	}
	return nil, fmt.Errorf("unknown token type: '%d'", tokenType)
}
