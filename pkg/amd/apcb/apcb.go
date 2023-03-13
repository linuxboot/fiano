package apcb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// APCB config consists of tokens, all tokens have the following attributes: ID, type, priority, boardMask, value
// ID - is token's unqique identifier. Note APCB config may contain multiple tokens with same ID. The used one is determined by priority and board
// Type - boolean, 1, 2 or 4 bytes value
// Priority - see PriorityLevel
// BoardMask - determines type of hardware for wich the token is aplicable
// Value - token's value according to its type
//
// Structure of APCB/APCB recovery config is the following:
// All tokens are grouped by a type, that has own TypeHeaderV3 followed by token pairs <ID, Value>.
// Each type contains tokens in a sorted order by their ID.
// All types are put into groups, that have GroupHeader followed by a number of 'types'
// Note that the groups have different purposes, the one with tokens should have a value of groupID = 0x3000
//
// Below is example of APCB header consisting of a single group with two types:
// | APCB header | group header | type header | <tokenID, tokenValue> ... | type header | <tokenID, tokenValue> ... |
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// TokenID is a unique token identifier
type TokenID uint32

// See: AgesaPkg/Addendum/Apcb/Inc/GN/ApcbV3TokenUid.h
const (
	TokenIDPSPMeasureConfig   TokenID = 0xDD3AD029
	TokenIDPSPEnableDebugMode TokenID = 0xD1091CD0
	TokenIDPSPErrorDisplay    TokenID = 0xDC33FF21
	TokenIDPSPStopOnError     TokenID = 0xE7024A21
)

// GetTokenIDString returns literal representation of known Token IDs otherwise an empty string
func GetTokenIDString(tokenID TokenID) string {
	switch tokenID {
	case TokenIDPSPMeasureConfig:
		return "APCB_TOKEN_UID_PSP_MEASURE_CONFIG"
	case TokenIDPSPEnableDebugMode:
		return "APCB_TOKEN_UID_PSP_ENABLE_DEBUG_MODE"
	case TokenIDPSPErrorDisplay:
		return "APCB_TOKEN_UID_PSP_ERROR_DISPLAY"
	case TokenIDPSPStopOnError:
		return "APCB_TOKEN_UID_PSP_STOP_ON_ERROR"
	}
	return ""
}

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

func (pl PriorityLevel) String() string {
	switch pl {
	case PriorityLevelHardForce:
		return "HardForce"
	case PriorityLevelHigh:
		return "High"
	case PriorityLevelMedium:
		return "Medium"
	case PriorityLevelEventLogging:
		return "EventLogging"
	case PriorityLevelLow:
		return "Low"
	case PriorityLevelDefault:
		return "Default"
	}
	return fmt.Sprintf("PriorityLevel_%d", pl)
}

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

func (m PriorityMask) String() string {
	var s strings.Builder
	for level := PriorityLevelHardForce; level <= PriorityLevelDefault; level++ {
		flag := uint8(1 << (uint8(level) - 1))
		if uint8(m)&flag != uint8(0) {
			if s.Len() > 0 {
				s.WriteString("|")
			}
			s.WriteString(level.String())
		}
	}
	if s.Len() == 0 {
		return "none"
	}
	return s.String()
}

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

	_, result, err := parseValue(t.Value)
	if err != nil {
		panic(fmt.Sprintf("unknown value type: %T", t.Value))
	}
	return result
}

// ParseAPCBBinaryTokens returns all tokens contained in the APCB Binary
func ParseAPCBBinaryTokens(apcbBinary []byte) ([]Token, error) {
	_, remainBytes, err := parseAPCBHeader(apcbBinary)
	if err != nil {
		return nil, err
	}

	// We should iterate through each groups->types and collect all the tokens we encounter
	var result []Token
	err = iterateTokenGroups(remainBytes, func(groupHeader groupHeader, groupOffset uint32) error {
		groupData := remainBytes[groupOffset+uint32(groupHeader.SizeOfHeader) : groupOffset+groupHeader.SizeOfGroup]
		return iterateTypes(groupData, func(typeHeader typeHeaderV3, typeOffset uint32) error {
			typeData := groupData[typeOffset+uint32(binary.Size(typeHeader)) : typeOffset+uint32(typeHeader.SizeOfType)]
			return iterateTokens(typeData, typeHeader, func(tokenPairOffset uint32, tp tokenPair) error {
				val, err := processValue(typeHeader.TypeID, tp.Value)
				if err != nil {
					return err
				}
				result = append(result, Token{
					ID:           tp.ID,
					PriorityMask: typeHeader.PriorityMask,
					BoardMask:    typeHeader.BoardMask,
					Value:        val,
				})
				return nil
			})
		})
	})
	return result, err
}

// UpsertToken inserts a new token or updates current into apcb binary
func UpsertToken(tokenID TokenID, priorityMask PriorityMask, boardMask uint16, newValue interface{}, apcbBinary []byte) error {
	typeID, numValue, err := parseValue(newValue)
	if err != nil {
		return err
	}
	header, remainBytes, err := parseAPCBHeader(apcbBinary)
	if err != nil {
		return err
	}

	// There are three ways to do that:
	// 1. We do already have a token with such ID/PriorityMask/BoardMask. Just - change the value of this token
	// 2. We do have a group with tokens. Try to find a Type of the inserted value, if there is one - place token there, otherwise create a new Type.
	// And place a new token with input tokenID and value in this type.
	// 3. We don't have a group with tokens. Create an approperiate group, type and place a new token in this type.
	// Not that APCB binary has conigues structure, so if one "inserts" something, one should not forged to shift the remaining bytes

	var (
		matchedGroupHeader *groupHeader
		matchedGroupOffset uint32
		matchedTypeHeader  *typeHeaderV3
		matchedTypeOffset  uint32
		matchedTokenOffset uint32
	)
	tokenBytesCount := uint32(binary.Size(tokenPair{}))

	var tokenChanged bool
	err = iterateTokenGroups(remainBytes, func(groupHeader groupHeader, groupOffset uint32) error {
		if matchedTypeHeader == nil {
			matchedGroupHeader = &groupHeader
			matchedGroupOffset = groupOffset
		}

		groupData := remainBytes[groupOffset+uint32(groupHeader.SizeOfHeader) : groupOffset+groupHeader.SizeOfGroup]
		return iterateTypes(groupData, func(typeHeader typeHeaderV3, typeOffset uint32) error {
			if typeID != typeHeader.TypeID || typeHeader.BoardMask&boardMask == 0 || typeHeader.PriorityMask&priorityMask == 0 {
				return nil
			}

			matchedGroupHeader = &groupHeader
			matchedGroupOffset = groupOffset
			matchedTypeHeader = &typeHeader
			matchedTypeOffset = typeOffset
			matchedTokenOffset = 0

			typeData := groupData[typeOffset+uint32(binary.Size(typeHeader)) : typeOffset+uint32(typeHeader.SizeOfType)]
			return iterateTokens(typeData, typeHeader, func(tokenPairOffset uint32, tp tokenPair) error {
				if tp.ID <= tokenID {
					matchedTokenOffset = tokenPairOffset + tokenBytesCount
				}
				if tp.ID != tokenID {
					return nil
				}
				newTokenPair := tp
				newTokenPair.Value = numValue

				if err := writeFixedBuffer(typeData[tokenPairOffset:], newTokenPair); err != nil {
					return err
				}
				tokenChanged = true
				return nil
			})
		})
	})
	if err != nil {
		return err
	}
	if tokenChanged {
		return nil
	}

	var (
		insertionOffset uint32
		addedBytes      uint32
		writeNewToken   func(wb io.Writer) error
	)

	// Add headers to offsets
	matchedGroupOffset += uint32(binary.Size(header))
	if matchedGroupHeader != nil {
		matchedTypeOffset += uint32(matchedGroupHeader.SizeOfHeader)
	}

	if matchedTypeHeader != nil {
		// case 1: There exists a type for a upserted token
		insertionOffset = matchedGroupOffset + matchedTypeOffset + uint32(binary.Size(matchedTypeHeader)) + matchedTokenOffset
		addedBytes = tokenBytesCount

		writeNewToken = func(wb io.Writer) error {
			newToken := tokenPair{
				ID:    tokenID,
				Value: numValue,
			}
			if err := binary.Write(wb, binary.LittleEndian, newToken); err != nil {
				return fmt.Errorf("failed to write inserted token pair: '%w'", err)
			}
			return nil
		}
	} else {
		if matchedGroupHeader != nil {
			// case 2: There exists a tokens group, but no type for upserted token
			insertionOffset = matchedGroupOffset + matchedGroupHeader.SizeOfGroup
			addedBytes, writeNewToken = constructNewTypeForToken(
				tokenID,
				priorityMask,
				boardMask,
				typeID,
				numValue,
			)
		} else {
			// case 3: We need to create a new tokens group with a new type and a new token
			insertionOffset = header.V2Header.SizeOfAPCB
			addedBytes, writeNewToken = constructNewGroupForToken(
				tokenID,
				priorityMask,
				boardMask,
				typeID,
				numValue,
			)
		}
	}

	if header.V2Header.SizeOfAPCB+addedBytes > uint32(len(apcbBinary)) {
		return fmt.Errorf(
			"impossible to insert a new token because apcb binary length is small, required: '%d', have: '%d'",
			header.V2Header.SizeOfAPCB+addedBytes,
			len(apcbBinary))
	}

	// we want to insert "addedBytes" bytes at insertionOffset that will invalidate all bytes after insertionOffset
	// so copy invalidated bytes first
	copy(apcbBinary[insertionOffset+addedBytes:], apcbBinary[insertionOffset:header.V2Header.SizeOfAPCB])
	if err := writeNewToken(newFixedSizeBuffer(apcbBinary[insertionOffset:])); err != nil {
		return err
	}

	// Fix sizes of touched elements
	if matchedTypeHeader != nil {
		matchedTypeHeader.SizeOfType += uint16(tokenBytesCount)
		if err := writeFixedBuffer(apcbBinary[matchedGroupOffset+matchedTypeOffset:], matchedTypeHeader); err != nil {
			return fmt.Errorf("failed to write inserted token pair: '%w'", err)
		}
	}
	if matchedGroupHeader != nil {
		matchedGroupHeader.SizeOfGroup += addedBytes
		if err := writeFixedBuffer(apcbBinary[matchedGroupOffset:], matchedGroupHeader); err != nil {
			return fmt.Errorf("failed to update token group: '%w'", err)
		}
	}
	header.V2Header.SizeOfAPCB += addedBytes
	if err := writeFixedBuffer(apcbBinary, header); err != nil {
		return fmt.Errorf("failed to update APCB binary header: '%w'", err)
	}
	return nil
}

func constructNewTypeForToken(
	tokenID TokenID,
	priorityMask PriorityMask,
	boardMask uint16,
	typeID tokenType,
	value uint32,
) (uint32, func(wb io.Writer) error) {
	newTypeHeader := typeHeaderV3{
		GroupID:       tokensGroupID,
		TypeID:        typeID,
		InstanceID:    0,
		ContextType:   tokenV3ContextType,
		ContextFormat: sortAscByUnitSizeContextFormat,
		BoardMask:     boardMask,
		PriorityMask:  priorityMask,
		UnitSize:      8, // hardcode for tokenV3ContextType
		KeySize:       uint8(binary.Size(tokenID)),
		KeyPos:        0,
	}
	newToken := tokenPair{
		ID:    tokenID,
		Value: value,
	}
	newTokenBytesCount := uint32(binary.Size(newToken))
	newTypeHeader.SizeOfType = uint16(binary.Size(newTypeHeader)) + uint16(newTokenBytesCount)

	return uint32(newTypeHeader.SizeOfType), func(wb io.Writer) error {
		if err := binary.Write(wb, binary.LittleEndian, newTypeHeader); err != nil {
			return fmt.Errorf("failed to write inserted type: '%w'", err)
		}
		if err := binary.Write(wb, binary.LittleEndian, newToken); err != nil {
			return fmt.Errorf("failed to write inserted token pair: '%w'", err)
		}
		return nil
	}
}

func constructNewGroupForToken(
	tokenID TokenID,
	priorityMask PriorityMask,
	boardMask uint16,
	typeID tokenType,
	value uint32,
) (uint32, func(wb io.Writer) error) {
	newTypeLength, insertNewTypeWithToken := constructNewTypeForToken(
		tokenID,
		priorityMask,
		boardMask,
		typeID,
		value,
	)
	newGroupHeader := groupHeader{
		Signature: tokenGroupSignature,
		GroupID:   tokensGroupID,
		Version:   1,
	}
	newGroupHeader.SizeOfHeader = uint16(binary.Size(newGroupHeader))
	newGroupHeader.SizeOfGroup = uint32(newGroupHeader.SizeOfHeader) + newTypeLength

	return newGroupHeader.SizeOfGroup, func(wb io.Writer) error {
		if err := binary.Write(wb, binary.LittleEndian, newGroupHeader); err != nil {
			return fmt.Errorf("failed to write inserted token pair: '%w'", err)
		}
		if err := insertNewTypeWithToken(wb); err != nil {
			return err
		}
		return nil
	}
}

func parseAPCBHeader(apcbBinary []byte) (headerV3, []byte, error) {
	var header headerV3
	if err := binary.Read(bytes.NewBuffer(apcbBinary), binary.LittleEndian, &header); err != nil {
		return header, nil, fmt.Errorf("failed to read input header: %w", err)
	}

	if header.V2Header.Signature != headerV2Signature {
		return header, nil, fmt.Errorf(
			"APCB header v2 signature mismatch, got '0x%X', expected: '0x%X'",
			header.V2Header.Signature, headerV2Signature)
	}
	if header.Signature2 != headerV3Signature {
		return header, nil, fmt.Errorf(
			"APCB header v3 signature mismatch, got '0x%X', expected: '0x%X'",
			header.Signature2, headerV3Signature)
	}
	if header.SignatureEnding != headerV3EndingSignature {
		return header, nil, fmt.Errorf(
			"APCB header v3 signature ending mismatch, got '0x%X', expected: '0x%X'",
			header.Signature2, headerV3EndingSignature)
	}

	if header.V2Header.SizeOfAPCB > uint32(len(apcbBinary)) {
		return header, nil, fmt.Errorf("input buffer '%d' is smaller than expected APCB size '%d'",
			len(apcbBinary), header.V2Header.SizeOfAPCB)
	}

	if uint32(len(apcbBinary)) < header.V2Header.SizeOfAPCB {
		return header, nil, fmt.Errorf(
			"invalid apcb binary header, expected size of APCB is %d, but having only %d",
			header.V2Header.SizeOfAPCB,
			len(apcbBinary),
		)
	}

	return header, apcbBinary[uint32(binary.Size(header)):header.V2Header.SizeOfAPCB], nil
}

// See: AgesaModulePkg/Library/ApcbLibV3/CoreApcbInterface.c
func iterateTokenGroups(apcbBody []byte, onGroupFound func(groupHeader groupHeader, offset uint32) error) error {
	groupHeaderSize := uint32(binary.Size(groupHeader{}))

	var offset uint32
	remainBytes := apcbBody
	for len(remainBytes) > 0 {
		var groupHeader groupHeader
		if err := binary.Read(bytes.NewReader(remainBytes), binary.LittleEndian, &groupHeader); err != nil {
			return fmt.Errorf("failed to read group header: '%v'", err)
		}
		if groupHeader.SizeOfGroup < groupHeaderSize {
			return fmt.Errorf("size of group is less than size of group header: %d < %d", groupHeader.SizeOfGroup, groupHeaderSize)
		}
		if groupHeader.SizeOfGroup > uint32(len(remainBytes)) {
			return fmt.Errorf("size of group exceeds the length of remaining data '%d' > '%d'", groupHeader.SizeOfGroup, len(remainBytes))
		}
		if groupHeader.GroupID == tokensGroupID {
			if err := onGroupFound(groupHeader, offset); err != nil {
				return err
			}
		}
		offset += groupHeader.SizeOfGroup
		remainBytes = remainBytes[groupHeader.SizeOfGroup:]
	}
	return nil
}

func iterateTypes(group []byte, onTypeFound func(typeHeader typeHeaderV3, offset uint32) error) error {
	typeHeaderSize := uint16(binary.Size(typeHeaderV3{}))

	var offset uint32
	remainBytes := group
	for len(remainBytes) > 0 {
		var typeHeader typeHeaderV3
		if err := binary.Read(bytes.NewReader(remainBytes), binary.LittleEndian, &typeHeader); err != nil {
			return fmt.Errorf("failed to read type header: '%v'", err)
		}
		if typeHeader.SizeOfType < typeHeaderSize {
			return fmt.Errorf("size of type is less than size of type header: %d < %d", typeHeader.SizeOfType, typeHeaderSize)
		}
		if typeHeader.SizeOfType > uint16(len(remainBytes)) {
			return fmt.Errorf("size of type '%d' is bigger than bytes left '%d'", typeHeader.SizeOfType, uint16(len(remainBytes)))
		}
		if err := onTypeFound(typeHeader, offset); err != nil {
			return err
		}

		offset += uint32(typeHeader.SizeOfType)
		remainBytes = remainBytes[typeHeader.SizeOfType:]
	}
	return nil
}

func iterateTokens(typeData []byte, typeHeader typeHeaderV3, onTokenFound func(offset uint32, tp tokenPair) error) error {
	tokenPairSize := binary.Size(tokenPair{})
	if len(typeData)%tokenPairSize != 0 {
		return fmt.Errorf("incorrect APCB type header SizeOfType: '%d'", typeHeader.SizeOfType)
	}

	b := bytes.NewReader(typeData)
	tokensCount := len(typeData) / tokenPairSize
	for i := 0; i < tokensCount; i++ {
		var token tokenPair
		if err := binary.Read(b, binary.LittleEndian, &token); err != nil {
			return fmt.Errorf("failed to read token pair: '%v'", err)
		}
		if err := onTokenFound(uint32(i*tokenPairSize), token); err != nil {
			return err
		}
	}
	return nil
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

func parseValue(v interface{}) (tokenType, uint32, error) {
	switch value := v.(type) {
	case bool:
		if value {
			return booleanTokenType, 1, nil
		}
		return booleanTokenType, 0, nil
	case uint8:
		return oneByteTokenType, uint32(value), nil
	case uint16:
		return twoBytesTokenType, uint32(value), nil
	case uint32:
		return fourBytesTokenType, value, nil
	}
	return 0, 0, fmt.Errorf("unknown type: '%T'", v)
}

type fixedSizeBuffer struct {
	buffer []byte
	offset int
}

func newFixedSizeBuffer(buf []byte) io.Writer {
	return &fixedSizeBuffer{buffer: buf}
}

func (fb *fixedSizeBuffer) Write(p []byte) (int, error) {
	remain := fb.buffer[fb.offset:]
	n := copy(remain, p)
	fb.offset += n
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func writeFixedBuffer(buf []byte, v interface{}) error {
	return binary.Write(newFixedSizeBuffer(buf), binary.LittleEndian, v)
}
