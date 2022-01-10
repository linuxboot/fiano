// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// EntryType is a 7 bit field containing the type code for the component
// registered in the FIT table.
type EntryType uint8

//noinspection GoSnakeCaseUsage
const (
	EntryTypeFITHeaderEntry              = EntryType(0x00)
	EntryTypeMicrocodeUpdateEntry        = EntryType(0x01)
	EntryTypeStartupACModuleEntry        = EntryType(0x02)
	EntryTypeDiagnosticACModuleEntry     = EntryType(0x03)
	EntryTypeBIOSStartupModuleEntry      = EntryType(0x07)
	EntryTypeTPMPolicyRecord             = EntryType(0x08)
	EntryTypeBIOSPolicyRecord            = EntryType(0x09)
	EntryTypeTXTPolicyRecord             = EntryType(0x0A)
	EntryTypeKeyManifestRecord           = EntryType(0x0B)
	EntryTypeBootPolicyManifest          = EntryType(0x0C)
	EntryTypeCSESecureBoot               = EntryType(0x10)
	EntryTypeFeaturePolicyDeliveryRecord = EntryType(0x2D)
	EntryTypeJMPDebugPolicy              = EntryType(0x2F)
	EntryTypeSkip                        = EntryType(0x7F)
)

// String implements fmt.Stringer
func (_type EntryType) String() string {
	if goType, ok := entryTypeIDToGo[_type]; ok {
		name := goType.Name()
		if strings.HasPrefix(name, "Entry") {
			return name[len("Entry"):]
		}
		return name
	}

	return fmt.Sprintf("unknown_entry_0x%X", uint8(_type))
}

var (
	entryTypeIDToGo = map[EntryType]reflect.Type{}
	entryTypeGoToID = map[reflect.Type]EntryType{}
)

func goTypeOfEntry(entry Entry) reflect.Type {
	return reflect.Indirect(reflect.ValueOf(entry)).Type()
}

// RegisterEntryType adds a new FIT entry type to the registry of known entry types.
func RegisterEntryType(entryTypeID EntryType, entryGoType Entry) {
	if goType, ok := entryTypeIDToGo[entryTypeID]; ok {
		delete(entryTypeIDToGo, entryTypeID)
		delete(entryTypeGoToID, goType)
	}

	goType := goTypeOfEntry(entryGoType)
	entryTypeIDToGo[entryTypeID] = goType
	entryTypeGoToID[goType] = entryTypeID
}

func init() {
	RegisterEntryType(EntryTypeFITHeaderEntry, &EntryFITHeaderEntry{})
	RegisterEntryType(EntryTypeMicrocodeUpdateEntry, &EntryMicrocodeUpdateEntry{})
	RegisterEntryType(EntryTypeStartupACModuleEntry, &EntrySACM{})
	RegisterEntryType(EntryTypeDiagnosticACModuleEntry, &EntryDiagnosticACM{})
	RegisterEntryType(EntryTypeBIOSStartupModuleEntry, &EntryBIOSStartupModuleEntry{})
	RegisterEntryType(EntryTypeTPMPolicyRecord, &EntryTPMPolicyRecord{})
	RegisterEntryType(EntryTypeBIOSPolicyRecord, &EntryBIOSPolicyRecord{})
	RegisterEntryType(EntryTypeTXTPolicyRecord, &EntryTXTPolicyRecord{})
	RegisterEntryType(EntryTypeKeyManifestRecord, &EntryKeyManifestRecord{})
	RegisterEntryType(EntryTypeBootPolicyManifest, &EntryBootPolicyManifestRecord{})
	RegisterEntryType(EntryTypeCSESecureBoot, &EntryCSESecureBoot{})
	RegisterEntryType(EntryTypeFeaturePolicyDeliveryRecord, &EntryFeaturePolicyDeliveryRecord{})
	RegisterEntryType(EntryTypeJMPDebugPolicy, &EntryJMPDebugPolicy{})
	RegisterEntryType(EntryTypeSkip, &EntrySkip{})
}

// newEntry returns a new empty entry instance of a registered type.
func (_type EntryType) newEntry() Entry {
	goType, ok := entryTypeIDToGo[_type]
	if !ok {
		return nil
	}

	entry := reflect.New(goType).Interface().(Entry)
	return entry
}

// entryTypeOf returns EntryType based on variable type (in contrast to
// reading it from the headers).
func entryTypeOf(entry Entry) (EntryType, bool) {
	entryTypeID, ok := entryTypeGoToID[goTypeOfEntry(entry)]
	return entryTypeID, ok
}

func AllEntryTypes() []EntryType {
	result := make([]EntryType, 0, len(entryTypeIDToGo))
	for entryType := range entryTypeIDToGo {
		result = append(result, entryType)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}
