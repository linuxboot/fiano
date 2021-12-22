package manifest

import (
	"encoding/json"
	"fmt"

	pspentries "github.com/orangecms/PSP-Entry-Types"
)

var knownTypes = pspentries.Types()

func (t BIOSDirectoryTableEntryType) MarshalJSON() ([]byte, error) {
	for _, knownType := range knownTypes {
		if knownType.Type == uint32(t) {
			name := knownType.Name
			if name == "" {
				name = knownType.ProposedName
			}
			if name == "" {
				return json.Marshal(fmt.Sprintf("0x%x", t))
			}
			return json.Marshal(name)
		}
	}
	return json.Marshal(fmt.Sprintf("0x%x", t))
}

/*
 TODO: extend information, also for PSPDirectoryTableEntry
func (e BIOSDirectoryTableEntry) MarshalJSON() json.RawMessage {
	info := TypeInfo{
	  Name:    name,
	  Comment: knownType.Comment,
	}
	entry.TypeInfo = &info
}
*/

func (t PSPDirectoryTableEntryType) MarshalJSON() ([]byte, error) {
	for _, knownType := range knownTypes {
		if knownType.Type == uint32(t) {
			name := knownType.Name
			if name == "" {
				name = knownType.ProposedName
			}
			if name == "" {
				return json.Marshal(fmt.Sprintf("0x%x", t))
			}
			return json.Marshal(name)
		}
	}
	return json.Marshal(fmt.Sprintf("0x%x", t))
}
