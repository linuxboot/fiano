package fit

// EntryType is a 7 bit field containing the type code for the component
// registered in the FIT table.
type EntryType uint8

//noinspection GoSnakeCaseUsage
const (
	EntryTypeFITHeaderEntry              = EntryType(0x00)
	EntryTypeMicrocodeUpdateEntry        = EntryType(0x01)
	EntryTypeStartupACModuleEntry        = EntryType(0x02)
	EntryTypeBIOSStartupModuleEntry      = EntryType(0x07)
	EntryTypeTPMPolicyRecord             = EntryType(0x08)
	EntryTypeBIOSPolicyRecord            = EntryType(0x09)
	EntryTypeTXTPolicyRecord             = EntryType(0x0A)
	EntryTypeKeyManifestRecord           = EntryType(0x0B)
	EntryTypeBootPolicyManifest          = EntryType(0x0C)
	EntryTypeCSESecureBoot               = EntryType(0x10)
	EntryTypeFeaturePolicyDeliveryRecord = EntryType(0x2D)
	EntryTypeJMP_DebugPolicy             = EntryType(0x2F)
	EntryTypeSkip                        = EntryType(0x7F)
)

func (_type EntryType) String() string {
	switch _type {
	case EntryTypeFITHeaderEntry:
		return "FIT_header_entry"
	case EntryTypeMicrocodeUpdateEntry:
		return "microcode_update_entry"
	case EntryTypeStartupACModuleEntry:
		return "startup_ACM_entry"
	case EntryTypeBIOSStartupModuleEntry:
		return "BIOS_startup_module_entry"
	case EntryTypeTPMPolicyRecord:
		return "TPM_policy_record"
	case EntryTypeBIOSPolicyRecord:
		return "BIOS_policy_record"
	case EntryTypeTXTPolicyRecord:
		return "TXT_policy_record"
	case EntryTypeKeyManifestRecord:
		return "key_manifest_record"
	case EntryTypeBootPolicyManifest:
		return "boot_policy_manifest"
	case EntryTypeCSESecureBoot:
		return "CSE_SecureBoot"
	case EntryTypeFeaturePolicyDeliveryRecord:
		return "feature_policy_delivery_record"
	case EntryTypeJMP_DebugPolicy:
		return "JMP__debug_policy"
	case EntryTypeSkip:
		return "skip_entry"
	}
	return "unknown_entry"
}
