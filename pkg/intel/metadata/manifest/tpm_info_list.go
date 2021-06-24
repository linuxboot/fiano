//go:generate manifestcodegen

package manifest

// TPM2PCRExtendPolicySupport defined TPM2 PCR Extend policy support.
type TPM2PCRExtendPolicySupport uint8

// Possible values of TPM2PCRExtendPolicySupport
const (
	TPM2PCRExtendIllegal                  TPM2PCRExtendPolicySupport = 0
	TPM2PCRExtendMaximumAgilityPolicy     TPM2PCRExtendPolicySupport = 1
	TPM2PCRExtendMaximumPerformancePolicy TPM2PCRExtendPolicySupport = 2
	TPM2PCRExtendBothPolicies             TPM2PCRExtendPolicySupport = 3
)

// TPMFamilySupport defines TPM family support
type TPMFamilySupport uint8

// IsDiscreteTPM12Supported returns true if discrete TPM1.2 is supported.
// PrettyString-true:  Discrete TPM1.2 is supported
// PrettyString-false: Discrete TPM1.2 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM12Supported() bool {
	return familySupport&1 != 0
}

// IsDiscreteTPM20Supported returns true if discrete TPM2.0 is supported.
// PrettyString-true:  Discrete TPM2.0 is supported
// PrettyString-false: Discrete TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM20Supported() bool {
	return familySupport&2 != 0
}

// IsFirmwareTPM20Supported returns true if firmware TPM2.0 is supported.
// PrettyString-true:  Firmware TPM2.0 is supported
// PrettyString-false: Firmware TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsFirmwareTPM20Supported() bool {
	return familySupport&(1<<3) != 0
}

// TPMCapabilities defines TPM capabilities
type TPMCapabilities uint32

// TPM2PCRExtendPolicySupport returns TPM2PCRExtendPolicySupport
func (cap TPMCapabilities) TPM2PCRExtendPolicySupport() TPM2PCRExtendPolicySupport {
	return TPM2PCRExtendPolicySupport(cap & 3)
}

// TPMFamilySupport returns TPMFamilySupport
func (cap TPMCapabilities) TPMFamilySupport() TPMFamilySupport {
	return TPMFamilySupport((cap >> 2) & 15)
}

// TPMInfoList represents TPM capabilities supported by ACM
type TPMInfoList struct {
	Capabilities TPMCapabilities
	Algorithms   []Algorithm
}
