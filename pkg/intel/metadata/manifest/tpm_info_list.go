//go:generate manifestcodegen
package manifest

type TPM2PCRExtendPolicySupport uint8

const (
	TPM2PCRExtendIllegal                  TPM2PCRExtendPolicySupport = 0
	TPM2PCRExtendMaximumAgilityPolicy     TPM2PCRExtendPolicySupport = 1
	TPM2PCRExtendMaximumPerformancePolicy TPM2PCRExtendPolicySupport = 2
	TPM2PCRExtendBothPolicies             TPM2PCRExtendPolicySupport = 3
)

type TPMFamilySupport uint8

// PrettyString-true:  Discrete TPM1.2 is supported
// PrettyString-false: Discrete TPM1.2 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM12Supported() bool {
	return familySupport&1 != 0
}

// PrettyString-true:  Discrete TPM2.0 is supported
// PrettyString-false: Discrete TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM20Supported() bool {
	return familySupport&2 != 0
}

// PrettyString-true:  Firmware TPM2.0 is supported
// PrettyString-false: Firmware TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsFirmwareTPM20Supported() bool {
	return familySupport&(1<<3) != 0
}

type TPMCapabilities uint32

func (cap TPMCapabilities) TPM2PCRExtendPolicySupport() TPM2PCRExtendPolicySupport {
	return TPM2PCRExtendPolicySupport(cap & 3)
}

func (cap TPMCapabilities) TPMFamilySupport() TPMFamilySupport {
	return TPMFamilySupport((cap >> 2) & 15)
}

// TPMInfoList represents TPM capabilities supported by ACM
type TPMInfoList struct {
	Capabilities TPMCapabilities
	Algorithms   []Algorithm
}
