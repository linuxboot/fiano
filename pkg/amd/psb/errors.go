package psb

import (
	"fmt"
	"strings"
)

// SignatureCheckError is an error type which indicates that signature of an element cannot be validated against its signing key
type SignatureCheckError struct {
	signingKey    KeyID
	signedElement string
	err           error
}

// Error returns the string representation of SignatureCheckError
func (m *SignatureCheckError) Error() string {
	var s strings.Builder
	fmt.Fprintf(&s, "signature of element %s does not validate against signing key %s: %s", m.signedElement, m.signingKey, m.err.Error())
	return s.String()
}
