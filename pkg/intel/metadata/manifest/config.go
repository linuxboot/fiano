// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

var (
	// StrictOrderCheck defines if elements order checks should be performed.
	// For example in the Boot Policy Manifest elements could be in a wrong
	// order. And we still can parse it, but in this way `*Offset` methods
	// could be confusing, since they will show the offset as they will
	// be written (not as they were parsed).
	//
	// We require a strict order because it is explicitly required
	// in the documentation #575623:
	//
	// > The order of the elements and the order of the fields within each
	// > element are architectural and must be followed.
	StrictOrderCheck = true
)
