// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"
)

// ErrArgs means arguments are invalid
type ErrArgs struct {
	Err error
}

func (err ErrArgs) Error() string {
	return fmt.Sprintf("invalid arguments: %v", err.Err)
}

func (err ErrArgs) Unwrap() error {
	return err.Err
}
