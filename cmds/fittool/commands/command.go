// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package commands

import (
	"github.com/jessevdk/go-flags"
)

// Command is an interface of implementations of verbs
// (like "add", "remove" etc of "fittool add"/"fittool remove")
type Command interface {
	flags.Commander

	// ShortDescription explains what this command does in one line
	ShortDescription() string

	// LongDescription explains what this verb does (without limitation in amount of lines)
	LongDescription() string
}
