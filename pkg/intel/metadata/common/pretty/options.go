// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pretty

type Option interface {
	apply(*config)
}

type OptionOmitKeySignature bool

func (opt OptionOmitKeySignature) apply(cfg *config) {
	cfg.OmitKeySignature = bool(opt)
}

type config struct {
	OmitKeySignature bool
}

func getConfig(opts []Option) config {
	var cfg config
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	return cfg
}
