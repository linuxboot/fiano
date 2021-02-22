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
