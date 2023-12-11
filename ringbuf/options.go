package ringbuf

type Callback func(raw []byte, remaining int)

type Option func(*Options)

type Options struct {
	cb Callback
}

func WithCallback(cb Callback) Option {
	return func(o *Options) {
		if cb != nil {
			o.cb = cb
		}
	}
}

func WithAsyncCallback(cb Callback) Option {
	return func(o *Options) {
		if cb != nil {
			o.cb = func(raw []byte, remaining int) {
				go cb(raw, remaining)
			}
		}
	}
}

func defaultOpts() *Options {
	return &Options{
		cb: func(raw []byte, remaining int) {}, // empty callback
	}
}
