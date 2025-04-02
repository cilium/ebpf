package pin

// Pin represents an object and its pinned path.
type Pin struct {
	Path   string
	Object Pinner
}

func (p *Pin) close() {
	if p.Object != nil {
		p.Object.Close()
	}
}

// Take ownership of Pin.Object.
//
// The caller is responsible for calling close on the [Pinner].
func (p *Pin) Take() Pinner {
	obj := p.Object
	p.Object = nil
	return obj
}
