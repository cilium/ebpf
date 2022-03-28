package asm

// Metadata contains metadata about an instruction.
type Metadata struct {
	head *metaElement
}

type metaElement struct {
	next       *metaElement
	key, value interface{}
}

func (me *metaElement) find(key interface{}) *metaElement {
	for e := me; e != nil; e = e.next {
		if e.key == key {
			return e
		}
	}
	return nil
}

// Set a value to the metadata set.
//
// If value is nil, the key is removed. Avoids modifying old metadata by
// copying if necessary.
func (m *Metadata) Set(key, value interface{}) {
	switch e := m.head.find(key); {
	case e == nil:
		// Key is not present, simply prepend it to the list.
		if value != nil {
			m.head = &metaElement{key: key, value: value, next: m.head}
		}
		return

	case e.value == value:
		// Key is present and the value is the same. Nothing to do.
		return

	case e == m.head:
		// Key is present with a different value, at the head position.
		// Use the tail without copying.
		if value != nil {
			m.head = &metaElement{key: key, value: value, next: m.head.next}
		} else {
			m.head = m.head.next
		}
		return
	}

	// There is no such key, or the value is different.
	// Create a copy and overwrite the entry for key.
	var (
		head *metaElement
		prev = &head
	)
	for e := m.head; e != nil; e = e.next {
		if e.key == key {
			// Don't copy an element we'll replace.
			continue
		}

		cpy := &metaElement{key: e.key, value: e.value}
		*prev = cpy
		prev = &cpy.next
	}

	if value != nil {
		m.head = &metaElement{key: key, value: value, next: head}
	} else {
		m.head = head
	}
}

// Get a value from the metadata set.
//
// Returns nil if no value with the given key is present.
func (m *Metadata) Get(key interface{}) interface{} {
	if e := m.head.find(key); e != nil {
		return e.value
	}
	return nil
}
