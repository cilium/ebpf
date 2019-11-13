package btf

import "github.com/pkg/errors"

// Section is the BTF information for a stream of instructions.
type Section struct {
	spec                 *Spec
	length               uint64
	funcInfos, lineInfos extInfo
}

// Spec returns the spec required for this Section.
func (s *Section) Spec() *Spec {
	return s.spec
}

// Append the information from other to the Program.
func (s *Section) Append(other *Section) error {
	funcInfos, err := s.funcInfos.append(other.funcInfos, s.length)
	if err != nil {
		return errors.Wrap(err, "func infos")
	}

	lineInfos, err := s.lineInfos.append(other.lineInfos, s.length)
	if err != nil {
		return errors.Wrap(err, "line infos")
	}

	s.length += other.length
	s.funcInfos = funcInfos
	s.lineInfos = lineInfos
	return nil
}

// FuncInfos returns the binary form of BTF function infos.
func (s *Section) FuncInfos() (recordSize uint32, bytes []byte, err error) {
	bytes, err = s.funcInfos.MarshalBinary()
	if err != nil {
		return 0, nil, err
	}

	return s.funcInfos.recordSize, bytes, nil
}

// LineInfos returns the binary form of BTF line infos.
func (s *Section) LineInfos() (recordSize uint32, bytes []byte, err error) {
	bytes, err = s.lineInfos.MarshalBinary()
	if err != nil {
		return 0, nil, err
	}

	return s.lineInfos.recordSize, bytes, nil
}
