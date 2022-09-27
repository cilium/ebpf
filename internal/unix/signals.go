package unix

import (
	"fmt"
	"unsafe"
)

const (
	wordBytes = int(unsafe.Sizeof(Sigset_t{}.Val[0]))
	wordBits  = wordBytes * 8

	setBytes = int(unsafe.Sizeof(Sigset_t{}))
	setBits  = setBytes * 8
)

// SigsetAdd adds signal to set.
func SigsetAdd(set *Sigset_t, signal Signal) error {
	if signal < 1 {
		return fmt.Errorf("signal %d must be larger than 0", signal)
	}
	if int(signal) > setBits {
		return fmt.Errorf("signal %d does not fit within unix.Sigset_t", signal)
	}

	// For amd64, runtime.sigaddset() performs the following operation:
	// set[(signal-1)/32] |= 1 << ((uint32(signal) - 1) & 31)
	//
	// This trick depends on sigset being two u32's, causing a signal in the the
	// bottom 31 bits to be written to the low word if bit 32 is low, or the high
	// word if bit 32 is high.

	// Signal is the nth bit in the bitfield.
	bit := int(signal - 1)
	// Word within the sigset the bit needs to be written to.
	word := bit / wordBits

	// Write the signal bit into its corresponding word at the corrected offset.
	set.Val[word] |= 1 << (bit % wordBits)

	return nil
}
