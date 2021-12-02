package asm

import (
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestGetSetJumpOp(t *testing.T) {
	test := func(class Class, op JumpOp, valid bool) {
		t.Run(fmt.Sprintf("%s-%s", class, op), func(t *testing.T) {
			opcode := OpCode(class).SetJumpOp(op)

			if valid {
				qt.Assert(t, opcode, qt.Not(qt.Equals), InvalidOpCode)
				qt.Assert(t, opcode.JumpOp(), qt.Equals, op)
			} else {
				qt.Assert(t, opcode, qt.Equals, InvalidOpCode)
				qt.Assert(t, opcode.JumpOp(), qt.Equals, InvalidJumpOp)
			}
		})
	}

	// Exit, call and JA aren't allowed with Jump32
	test(Jump32Class, Exit, false)
	test(Jump32Class, Call, false)
	test(Jump32Class, Ja, false)

	// But are with Jump
	test(JumpClass, Exit, true)
	test(JumpClass, Call, true)
	test(JumpClass, Ja, true)

	// All other ops work
	for _, op := range []JumpOp{
		JEq,
		JGT,
		JGE,
		JSet,
		JNE,
		JSGT,
		JSGE,
		JLT,
		JLE,
		JSLT,
		JSLE,
	} {
		test(Jump32Class, op, true)
		test(JumpClass, op, true)
	}
}
