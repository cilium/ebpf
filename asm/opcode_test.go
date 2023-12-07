package asm

import (
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestGetSetJumpOp(t *testing.T) {
	test := func(class Class, op JumpOp, valid bool) {
		t.Run(fmt.Sprintf("%s-%s", class, op), func(t *testing.T) {
			opcode := OpCode(class).SetJumpOp(op)

			if valid {
				qt.Assert(t, qt.Not(qt.Equals(opcode, InvalidOpCode)))
				qt.Assert(t, qt.Equals(opcode.JumpOp(), op))
			} else {
				qt.Assert(t, qt.Equals(opcode, InvalidOpCode))
				qt.Assert(t, qt.Equals(opcode.JumpOp(), InvalidJumpOp))
			}
		})
	}

	// Exit and call aren't allowed with Jump32
	test(Jump32Class, Exit, false)
	test(Jump32Class, Call, false)

	// But are with Jump
	test(JumpClass, Exit, true)
	test(JumpClass, Call, true)

	// All other ops work
	for _, op := range []JumpOp{
		Ja,
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
