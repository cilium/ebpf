package ebpf

import (
	"fmt"
)

// ExampleInstructions_Format shows the different options available
// to format an instruction stream.
func ExampleInstructions_Format() {
	insns := Instructions{
		BPFCall(MapLookupElement).Sym("my_func"),
		BPFILdImm64(Reg0, 42),
		BPFIOp(Exit),
	}

	fmt.Println("Default format:")
	fmt.Printf("%s", insns)

	fmt.Println("Don't indent instructions:")
	fmt.Printf("%.0s", insns)

	fmt.Println("Indent using spaces:")
	fmt.Printf("% s", insns)

	fmt.Println("Control symbol indentation:")
	fmt.Printf("%2s", insns)

	// Output: Default format:
	// my_func:
	// 	0: Call MapLookupElement
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
	// Don't indent instructions:
	// my_func:
	// 0: Call MapLookupElement
	// 1: LdImmDW dst: r0 imm: 42
	// 3: Exit
	// Indent using spaces:
	// my_func:
	//  0: Call MapLookupElement
	//  1: LdImmDW dst: r0 imm: 42
	//  3: Exit
	// Control symbol indentation:
	// 		my_func:
	// 	0: Call MapLookupElement
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
}
