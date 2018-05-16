package ebpf

import (
	"fmt"
)

// ExampleInstructions_Format shows the different options available
// to format an instruction stream.
func ExampleInstructions_Format() {
	insns := Instructions{
		BPFILdImm64(Reg0, 42),
		BPFIOp(Exit),
	}

	fmt.Println("Default format:")
	fmt.Printf("%s\n", insns)

	fmt.Println("Custom indendation:")
	fmt.Printf("%1s\n", insns)

	fmt.Println("Indent using spaces:")
	fmt.Printf("% 3s\n", insns)

	// Output: Default format:
	// 0: LdImmDW dst: r0 imm: 42
	// 2: Exit
	//
	// Custom indendation:
	// 	0: LdImmDW dst: r0 imm: 42
	// 	2: Exit
	//
	// Indent using spaces:
	//    0: LdImmDW dst: r0 imm: 42
	//    2: Exit
}
