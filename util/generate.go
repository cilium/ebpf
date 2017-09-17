package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const comment = `// import (
// 	"bytes"
//
// 	"github.com/nathanjsweet/ebpf"
// )
// ...
// func main() {
// 	coll, err := NewBPFCollectionFromObjectCode(bytes.NewReader(program[:]))
// 	if err != nil {
// 		panic(err)
// 	}
//	...
// }
`

func main() {
	fileName := flag.String("file", "", "specific file to dump")
	packageName := flag.String("package", "main", "what to call the package")
	variableName := flag.String("variable", "program", "what to call the program")
	name := flag.String("name", "", "what to name the file")
	stdOut := flag.Bool("stdout", false, "just output to stdout")
	flag.Parse()

	rf, err := os.Open(*fileName)
	if err != nil {
		panic(err)
	}
	defer rf.Close()
	var wf *os.File
	if *stdOut {
		wf = os.Stdout
	} else {
		if len(*name) == 0 {
			_, file := path.Split(*fileName)
			*name = file
			tmp := strings.Split(*name, ".")
			if len(tmp) > 1 && tmp[len(tmp)-1] == "o" {
				tmp[len(tmp)-1] = "go"
				*name = strings.Join(tmp, ".")
			} else {
				*name = *name + ".go"
			}
		}
		wf, err = os.OpenFile(*name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer wf.Close()
	}

	buffer := make([]byte, 256)
	wf.WriteString(fmt.Sprintf("package %s\n\n", *packageName))
	wf.WriteString(fmt.Sprintf("var %s = [...]byte{", *variableName))
	first := true
	for {
		n, err := rf.Read(buffer)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if !first && n > 0 {
			wf.WriteString(", ")
		}
		writeBytes(wf, buffer, n)
		if err == io.EOF {
			break
		}
		first = false
	}
	wf.WriteString("}\n\n")
	wf.WriteString(comment)
}

func writeBytes(wf *os.File, bytes []byte, n int) {
	for i := 0; i < n; i++ {
		s := ", "
		if i+1 == n {
			s = ""
		}
		wf.WriteString(fmt.Sprintf("0x%02x%s", bytes[i], s))
	}
}
