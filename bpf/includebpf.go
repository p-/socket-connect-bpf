package main

import (
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// Reads all .bpf files in the current folder
// and encodes them as strings literals in bpfiles.go
func main() {
	fs, _ := ioutil.ReadDir(".")
	out, _ := os.Create("bpffiles.go")
	out.Write([]byte("package main \n\nconst (\n"))
	for _, f := range fs {
		if strings.HasSuffix(f.Name(), ".bpf") {
			out.Write([]byte(strings.TrimSuffix(f.Name(), ".bpf") + " = `"))
			f, _ := os.Open(f.Name())
			io.Copy(out, f)
			out.Write([]byte("`\n"))
		}
	}
	out.Write([]byte(")\n"))
}
