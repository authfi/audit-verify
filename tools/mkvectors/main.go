// Command mkvectors writes the generated test vectors into a directory (default: vectors). It is how the files
// under vectors/ are made; vectors_test.go fails if they differ from a fresh run.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/authfi/audit-verify/internal/vectorgen"
)

func main() {
	dir := flag.String("out", "vectors", "directory to write into")
	flag.Parse()
	for name, data := range vectorgen.Files() {
		path := filepath.Join(*dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
