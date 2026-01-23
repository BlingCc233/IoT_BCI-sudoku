package bench

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func CoreSourceBytes(repoRoot string) (int64, error) {
	var total int64
	roots := []string{
		filepath.Join(repoRoot, "pkg", "iotbci"),
		filepath.Join(repoRoot, "pkg", "obfs", "sudoku"),
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			total += info.Size()
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return 0, err
		}
	}
	return total, nil
}
