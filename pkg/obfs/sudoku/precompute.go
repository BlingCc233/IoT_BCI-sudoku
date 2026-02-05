package sudoku

// Precompute warms up shared Sudoku structures that are otherwise lazily initialized.
//
// This is useful for benchmarks that want to exclude one-time global initialization
// (e.g. unique-combination indexing) from per-scenario peak memory measurements.
func Precompute() {
	_ = uniqueCombosByGridRef()
}
