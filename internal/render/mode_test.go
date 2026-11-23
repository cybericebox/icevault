package render

import "io/fs"

func fileMode(m int) fs.FileMode { return fs.FileMode(m) }
