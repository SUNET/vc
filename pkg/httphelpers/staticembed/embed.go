package staticembed

import "embed"

//go:embed error.html logo.png
var FS embed.FS
