package staticembed

import "embed"

//go:embed *.html *.js *.css *.png
var FS embed.FS
