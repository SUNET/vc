package staticembed

import "embed"

//go:embed *.html consent.js styles.css offers.js bulma.min.css favicon.png logo.png
var FS embed.FS
