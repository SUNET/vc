package staticembed

import "embed"

//go:embed *.html *.js *.css *.png alpinejs.esm.min.js valibot.min.js tailwindcss.js
var FS embed.FS
