package staticembed

import "embed"

//go:embed *.html consent.js styles.css offers.js bulma.min.css favicon.png logo.png alpinejs.esm.min.js valibot.min.js tailwindcss.js
var FS embed.FS
