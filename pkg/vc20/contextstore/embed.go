package contextstore

import (
	"embed"
	"fmt"
)

//go:embed data/*.jsonld
var contextFS embed.FS

var contextMap = map[string]string{
	"https://www.w3.org/ns/credentials/v2":   "data/credentials-v2.jsonld",
	"https://www.w3.org/2018/credentials/v1": "data/credentials-v1.jsonld",
}

// GetContext returns the content of a well-known context
func GetContext(url string) ([]byte, error) {
	filename, ok := contextMap[url]
	if !ok {
		return nil, fmt.Errorf("context not found: %s", url)
	}
	return contextFS.ReadFile(filename)
}

// GetAllContexts returns all embedded contexts
func GetAllContexts() map[string][]byte {
	result := make(map[string][]byte)
	for url, filename := range contextMap {
		data, err := contextFS.ReadFile(filename)
		if err == nil {
			result[url] = data
		}
	}
	return result
}
