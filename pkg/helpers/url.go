package helpers

import (
	"fmt"
	"net/url"
)

// HostFromURL extracts the host (including any port) from a URL string.
// Unlike strings.TrimLeft, this correctly handles all URL schemes and paths.
func HostFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL %q has no host", rawURL)
	}
	return u.Host, nil
}
