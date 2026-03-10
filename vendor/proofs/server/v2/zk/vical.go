package zk

import (
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

// LoadVICAL fetches the VICAL from the given URL and adds the certificates to the IssuerRoots pool.
func LoadVICAL(url string) error {
	log.Printf("Fetching VICAL from %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch VICAL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch VICAL: status %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read VICAL body: %w", err)
	}

	var rawItems []interface{}
	if err := cbor.Unmarshal(data, &rawItems); err != nil {
		return fmt.Errorf("failed to unmarshal VICAL CBOR: %w", err)
	}

	count := 0
	var findCerts func(item interface{}, depth int)
	findCerts = func(item interface{}, depth int) {
		if depth > 10 {
			return // Avoid infinite recursion
		}
		switch v := item.(type) {
		case []byte:
			// Try to parse as certificate first
			if len(v) > 0 && v[0] == 0x30 {
				cert, err := x509.ParseCertificate(v)
				if err == nil {
					IssuerRoots.AddCert(cert)
					count++
					return // Found a cert, stop digging in this branch
				}
			}
			// If not a cert or cert parse failed, try treating as CBOR
			var child interface{}
			if err := cbor.Unmarshal(v, &child); err == nil {
				findCerts(child, depth+1)
			}
		case []interface{}:
			for _, child := range v {
				findCerts(child, depth+1)
			}
		case map[interface{}]interface{}:
			for _, val := range v {
				findCerts(val, depth+1)
			}
		}
	}

	for _, item := range rawItems {
		findCerts(item, 0)
	}

	log.Printf("Loaded %d certificates from VICAL", count)
	return nil
}
