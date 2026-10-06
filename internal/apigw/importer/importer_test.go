package importer

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBootstrapFile(t *testing.T) {
	payload := []byte(`{"100":{"meta":{"scope":"microcredential"}}}`)

	t.Run("plain json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "microcredential.json")
		require.NoError(t, os.WriteFile(path, payload, 0o600))

		got, err := readBootstrapFile(path)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("gzip json yields identical bytes", func(t *testing.T) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, err := zw.Write(payload)
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		path := filepath.Join(t.TempDir(), "microcredential.json.gz")
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

		got, err := readBootstrapFile(path)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("corrupt gzip errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "broken.json.gz")
		require.NoError(t, os.WriteFile(path, append(gzipMagic, 0x00, 0x01), 0o600))

		_, err := readBootstrapFile(path)
		assert.Error(t, err)
	})
}
