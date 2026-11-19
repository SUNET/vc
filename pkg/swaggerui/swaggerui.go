// Package swaggerui serves the Swagger UI bundled in swaggo/files/v2 for an
// OpenAPI document held in memory.
//
// It replaces gin-swagger, which is tied to swaggo/files v1 and so to a UI
// that cannot render OpenAPI 3.1.
package swaggerui

import (
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/SUNET/vc/pkg/status"

	"github.com/gin-gonic/gin"
	files "github.com/swaggo/files/v2"
)

const (
	specName        = "doc.json"
	indexName       = "index.html"
	initializerName = "swagger-initializer.js"

	// defaultSpecURL is the placeholder the bundled initializer loads.
	defaultSpecURL = "https://petstore.swagger.io/v2/swagger.json"
)

// undefinedVersion is what status.BuildVersion holds when no version was
// injected at build time.
const undefinedVersion = "undef"

// Handler serves the UI and spec. Mount it on a wildcard route, e.g.
// group.GET("/*any", swaggerui.Handler(spec)): the UI is at the group root and
// the document at doc.json beneath it.
//
// The spec's info.version is replaced by status.BuildVersion when the build
// set one, so the UI shows the running release rather than the annotation.
func Handler(spec []byte) gin.HandlerFunc {
	spec = stampVersion(spec, status.BuildVersion)

	return func(c *gin.Context) {
		name := strings.TrimPrefix(c.Param("any"), "/")

		switch name {
		case "":
			name = indexName
		case specName:
			c.Data(http.StatusOK, "application/json; charset=utf-8", spec)
			return
		}

		body, err := fs.ReadFile(files.FS, name)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		if name == initializerName {
			body = []byte(strings.ReplaceAll(string(body), defaultSpecURL, specName))
		}

		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		c.Data(http.StatusOK, contentType, body)
	}
}

// stampVersion returns spec with info.version set to version. A spec that is
// not a JSON object with an info object, or an unset version, is returned
// unchanged.
func stampVersion(spec []byte, version string) []byte {
	if version == "" || version == undefinedVersion {
		return spec
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(spec, &doc); err != nil {
		return spec
	}
	var info map[string]json.RawMessage
	if err := json.Unmarshal(doc["info"], &info); err != nil {
		return spec
	}

	v, err := json.Marshal(version)
	if err != nil {
		return spec
	}
	info["version"] = v

	if doc["info"], err = json.Marshal(info); err != nil {
		return spec
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return spec
	}
	return out
}
