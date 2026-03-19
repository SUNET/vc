package helpers

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kaptinlin/jsonschema"
)

func getValidationSchema(schemaRef string, compiler *jsonschema.Compiler) (*jsonschema.Schema, error) {
	origin := strings.Split(schemaRef, "//")[0]

	switch origin {
	case "http:", "https:":
		return compiler.Schema(schemaRef)

	case "file:":
		filePath := strings.TrimPrefix(filepath.SplitList(schemaRef)[1:][0], "//")
		schemaFile, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return nil, err
		}

		return compiler.Compile(schemaFile)
	}

	return nil, nil

}
