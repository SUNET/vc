// Package persist provides file I/O and serialization for SPOCP rulesets.
// It supports both text-based (canonical S-expression) and binary formats
// for efficient storage and loading of policy rules.
package persist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// FileFormat represents the format of a ruleset file
type FileFormat int

const (
	// FormatCanonical uses canonical S-expression format (length-prefixed)
	// Example: (4:http3:GET)
	FormatCanonical FileFormat = iota

	// FormatAdvanced uses human-readable advanced form
	// Example: (http GET)
	FormatAdvanced

	// FormatBinary uses efficient binary encoding
	FormatBinary
)

// LoadOptions controls how files are loaded
type LoadOptions struct {
	// Format specifies the file format (auto-detected if not specified)
	Format FileFormat

	// SkipInvalid continues loading if a rule fails to parse
	SkipInvalid bool

	// MaxRules limits the number of rules to load (0 = unlimited)
	MaxRules int

	// Comments defines comment prefixes to ignore (default: "#", "//")
	Comments []string
}

// DefaultLoadOptions returns sensible defaults for loading rulesets
func DefaultLoadOptions() LoadOptions {
	return LoadOptions{
		Format:      FormatCanonical,
		SkipInvalid: false,
		MaxRules:    0,
		Comments:    []string{"#", "//", ";"},
	}
}

// LoadFile loads rules from a file and returns parsed elements
func LoadFile(filename string, opts LoadOptions) ([]sexp.Element, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Auto-detect binary format
	if opts.Format == FormatBinary || isBinaryFile(filename) {
		return loadBinary(file)
	}

	return loadText(file, opts)
}

// LoadFileToSlice is a convenience function that loads rules into a slice
// This is the recommended way to load rules for most use cases
func LoadFileToSlice(filename string) ([]sexp.Element, error) {
	return LoadFile(filename, DefaultLoadOptions())
}

// SaveFile saves rules to a file in the specified format
func SaveFile(filename string, rules []sexp.Element, format FileFormat) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	switch format {
	case FormatBinary:
		return saveBinary(file, rules)
	case FormatAdvanced:
		return saveAdvanced(file, rules)
	default:
		return saveCanonical(file, rules)
	}
}

// loadText loads rules from a text file (canonical or advanced form)
func loadText(r io.Reader, opts LoadOptions) ([]sexp.Element, error) {
	scanner := bufio.NewScanner(r)
	rules := make([]sexp.Element, 0)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comments
		if isComment(line, opts.Comments) {
			continue
		}

		// Parse the rule
		var elem sexp.Element
		var err error

		if opts.Format == FormatAdvanced {
			// Convert advanced form to canonical, then parse
			canonical := advancedToCanonical(line)
			parser := sexp.NewParser(canonical)
			elem, err = parser.Parse()
		} else {
			// Parse canonical form directly
			parser := sexp.NewParser(line)
			elem, err = parser.Parse()
		}

		if err != nil {
			if opts.SkipInvalid {
				continue
			}
			return nil, fmt.Errorf("line %d: failed to parse rule: %w", lineNum, err)
		}

		rules = append(rules, elem)

		// Check max rules limit
		if opts.MaxRules > 0 && len(rules) >= opts.MaxRules {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return rules, nil
}

// saveCanonical saves rules in canonical S-expression format (one per line)
func saveCanonical(w io.Writer, rules []sexp.Element) error {
	writer := bufio.NewWriter(w)
	for _, rule := range rules {
		if _, err := writer.WriteString(rule.String()); err != nil {
			return err
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// saveAdvanced saves rules in human-readable advanced form (one per line)
func saveAdvanced(w io.Writer, rules []sexp.Element) error {
	writer := bufio.NewWriter(w)
	for _, rule := range rules {
		advanced := sexp.AdvancedForm(rule)
		if _, err := writer.WriteString(advanced); err != nil {
			return err
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// Binary format specification:
// - Magic number: "SPOCP" (5 bytes)
// - Version: uint8 (1 byte)
// - Rule count: uint32 (4 bytes)
// - For each rule:
//   - Rule length: uint32 (4 bytes)
//   - Rule data: canonical S-expression (variable length)

const (
	binaryMagic   = "SPOCP"
	binaryVersion = 1
)

// saveBinary saves rules in efficient binary format
func saveBinary(w io.Writer, rules []sexp.Element) error {
	// Write magic number
	if _, err := w.Write([]byte(binaryMagic)); err != nil {
		return err
	}

	// Write version
	if err := binary.Write(w, binary.LittleEndian, uint8(binaryVersion)); err != nil {
		return err
	}

	// Write rule count (check bounds)
	if len(rules) > int(^uint32(0)) {
		return fmt.Errorf("too many rules: %d exceeds uint32 max", len(rules))
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(rules))); err != nil { //nolint:gosec // bounds checked above
		return err
	}

	// Write each rule
	for _, rule := range rules {
		canonical := rule.String()
		data := []byte(canonical)

		// Write length (check bounds)
		if len(data) > int(^uint32(0)) {
			return fmt.Errorf("rule data too large: %d exceeds uint32 max", len(data))
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil { //nolint:gosec // bounds checked above
			return err
		}

		// Write data
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// loadBinary loads rules from binary format
func loadBinary(r io.Reader) ([]sexp.Element, error) {
	// Read and verify magic number
	magic := make([]byte, len(binaryMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("failed to read magic number: %w", err)
	}
	if string(magic) != binaryMagic {
		return nil, fmt.Errorf("invalid magic number: %s", string(magic))
	}

	// Read version
	var version uint8
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if version != binaryVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read rule count
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, fmt.Errorf("failed to read rule count: %w", err)
	}

	// Read each rule
	rules := make([]sexp.Element, 0, count)
	for i := uint32(0); i < count; i++ {
		// Read length
		var length uint32
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return nil, fmt.Errorf("rule %d: failed to read length: %w", i, err)
		}

		// Read data
		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("rule %d: failed to read data: %w", i, err)
		}

		// Parse rule
		parser := sexp.NewParser(string(data))
		elem, err := parser.Parse()
		if err != nil {
			return nil, fmt.Errorf("rule %d: failed to parse: %w", i, err)
		}

		rules = append(rules, elem)
	}

	return rules, nil
}

// SerializeRule converts a single rule to binary format
func SerializeRule(rule sexp.Element) ([]byte, error) {
	var buf bytes.Buffer
	canonical := rule.String()
	data := []byte(canonical)

	// Write length (check bounds)
	if len(data) > int(^uint32(0)) {
		return nil, fmt.Errorf("rule data too large: %d exceeds uint32 max", len(data))
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(data))); err != nil { //nolint:gosec // bounds checked above
		return nil, err
	}

	// Write data
	if _, err := buf.Write(data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DeserializeRule converts binary format back to a rule
func DeserializeRule(data []byte) (sexp.Element, error) {
	buf := bytes.NewReader(data)

	// Read length
	var length uint32
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	// Read canonical form
	canonical := make([]byte, length)
	if _, err := io.ReadFull(buf, canonical); err != nil {
		return nil, err
	}

	// Parse
	parser := sexp.NewParser(string(canonical))
	return parser.Parse()
}

// Helper functions

func isComment(line string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func isBinaryFile(filename string) bool {
	return strings.HasSuffix(filename, ".spocp") ||
		strings.HasSuffix(filename, ".bin")
}

// advancedToCanonical converts advanced form to canonical form
// This is a simple implementation - for production use, you might want
// a more sophisticated parser
func advancedToCanonical(advanced string) string {
	// Remove outer parentheses if present
	advanced = strings.TrimSpace(advanced)
	if strings.HasPrefix(advanced, "(") && strings.HasSuffix(advanced, ")") {
		advanced = advanced[1 : len(advanced)-1]
	}

	// Split into tokens
	tokens := tokenize(advanced)

	// Convert to canonical
	return tokensToCanonical(tokens)
}

func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0
	inQuote := false

	for i, ch := range s {
		switch ch {
		case '(':
			if !inQuote {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
				depth++
				current.WriteRune(ch)
			} else {
				current.WriteRune(ch)
			}
		case ')':
			if !inQuote {
				current.WriteRune(ch)
				depth--
				if depth == 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(ch)
			}
		case '"':
			inQuote = !inQuote
			current.WriteRune(ch)
		case ' ', '\t', '\n', '\r':
			if !inQuote && depth == 0 {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}

		// Handle last character
		if i == len(s)-1 && current.Len() > 0 {
			tokens = append(tokens, current.String())
		}
	}

	return tokens
}

func tokensToCanonical(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}

	// Single token
	if len(tokens) == 1 {
		token := tokens[0]
		if strings.HasPrefix(token, "(") {
			return tokensToCanonical(tokenize(token[1 : len(token)-1]))
		}
		return fmt.Sprintf("%d:%s", len(token), token)
	}

	// Multiple tokens form a list
	var buf strings.Builder
	buf.WriteString("(")
	for _, token := range tokens {
		if strings.HasPrefix(token, "(") {
			buf.WriteString(tokensToCanonical(tokenize(token[1 : len(token)-1])))
		} else {
			buf.WriteString(fmt.Sprintf("%d:%s", len(token), token))
		}
	}
	buf.WriteString(")")
	return buf.String()
}
