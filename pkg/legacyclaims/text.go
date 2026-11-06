package legacyclaims

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// written is a file as written, and where the text the parser reads lies
// in it. gopkg.in/yaml.v2 reads UTF-16 after a UTF-16 byte order mark,
// drops the byte order mark that opens the file, and reads CRLF, CR, LF,
// NEL, LS and PS as line breaks. The parser reads the same text in UTF-8,
// with LF for each line break, where it places each token exactly.
type written struct {
	encoding encoding
	// text is the file in UTF-8, without the byte order mark that opens
	// it.
	text []byte
	// shifts holds, in order, each line break of more than one byte of
	// text.
	shifts []shift
	// newline is the line break that ends the most lines of text, the
	// first of them on a tie, and LF in a text of one line. An edit
	// writes it for each LF of its text.
	newline string
}

// shift is a line break of more than one byte of text: up to offset end
// of the parser's text, the text holds extra bytes more.
type shift struct{ end, extra int }

// lineBreaks lists the line breaks gopkg.in/yaml.v2 reads, CRLF before
// CR.
var lineBreaks = [...][]byte{[]byte("\r\n"), []byte("\r"), []byte("\n"), []byte("\u0085"), []byte("\u2028"), []byte("\u2029")}

// readFile returns a file as written, and the text the parser reads from
// it.
func readFile(src []byte) (written, []byte, error) {
	enc, text, err := decode(src)
	if err != nil {
		return written{}, nil, err
	}
	w := written{encoding: enc, text: text, newline: "\n"}
	parsed := make([]byte, 0, len(text))
	var count, first [len(lineBreaks)]int
	extra := 0
	for i := 0; i < len(text); {
		kind := lineBreakAt(text[i:])
		if kind < 0 {
			parsed = append(parsed, text[i])
			i++
			continue
		}
		if count[kind] == 0 {
			first[kind] = i
		}
		count[kind]++
		parsed = append(parsed, '\n')
		if size := len(lineBreaks[kind]); size > 1 {
			extra += size - 1
			w.shifts = append(w.shifts, shift{end: len(parsed), extra: extra})
		}
		i += len(lineBreaks[kind])
	}
	best := -1
	for kind := range lineBreaks {
		if count[kind] > 0 && (best < 0 || count[kind] > count[best] || count[kind] == count[best] && first[kind] < first[best]) {
			best = kind
		}
	}
	if best >= 0 {
		w.newline = string(lineBreaks[best])
	}
	return w, parsed, nil
}

// lineBreakAt returns the index in lineBreaks of the line break that
// starts text, and -1 where text starts with none.
func lineBreakAt(text []byte) int {
	for kind, lineBreak := range lineBreaks {
		if bytes.HasPrefix(text, lineBreak) {
			return kind
		}
	}
	return -1
}

// offset returns the offset of the text at an offset of the parser's
// text. An offset at a line break is the start of the line break.
func (w *written) offset(at int) int {
	i := sort.Search(len(w.shifts), func(i int) bool { return w.shifts[i].end > at })
	if i == 0 {
		return at
	}
	return at + w.shifts[i-1].extra
}

// encoding is the encoding of a file, which gopkg.in/yaml.v2 reads from
// its byte order mark.
type encoding uint8

const (
	// plainUTF8 is UTF-8 without a byte order mark.
	plainUTF8 encoding = iota
	// markedUTF8 is UTF-8 after a byte order mark.
	markedUTF8
	// utf16LE is little-endian UTF-16 after a byte order mark.
	utf16LE
	// utf16BE is big-endian UTF-16 after a byte order mark.
	utf16BE
)

// utf8Mark is the UTF-8 byte order mark.
const utf8Mark = "\xef\xbb\xbf"

// decode returns the encoding of a file and its text in UTF-8, without
// the byte order mark that opens it. It refuses the UTF-16 text
// gopkg.in/yaml.v2 refuses.
func decode(src []byte) (encoding, []byte, error) {
	switch {
	case bytes.HasPrefix(src, []byte{0xff, 0xfe}):
		text, err := decodeUTF16(src[2:], binary.LittleEndian)
		return utf16LE, text, err
	case bytes.HasPrefix(src, []byte{0xfe, 0xff}):
		text, err := decodeUTF16(src[2:], binary.BigEndian)
		return utf16BE, text, err
	case bytes.HasPrefix(src, []byte(utf8Mark)):
		return markedUTF8, src[len(utf8Mark):], nil
	}
	return plainUTF8, src, nil
}

// decodeUTF16 returns UTF-16 text in UTF-8. It refuses an odd number of
// bytes, and a surrogate outside a pair.
func decodeUTF16(src []byte, order binary.ByteOrder) ([]byte, error) {
	if len(src)%2 != 0 {
		return nil, errors.New("the text ends inside a UTF-16 character")
	}
	text := make([]byte, 0, len(src))
	for i := 0; i < len(src); i += 2 {
		r := rune(order.Uint16(src[i:]))
		if utf16.IsSurrogate(r) {
			if i+4 > len(src) {
				return nil, errors.New("the text ends inside a UTF-16 surrogate pair")
			}
			i += 2
			if r = utf16.DecodeRune(r, rune(order.Uint16(src[i:]))); r == utf8.RuneError {
				return nil, errors.New("the text holds a UTF-16 surrogate outside a pair")
			}
		}
		text = utf8.AppendRune(text, r)
	}
	return text, nil
}

// encode writes UTF-8 text in the encoding, after its byte order mark.
func (e encoding) encode(text []byte) []byte {
	switch e {
	case markedUTF8:
		return append([]byte(utf8Mark), text...)
	case utf16LE:
		return encodeUTF16(text, binary.LittleEndian)
	case utf16BE:
		return encodeUTF16(text, binary.BigEndian)
	}
	return text
}

// encodeUTF16 writes UTF-8 text in UTF-16, after the byte order mark.
func encodeUTF16(text []byte, order binary.AppendByteOrder) []byte {
	out := order.AppendUint16(make([]byte, 0, 2*len(text)+2), 0xfeff)
	for _, unit := range utf16.Encode([]rune(string(text))) {
		out = order.AppendUint16(out, unit)
	}
	return out
}
