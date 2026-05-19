package jsonpointer

const (
	// MaxPointerLength is the maximum allowed length for JSON Pointer strings.
	MaxPointerLength = 1024

	// MaxPathLength is the maximum allowed length for Path arrays.
	MaxPathLength = 256
)

func validatePointerString(pointer string) error {
	if pointer == "" {
		return nil
	}

	if pointer[0] != '/' {
		return ErrPointerInvalid
	}

	if len(pointer) > MaxPointerLength {
		return ErrPointerTooLong
	}

	for i := range len(pointer) {
		if pointer[i] != '~' {
			continue
		}
		if i+1 >= len(pointer) {
			return ErrPointerInvalid
		}
		next := pointer[i+1]
		if next != '0' && next != '1' {
			return ErrPointerInvalid
		}
	}

	return nil
}

func validatePath(path Path) error {
	if len(path) > MaxPathLength {
		return ErrPathTooLong
	}
	return nil
}
