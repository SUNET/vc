package jsonpointer

func find(val any, path Path) (*Reference, error) {
	if len(path) == 0 {
		return &Reference{Val: val}, nil
	}

	var obj any
	var key string
	current := val

	for _, step := range path {
		obj = current
		key = step

		var err error
		current, err = traverseStep(current, step)
		if err != nil {
			return nil, err
		}
	}

	return &Reference{Val: current, Obj: obj, Key: key}, nil
}
