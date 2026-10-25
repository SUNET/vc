package claimpath

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// DecodeList reads a YAML sequence into list. It also reads the legacy
// form of the list, a mapping from a dotted claim to a value: entry makes
// one item of each key, as a pending pointer, and its value, in document
// order.
func DecodeList[L ~[]T, T, V any](unmarshal func(any) error, list *L, entry func(Pointer, V) (T, error)) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if _, mapping := raw.(map[any]any); !mapping {
		var items []T
		if err := unmarshal(&items); err != nil {
			return err
		}
		*list = items
		return nil
	}
	items, err := legacyItems(unmarshal, entry)
	if err != nil {
		return err
	}
	*list = items
	return nil
}

// legacyItems reads the mapping form, in document order.
func legacyItems[T, V any](unmarshal func(any) error, entry func(Pointer, V) (T, error)) ([]T, error) {
	var order yaml.MapSlice
	if err := unmarshal(&order); err != nil {
		return nil, err
	}
	var values map[string]V
	if err := unmarshal(&values); err != nil {
		return nil, err
	}
	items := make([]T, 0, len(order))
	for _, item := range order {
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("claimpath: the claim %v is no dotted string", item.Key)
		}
		pointer, err := Dotted(key)
		if err != nil {
			return nil, err
		}
		listItem, err := entry(pointer, values[key])
		if err != nil {
			return nil, fmt.Errorf("claimpath: claim %q: %w", key, err)
		}
		items = append(items, listItem)
	}
	return items, nil
}
