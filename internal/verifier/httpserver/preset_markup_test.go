package httpserver

import (
	"testing"

	"github.com/SUNET/vc/internal/verifier/staticembed"

	"github.com/stretchr/testify/require"
)

// The helper deciding that the groups may not start collapsed is only half
// the fix - the shipped template is what obeys it, and the defect lived
// there as much as in the data. A test over groupPresets alone passes with
// the template still hiding everything behind the toggle.
func TestPresetMarkupRendersGroupsWhenNothingIsFeatured(t *testing.T) {
	page, err := staticembed.FS.ReadFile("presentation-definition.html")
	require.NoError(t, err)
	html := string(page)

	// The groups render when the toggle is open OR when there is nothing
	// to collapse them behind. Without the second half, a deployment that
	// categorises every preset and features none shows a heading, an empty
	// button list and a "Show more presets" link.
	require.Contains(t, html, `x-if="showMorePresets || !groupedPresetData.collapsible"`,
		"the groups must render at rest when no preset is featured")
	require.NotContains(t, html, `<template x-if="showMorePresets">`,
		"the unconditional collapse is what hid every preset on such a deployment")

	// And the toggle itself is suppressed in that case: a control offering
	// to show what is already shown, whose label would read "Show fewer
	// presets" before anything was shown, is worse than no control.
	require.Contains(t, html, `x-if="groupedPresetData.collapsible"`,
		"the toggle only makes sense when something is featured to collapse behind")
}
