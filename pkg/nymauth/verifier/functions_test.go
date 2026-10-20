package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Check() must be function-AGNOSTIC: a predicate it has never heard of,
// registered by a deployment, goes through exactly like the age check.
//
// Predicates in circuit_zk apply to any claim and the set of functions
// is open-ended, so a verifier that knows the vocabulary is a verifier
// that has to be changed for every new predicate. This drives a dummy
// function end to end to prove it does not.
func TestCheckIsFunctionAgnostic(t *testing.T) {
	const dummy = "test.document_number_prefix"
	require.NoError(t, Register(Function{ID: dummy, Inputs: []string{"prefix"}}))

	r := testRequest(t)
	r.Inputs = []CircuitInput{{FunctionID: dummy, Values: map[string][]byte{"prefix": []byte("SE")}}}
	r.SupportedFunctions = []string{dummy}

	require.NoError(t, r.Check(),
		"a registered function the circuit supports needs no change to Request or Check")

	// Alongside the age check, since a request may carry several.
	bounds, err := AgeCheck{GE: "2000-01-01"}.Bounds()
	require.NoError(t, err)
	r.Inputs = append(r.Inputs, bounds.CircuitInput())
	r.SupportedFunctions = append(r.SupportedFunctions, FunctionAgeCheck)
	require.NoError(t, r.Check())
}

// Fail closed, in both directions: a function nobody registered, and a
// registered function the selected circuit does not support.
//
// Passing either would hand the circuit inputs it does not read, and
// the proof would verify against a statement nobody checked.
func TestUnsupportedFunctionsAreRefused(t *testing.T) {
	const dummy = "test.unsupported"
	require.NoError(t, Register(Function{ID: dummy, Inputs: []string{"value"}}))

	t.Run("a function nobody registered", func(t *testing.T) {
		r := testRequest(t)
		r.Inputs = []CircuitInput{{FunctionID: "test.never_registered", Values: map[string][]byte{"value": []byte("x")}}}
		r.SupportedFunctions = []string{"test.never_registered"}
		err := r.Check()
		require.Error(t, err, "the circuit claiming to support it does not make it expressible here")
		assert.Contains(t, err.Error(), "not a registered predicate function")
	})

	t.Run("a registered function this circuit does not support", func(t *testing.T) {
		r := testRequest(t)
		r.Inputs = []CircuitInput{{FunctionID: dummy, Values: map[string][]byte{"value": []byte("x")}}}
		r.SupportedFunctions = []string{FunctionAgeCheck}
		err := r.Check()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not support")
	})

	t.Run("no supported functions at all", func(t *testing.T) {
		r := testRequest(t)
		r.SupportedFunctions = nil
		require.Error(t, r.Check(),
			"an empty capability list means none, not all; the alternative fails open")
	})

	t.Run("a value the function does not fill", func(t *testing.T) {
		r := testRequest(t)
		r.Inputs = []CircuitInput{{FunctionID: dummy, Values: map[string][]byte{
			"value": []byte("x"), "smuggled": []byte("y"),
		}}}
		r.SupportedFunctions = []string{dummy}
		err := r.Check()
		require.Error(t, err, "a value no circuit reads makes the request mean something other than it appears to")
		assert.Contains(t, err.Error(), "does not fill")
	})

	t.Run("one function contributing twice", func(t *testing.T) {
		bounds, err := AgeCheck{GE: "2000-01-01"}.Bounds()
		require.NoError(t, err)
		r := testRequest(t)
		r.Inputs = []CircuitInput{bounds.CircuitInput(), bounds.CircuitInput()}
		require.Error(t, r.Check(), "the second would silently fill the same circuit inputs")
	})
}

// The age check keeps its own privacy floor, declared on the function
// rather than invented for every predicate.
func TestAgeCheckDeclaresItsMinimumSelectivity(t *testing.T) {
	f, ok := LookupFunction(FunctionAgeCheck)
	require.True(t, ok)
	assert.Contains(t, f.MinimumSelectivity, "365",
		"the rulebook's rule belongs to this function; a generic one would be a rule nobody specified")
	assert.Equal(t, []string{InputEarliest, InputCutoff}, f.Inputs)

	// And it is still enforced where it is specified: in the mapping.
	_, err := AgeCheck{GE: "2008-01-01", LE: "2008-01-02"}.Bounds()
	assert.ErrorContains(t, err, "at least 365")
}

// Registration refuses what cannot be used.
func TestRegisterRefusesAnUnusableFunction(t *testing.T) {
	assert.Error(t, Register(Function{Inputs: []string{"x"}}), "a function needs an id")
	assert.Error(t, Register(Function{ID: "test.no_inputs"}), "a function that fills nothing cannot contribute")
}

// A looked-up function must not be a handle on the registry.
//
// Inputs was the stored slice, so assigning to f.Inputs[0] rewrote
// what every later request is validated against - without calling
// Register, without the mutex, and racing concurrent checks.
func TestLookupFunctionDoesNotShareTheRegistrysInputs(t *testing.T) {
	const id = "test.lookup_aliasing"
	require.NoError(t, Register(Function{ID: id, Inputs: []string{"value"}}))

	f, ok := LookupFunction(id)
	require.True(t, ok)
	require.Equal(t, []string{"value"}, f.Inputs)

	f.Inputs[0] = "something-else"

	again, ok := LookupFunction(id)
	require.True(t, ok)
	assert.Equal(t, []string{"value"}, again.Inputs,
		"a caller writing to the returned slice must not change the registry")
}
