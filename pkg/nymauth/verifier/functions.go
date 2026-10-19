package verifier

import (
	"fmt"
	"maps"
	"slices"
	"sync"
)

// FunctionAgeCheck is the rulebook's age predicate, and the first
// registered function. Its parameters map to the circuits' inclusive
// (E, C) - see AgeCheck.
const FunctionAgeCheck = "age_check"

// Circuit input names FunctionAgeCheck fills.
const (
	InputEarliest = "earliest"
	InputCutoff   = "cutoff"
)

// CircuitInput is one predicate's contribution to a circuit request:
// which function it is, and the circuit inputs it fills.
//
// Opaque to everything generic. The predicate's own mapping builds it -
// AgeCheck.Bounds().CircuitInput() for the age check - and the generic
// layer only ever asks whether the function is known, whether the
// selected circuit supports it, and whether it filled the inputs that
// function is declared to fill. A predicate over some claim nobody has
// written yet needs no change here.
type CircuitInput struct {
	// FunctionID is the predicate function, e.g. FunctionAgeCheck.
	FunctionID string

	// Values are the circuit inputs this predicate fills, keyed by the
	// names its Function declares.
	Values map[string][]byte
}

// Function describes a predicate function this verifier can express.
//
// Predicates in circuit_zk apply to ANY claim, and the set of functions
// is OPEN-ENDED - unlike EC TS12, where the vocabulary is closed. So
// the generic layer is a registry rather than a list of fields: adding
// a function is registering one, and nothing in Request or Check has to
// learn about it.
//
// Which claim a predicate applies to is NOT here. It comes from the
// request's own source path when the presentation is matched, so a
// function is reusable across claims by construction.
type Function struct {
	// ID is the function identifier the circuit and the catalog use.
	ID string

	// Inputs are the circuit input names this function fills. Exactly
	// these, no more and no fewer: a missing one would leave a circuit
	// input unset, and an extra one is a value no circuit reads, which
	// is a request that means something other than it appears to.
	Inputs []string

	// MinimumSelectivity, when non-empty, describes a privacy floor
	// this function imposes on its own parameters - the age check's
	// 365-day minimum range, for instance.
	//
	// Declared PER FUNCTION and enforced by the function's own mapping,
	// not by the generic layer. A floor invented for every predicate
	// would be a rule nobody specified: a range over birth dates
	// narrows to an identifier, while a predicate over a document
	// number has no analogue.
	MinimumSelectivity string
}

var (
	functionsMu sync.RWMutex
	functions   = map[string]Function{
		FunctionAgeCheck: {
			ID:                 FunctionAgeCheck,
			Inputs:             []string{InputEarliest, InputCutoff},
			MinimumSelectivity: "the range between a set earliest and cutoff birth date is at least 365 days",
		},
	}
)

// Register adds a predicate function. Re-registering an id replaces it,
// which is what a deployment extending the vocabulary wants; the
// registry is read far more often than written.
func Register(f Function) error {
	if f.ID == "" {
		return fmt.Errorf("nymauth: a predicate function needs an id")
	}
	if len(f.Inputs) == 0 {
		return fmt.Errorf("nymauth: function %q fills no circuit inputs", f.ID)
	}
	functionsMu.Lock()
	defer functionsMu.Unlock()
	functions[f.ID] = Function{ID: f.ID, Inputs: slices.Clone(f.Inputs), MinimumSelectivity: f.MinimumSelectivity}
	return nil
}

// LookupFunction returns a registered predicate function.
func LookupFunction(id string) (Function, bool) {
	functionsMu.RLock()
	defer functionsMu.RUnlock()
	f, ok := functions[id]
	return f, ok
}

// RegisteredFunctions names every registered function, sorted.
func RegisteredFunctions() []string {
	functionsMu.RLock()
	defer functionsMu.RUnlock()
	return slices.Sorted(maps.Keys(functions))
}

// check refuses an input that does not fill exactly what its function
// declares.
func (i CircuitInput) check() error {
	f, ok := LookupFunction(i.FunctionID)
	if !ok {
		return fmt.Errorf("nymauth: %q is not a registered predicate function; registered: %v",
			i.FunctionID, RegisteredFunctions())
	}
	for _, name := range f.Inputs {
		if len(i.Values[name]) == 0 {
			return fmt.Errorf("nymauth: function %q leaves circuit input %q unset", i.FunctionID, name)
		}
	}
	for name := range i.Values {
		if !slices.Contains(f.Inputs, name) {
			// A value no circuit reads. Refused rather than ignored:
			// the request means something other than it appears to, and
			// whoever wrote it believes the extra value is doing
			// something.
			return fmt.Errorf("nymauth: function %q sets %q, which it does not fill", i.FunctionID, name)
		}
	}
	return nil
}

// CircuitInput renders these bounds as the age check's contribution to
// a circuit request.
func (b AgeBounds) CircuitInput() CircuitInput {
	return CircuitInput{
		FunctionID: FunctionAgeCheck,
		Values: map[string][]byte{
			InputEarliest: []byte(b.Earliest),
			InputCutoff:   []byte(b.Cutoff),
		},
	}
}
