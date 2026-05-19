package apiv1

import (
	"sync"
	"time"
)

// ScenarioResult holds the outcome of a scenario execution
type ScenarioResult struct {
	ScenarioName string       `json:"scenario_name"`
	Type         string       `json:"type"`
	StartedAt    time.Time    `json:"started_at"`
	CompletedAt  time.Time    `json:"completed_at"`
	Success      bool         `json:"success"`
	Error        string       `json:"error,omitempty"`
	Steps        []StepResult `json:"steps"`
}

// StepResult holds the outcome of a single step within a scenario
type StepResult struct {
	Name        string    `json:"name"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Detail      string    `json:"detail,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ResultStore keeps a history of scenario execution results
type ResultStore struct {
	mu      sync.RWMutex
	results []*ScenarioResult
}

// NewResultStore creates a new result store
func NewResultStore() *ResultStore {
	return &ResultStore{
		results: make([]*ScenarioResult, 0),
	}
}

// Add appends a scenario result
func (r *ResultStore) Add(result *ScenarioResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, result)
}
