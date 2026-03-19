package discoverfeatures

import (
	"fmt"
	"strings"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
)

const (
	// Protocol identifier
	ProtocolURI = "https://didcomm.org/discover-features/2.0"

	// Message types
	TypeQueries  = ProtocolURI + "/queries"
	TypeDisclose = ProtocolURI + "/disclose"

	// Feature types
	FeatureTypeProtocol   = "protocol"
	FeatureTypeGoalCode   = "goal-code"
	FeatureTypeHeader     = "header"
	FeatureTypeAttachment = "attachment"
)

// Query represents a feature discovery query.
type Query struct {
	// FeatureType is the type of feature being queried (protocol, goal-code, etc.)
	FeatureType string `json:"feature-type"`

	// Match is the pattern to match (supports wildcards)
	Match string `json:"match,omitempty"`
}

// QueryBody contains the body of a queries message.
type QueryBody struct {
	Queries []Query `json:"queries"`
}

// Feature represents a disclosed feature.
type Feature struct {
	// FeatureType is the type of feature
	FeatureType string `json:"feature-type"`

	// ID is the feature identifier (e.g., protocol URI)
	ID string `json:"id"`

	// Roles supported for this feature (for protocols)
	Roles []string `json:"roles,omitempty"`
}

// DiscloseBody contains the body of a disclose message.
type DiscloseBody struct {
	Disclosures []Feature `json:"disclosures"`
}

// QueryOption configures query creation.
type QueryOption func(*queryConfig)

type queryConfig struct {
	queries []Query
}

// QueryProtocols adds a protocol query with the given pattern.
func QueryProtocols(pattern string) QueryOption {
	return func(c *queryConfig) {
		c.queries = append(c.queries, Query{
			FeatureType: FeatureTypeProtocol,
			Match:       pattern,
		})
	}
}

// QueryGoalCodes adds a goal-code query with the given pattern.
func QueryGoalCodes(pattern string) QueryOption {
	return func(c *queryConfig) {
		c.queries = append(c.queries, Query{
			FeatureType: FeatureTypeGoalCode,
			Match:       pattern,
		})
	}
}

// AddQuery adds a custom query.
func AddQuery(featureType, match string) QueryOption {
	return func(c *queryConfig) {
		c.queries = append(c.queries, Query{
			FeatureType: featureType,
			Match:       match,
		})
	}
}

// NewQuery creates a new feature discovery query message.
func NewQuery(from, to string, opts ...QueryOption) (*message.Message, error) {
	cfg := &queryConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.queries) == 0 {
		return nil, fmt.Errorf("%w: at least one query is required", didcomm.ErrInvalidMessage)
	}

	body := QueryBody{
		Queries: cfg.queries,
	}

	msgOpts := []message.Option{
		message.WithType(TypeQueries),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set query body: %w", err)
	}

	return msg, nil
}

// NewDisclose creates a disclose response message.
func NewDisclose(query *message.Message, features []Feature) (*message.Message, error) {
	if !IsQuery(query) {
		return nil, fmt.Errorf("%w: expected %s, got %s", didcomm.ErrInvalidMessage, TypeQueries, query.Type)
	}

	// Response goes back to the sender
	from := ""
	if len(query.To) > 0 {
		from = query.To[0]
	}

	to := query.From

	body := DiscloseBody{
		Disclosures: features,
	}

	msgOpts := []message.Option{
		message.WithType(TypeDisclose),
		message.WithThreadID(query.ThreadID()),
	}

	if from != "" {
		msgOpts = append(msgOpts, message.WithFrom(from))
	}
	if to != "" {
		msgOpts = append(msgOpts, message.WithTo(to))
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set disclose body: %w", err)
	}

	return msg, nil
}

// IsQuery checks if a message is a discover-features query.
func IsQuery(msg *message.Message) bool {
	return msg.Type == TypeQueries
}

// IsDisclose checks if a message is a discover-features disclosure.
func IsDisclose(msg *message.Message) bool {
	return msg.Type == TypeDisclose
}

// GetQueryBody extracts the queries from a query message.
func GetQueryBody(msg *message.Message) (*QueryBody, error) {
	if !IsQuery(msg) {
		return nil, fmt.Errorf("%w: not a query message", didcomm.ErrInvalidMessage)
	}

	var body QueryBody
	if err := msg.GetBody(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

// GetDiscloseBody extracts the disclosures from a disclose message.
func GetDiscloseBody(msg *message.Message) (*DiscloseBody, error) {
	if !IsDisclose(msg) {
		return nil, fmt.Errorf("%w: not a disclose message", didcomm.ErrInvalidMessage)
	}

	var body DiscloseBody
	if err := msg.GetBody(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

// ProtocolRegistry holds information about supported protocols.
type ProtocolRegistry struct {
	protocols []Feature
	goalCodes []Feature
}

// NewProtocolRegistry creates a new protocol registry.
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{}
}

// RegisterProtocol registers a supported protocol.
func (r *ProtocolRegistry) RegisterProtocol(uri string, roles ...string) {
	r.protocols = append(r.protocols, Feature{
		FeatureType: FeatureTypeProtocol,
		ID:          uri,
		Roles:       roles,
	})
}

// RegisterGoalCode registers a supported goal code.
func (r *ProtocolRegistry) RegisterGoalCode(code string) {
	r.goalCodes = append(r.goalCodes, Feature{
		FeatureType: FeatureTypeGoalCode,
		ID:          code,
	})
}

// HandleQuery processes a query and returns matching features.
func (r *ProtocolRegistry) HandleQuery(query *message.Message) (*message.Message, error) {
	queryBody, err := GetQueryBody(query)
	if err != nil {
		return nil, err
	}

	var disclosures []Feature

	for _, q := range queryBody.Queries {
		switch q.FeatureType {
		case FeatureTypeProtocol:
			for _, p := range r.protocols {
				if matchPattern(q.Match, p.ID) {
					disclosures = append(disclosures, p)
				}
			}
		case FeatureTypeGoalCode:
			for _, g := range r.goalCodes {
				if matchPattern(q.Match, g.ID) {
					disclosures = append(disclosures, g)
				}
			}
		}
	}

	return NewDisclose(query, disclosures)
}

// matchPattern checks if a value matches a pattern with wildcards.
// Supports "*" as a wildcard for any characters.
func matchPattern(pattern, value string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}

	// Handle prefix wildcard (e.g., "https://didcomm.org/*")
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		prefix := before
		return strings.HasPrefix(value, prefix)
	}

	// Exact match
	return pattern == value
}
