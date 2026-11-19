package cache

// IssuanceStatusRecord is what the issuance status cache stores per issuance_id.
type IssuanceStatusRecord struct {
	IssuanceID       string `json:"issuance_id"`
	Scope            string `json:"scope"`
	AuthenticSource  string `json:"authentic_source"`
	Status           string `json:"status"`
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
	Deadline         int64  `json:"deadline,omitempty"`
	EventDescription string `json:"event_description,omitempty"`
}
