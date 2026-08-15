package db

import (
	"context"
)

// TokenStatusListStore defines the interface for token status list operations
type TokenStatusListStore interface {
	// CountAll returns the total number of status entries across all sections.
	CountAll(ctx context.Context) (int64, error)
	// CountDecoysInSectionWithLimit counts decoy entries in the given section,
	// stopping early once limit is reached. Much faster than an unbounded count
	// when only a threshold check is needed (e.g. "are there more than N?").
	CountDecoysInSectionWithLimit(ctx context.Context, section int64, limit int64) (int64, error)
	CreateNewSection(ctx context.Context, section int64, sectionSize int64) error
	Add(ctx context.Context, section int64, status uint8) (int64, error)
	UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error
	GetAllStatusesForSection(ctx context.Context, section int64) ([]uint8, error)
	InitializeIfEmpty(ctx context.Context) error
	FindOne(ctx context.Context, section, index int64) (*TokenStatusListDoc, error)
}

// TokenStatusListMetadataStore defines the interface for token status list metadata operations
type TokenStatusListMetadataStore interface {
	GetCurrentSection(ctx context.Context) (int64, error)
	UpdateCurrentSection(ctx context.Context, newSection int64) error
	GetAllSections(ctx context.Context) ([]int64, error)
}

// CredentialSubjectsStore defines the interface for credential subjects operations
type CredentialSubjectsStore interface {
	Search(ctx context.Context, identifier string) ([]*CredentialSubjectDoc, error)
	Add(ctx context.Context, doc *CredentialSubjectDoc) error
}

// Ensure concrete types implement the interfaces
var (
	_ TokenStatusListStore         = (*TokenStatusListColl)(nil)
	_ TokenStatusListMetadataStore = (*TokenStatusListMetadataColl)(nil)
	_ CredentialSubjectsStore      = (*CredentialSubjectsColl)(nil)
)
