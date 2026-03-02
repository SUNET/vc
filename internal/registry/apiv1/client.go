package apiv1

import (
	"context"
	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// TokenStatusListIssuer defines the interface for the Token Status List issuer service
type TokenStatusListIssuer interface {
	GetCachedJWT(ctx context.Context, section int64) string
	GetCachedCWT(ctx context.Context, section int64) []byte
	GetAllSections(ctx context.Context) ([]int64, error)
}

// AdminDBStore defines the interface for admin GUI database operations on Token Status List
type AdminDBStore interface {
	FindOne(ctx context.Context, section, index int64) (*db.TokenStatusListDoc, error)
	UpdateStatus(ctx context.Context, section, index int64, status uint8) error
}

// CredentialSubjectsStore defines the interface for credential subjects database operations
type CredentialSubjectsStore interface {
	Search(ctx context.Context, firstName, lastName, dateOfBirth string) ([]*db.CredentialSubjectDoc, error)
	Add(ctx context.Context, doc *db.CredentialSubjectDoc) error
}

// Client holds the public api object
type Client struct {
	cfg                     *model.Cfg
	log                     *logger.Log
	tokenStatusListIssuer   TokenStatusListIssuer
	adminDB                 AdminDBStore
	credentialSubjects      CredentialSubjectsStore
}

//	@title		Registry API
//	@version	0.1.0
//	@BasePath	/api/v1

// New creates a new instance of the public api
func New(ctx context.Context, cfg *model.Cfg, tokenStatusListIssuer TokenStatusListIssuer, dbService *db.Service, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                   cfg,
		log:                   log.New("apiv1"),
		tokenStatusListIssuer: tokenStatusListIssuer,
	}

	if dbService != nil {
		c.adminDB = dbService.TokenStatusListColl
		c.credentialSubjects = dbService.CredentialSubjects
	}

	c.log.Info("Started")

	return c, nil
}
