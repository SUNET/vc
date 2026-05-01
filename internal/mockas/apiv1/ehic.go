package apiv1

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/socialsecurity"

	"github.com/brianvoe/gofakeit/v6"
)

// EHICService holds the EHIC document type
type EHICService struct {
	Client *Client
}

func (s *EHICService) random(ctx context.Context, person *person) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := socialsecurity.EHICDocument{
		PersonalAdministrativeNumber: gofakeit.Numerify("##########"),
		IssuingAuthority: socialsecurity.IssuingAuthority{
			ID:   fmt.Sprintf("%s:%s", gofakeit.RandomString([]string{"SE", "DK", "NO", "FI"}), gofakeit.Numerify("####")),
			Name: gofakeit.Company(),
		},
		IssuingCountry: gofakeit.RandomString([]string{"SE", "DK", "NO", "FI"}),
		DateOfExpiry:   gofakeit.Date().String(),
		DateOfIssuance: gofakeit.Date().String(),
		DocumentNumber: gofakeit.UUID(),
	}

	return doc.Marshal()
}
