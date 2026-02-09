package apiv1

import (
	"context"
	"time"
	"vc/pkg/socialsecurity"

	"github.com/brianvoe/gofakeit/v6"
)

// PDA1Service holds the PDA1 document type
type PDA1Service struct {
	Client *Client
}

func (s *PDA1Service) random(ctx context.Context, person *person) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := socialsecurity.PDA1Document{
		PersonalAdministrativeNumber: gofakeit.Numerify("##########"),
		Employer: socialsecurity.Employer{
			ID:   gofakeit.Numerify("##########"),
			Name: gofakeit.Company(),
		},
		WorkAddress: socialsecurity.WorkAddress{
			Formatted:      gofakeit.Street(),
			Street_address: gofakeit.Street(),
			House_number:   gofakeit.StreetNumber(),
			Postal_code:    gofakeit.Zip(),
			Locality:       gofakeit.City(),
			Region:         gofakeit.City(),
			Country:        s.Client.randomISO31661Alpha2EU(),
		},
		IssuingAuthority:   socialsecurity.IssuingAuthority{},
		IssuingCountry:     s.Client.randomISO31661Alpha2EU(),
		LegislationCountry: s.Client.randomISO31661Alpha2EU(),
		DateOfExpiry:       gofakeit.Date().String(),
		DateOfIssuance:     gofakeit.Date().String(),
		DocumentNumber:     gofakeit.UUID(),
	}

	return doc.Marshal()
}
