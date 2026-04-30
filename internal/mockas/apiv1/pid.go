package apiv1

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/model"

	"github.com/brianvoe/gofakeit/v6"
)

type PIDService struct {
	Client *Client
}

func (s *PIDService) random(ctx context.Context, person *person) (map[string]any, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	doc := model.Identity{
		GivenName:        person.sa.FirstName,
		FamilyName:       person.sa.LastName,
		BirthDate:        gofakeit.Date().Format("2006-01-02"),
		BirthPlace:       gofakeit.City(),
		Nationality:      []string{s.Client.randomISO31661Alpha2EU()},
		ExpiryDate:       "2033-01-01",
		IssuingAuthority: gofakeit.Company(),
		IssuingCountry:   s.Client.randomISO31661Alpha2EU(),
	}

	return doc.Marshal()

}
