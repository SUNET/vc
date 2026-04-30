package apiv1

import (
	"testing"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchScope(t *testing.T) {
	t.Parallel()

	cc := &model.CredentialMetadata{Format: "vc+sd-jwt"}

	tests := []struct {
		name      string
		cfg       *model.Cfg
		scopes    []string
		wantScope string
		wantCC    *model.CredentialMetadata
		wantErr   string
	}{
		{
			name: "single scope matches",
			cfg: &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"diploma": cc,
					},
				},
			},
			scopes:    []string{"diploma"},
			wantScope: "diploma",
			wantCC:    cc,
		},
		{
			name: "first matching scope wins",
			cfg: &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"ehic":    cc,
						"diploma": cc,
					},
				},
			},
			scopes:    []string{"diploma", "ehic"},
			wantScope: "diploma",
			wantCC:    cc,
		},
		{
			name: "second scope matches when first does not",
			cfg: &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"ehic": cc,
					},
				},
			},
			scopes:    []string{"unknown", "ehic"},
			wantScope: "ehic",
			wantCC:    cc,
		},
		{
			name: "no scope matches returns error",
			cfg: &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"diploma": cc,
					},
				},
			},
			scopes:  []string{"unknown"},
			wantErr: "no matching credential constructor for scopes: [unknown]",
		},
		{
			name: "empty scopes returns error",
			cfg: &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"diploma": cc,
					},
				},
			},
			scopes:  []string{},
			wantErr: "no matching credential constructor for scopes: []",
		},
		{
			name:    "nil Common returns error",
			cfg:     &model.Cfg{},
			scopes:  []string{"diploma"},
			wantErr: "no matching credential constructor for scopes: [diploma]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{cfg: tt.cfg}

			gotScope, gotCC, err := c.matchScope(tt.scopes)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				assert.Empty(t, gotScope)
				assert.Nil(t, gotCC)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantScope, gotScope)
				assert.Equal(t, tt.wantCC, gotCC)
			}
		})
	}
}
