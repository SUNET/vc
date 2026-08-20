package openid4vp

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
)

var mockQRCode = "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAABm0lEQVR4nOyYQc7jIAyFH+qCZY6Qo3A0OBpH6RGyZBHxRs+Qv0xn1qOJlRepVcjXRW3Hz4BHjx79t9oota2C57hpc8kX8AbwalvNPCPfy5IzILGPuxf5Rg5tWfIGbBUdwM5CzwBSsRJIboGrhHnGA8hsnyVHwNWjcjjjsdccvnuUC2BeG0sgDyT+LLkCVNV6ND53sqsCcmC7E6D3NZz6DmashVPOAMXmZYGSsaYS2uc3fgD1m454IPdhrIikKri5AoBkyU8cvjnz3AFvQAGi0m2Pco9kXQzFCbBf43qYvsmvdLsANmrMi6yZczAA5J4nXAEq+zHs0day+U4B3AFFWzBeVR14DPv5kQdAJaBEc8Qh/RYBP4AuOzcQYPNDs+0Ymy9ANf4iqyZEzY5qUTMoNwJmUtV9bX7Q/7vcZdHNgWWfNfOocC1xcALMEy3yshLFYfVNJ8A88MjX6G6B+fOQxAUwDjCPvaJHba7XdLsC5KWbWpUilP8Sh5sDVtVIRdtSVTWpA4UTvoDZo+zlte7UvodeD8CjR4/+uX4NANelC0pyhAZmAAAAAElFTkSuQmCC"

func TestGenerateQR(t *testing.T) {
	type args struct {
		uri           string
		recoveryLevel qrcode.RecoveryLevel
		size          int
	}
	type want struct {
		err     error
		qrReply *QRReply
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "valid uri",
			args: args{
				uri:           "openid4vp://authorize?key=val",
				recoveryLevel: qrcode.Medium,
				size:          256,
			},
			want: want{
				err: nil,
				qrReply: &QRReply{
					Base64Image: mockQRCode,
					URI:         "openid4vp://authorize?key=val",
				},
			},
		},
		{
			name: "not a valid uri",
			args: args{
				uri:           "no_valid_uri",
				recoveryLevel: qrcode.Medium,
				size:          256,
			},
			want: want{
				err: &url.Error{Op: "parse", URL: "no_valid_uri", Err: fmt.Errorf("invalid URI for request")},

				qrReply: &QRReply{
					Base64Image: "",
					URI:         "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := url.ParseRequestURI(tt.args.uri)
			if err != nil {
				assert.Equal(t, tt.want.err, err)
			} else {
				got, err := GenerateQR(uri, tt.args.recoveryLevel, tt.args.size)
				assert.Equal(t, tt.want.err, err)
				assert.Equal(t, tt.want.qrReply.URI, got.URI)
				assert.Equal(t, tt.want.qrReply.Base64Image, got.Base64Image)
			}
		})
	}
}

func TestGenerateQRV2(t *testing.T) {
	tts := []struct {
		name string
		data string
		want string
	}{
		{
			name: "valid data",
			data: "openid4vp://authorize?key=val",
			want: mockQRCode,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateQRV2(t.Context(), tt.data)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
