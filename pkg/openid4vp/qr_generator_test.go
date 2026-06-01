package openid4vp

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
)

var mockQRCode = "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAABoklEQVR4nOyYQdKkIAyFH+WCpUfwKBwNjsZRPIJLFhZvKgnOb0+7nvpJmUV3iZ8LkkBegtdee+3X2kqxtlbwtIc2lnwBO4ClrTXzjNxvS86AxG5PC7kjh3Zb8gasFR3AxkLPAFLRCCe3wJXCPOMBZAEe0n524LqjcjjjsVXJ6udLbGrgL1cCeSARzzY5ICksr+x3I7tkQA5sMwFyHMMp/0HrZuEwZ4BsfVE/SN1MJbSfb/wAct90xAO5W91EJCWDmysASBrbRKubI84d8AYUIOrhlVe5R7LeCooTYLvkehh1k/+E2wWwUmReZM0cwgCQ6vlzeF0AktUm9qhrWetOAdwBRVowXlkdeFj5cQVIhDWrzQ/pwwN+AKhohwGqH5q2Yx+a1gEgKbyQVQSgSEO7o3gXGBMAI6iqzEUeyP6u6uIHuPVZI47ijZsfnABjokVtsLSdVE37NbibHRgDj3xJd3XMw8jLA2DzyWOr6FF653u4XQHWb1q4pV35nuzNDdj4KhXpOiWryV2aT/gCeEl3c4rWzU/R6wF47bXX/rv9CQAA///XpQtKbKk63AAAAABJRU5ErkJggg=="

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
