package openid4vp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/url"

	"github.com/skip2/go-qrcode"
)

// QRReply is a collection of fields representing a QRReply code
// TODO(masv): not sure if the type should include uri,request_uri,client_id,session_id
type QRReply struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URI         string `json:"uri" bson:"uri" validate:"required"`
	// RequestURI  string `json:"request_uri" bson:"request_uri" validate:"required"`
	// ClientID    string `json:"client_id" bson:"client_id" validate:"required"`
	// SessionID   string `json:"session_id" bson:"session_id" validate:"required"`
}

// GenerateQR takes the URI as a string rather than a *url.URL on purpose.
//
// url.URL cannot faithfully round-trip a URI whose authority component is
// empty. Parsing "openid-credential-offer://?credential_offer=..." yields an
// empty Host and Path, and URL.String() then writes the "//" back only when
// one of Host, Path or User is non-empty - so the value that comes out is
// "openid-credential-offer:?credential_offer=...". That is a different URI
// from the one the caller built, and the spec's own examples use the "//"
// form (OpenID4VCI 1.0 section 4.1.2). Accepting a *url.URL here silently
// corrupted every "scheme:?query" URI encoded into a QR code.
func GenerateQR(uri string, recoveryLevel qrcode.RecoveryLevel, size int) (*QRReply, error) {
	if size == 0 {
		size = 256
	}

	// Validated, but never re-serialised: the QR carries the caller's own
	// string, so an authority-less URI reaches the wallet as it was written.
	if _, err := url.ParseRequestURI(uri); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	qrCode, err := qrcode.New(uri, recoveryLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create QRReply-code: %w", err)
	}

	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, qrCode.Image(size)); err != nil {
		return nil, err
	}

	if err := encoder.Close(); err != nil {
		return nil, err
	}

	return &QRReply{
		Base64Image: buf.String(),
		URI:         uri,
	}, nil
}

func GenerateQRV2(ctx context.Context, data string) (string, error) {
	qrCode, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("failed to create QR code: %w", err)
	}

	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, qrCode.Image(256)); err != nil {
		return "", err
	}

	if err := encoder.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}
