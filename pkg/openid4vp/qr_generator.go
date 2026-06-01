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

func GenerateQR(uri *url.URL, recoveryLevel qrcode.RecoveryLevel, size int) (*QRReply, error) {
	if size == 0 {
		size = 256
	}

	var buf bytes.Buffer
	qrCode, err := qrcode.New(uri.String(), recoveryLevel)
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
		URI:         uri.String(),
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
