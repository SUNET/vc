package openid4vp

import (
	"context"
	"errors"
	"net/url"
	"path"
	"time"
)

var ErrInvalidVerifierHost = errors.New("verifier host is invalid or empty")

func (r *RequestObject) CreateAuthorizationRequestURI(ctx context.Context, verifierHost, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	u := url.URL{
		Scheme: "openid4vp",
		Path:   "cb",
	}

	q := u.Query()
	q.Set("client_id", r.ClientID)

	requestObjectURL, err := r.createRequestURI(ctx, verifierHost, id)
	if err != nil {
		return "", err
	}

	q.Set("request_uri", requestObjectURL)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func (r *RequestObject) createRequestURI(ctx context.Context, verifierHost, id string) (string, error) {
	if verifierHost == "" {
		return "", ErrInvalidVerifierHost
	}

	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	baseURL, err := url.Parse(verifierHost)
	if err != nil {
		return "", err
	}

	baseURL.Path = path.Join(baseURL.Path, "verification", "request-object")

	q := baseURL.Query()
	q.Set("id", id)
	baseURL.RawQuery = q.Encode()

	return baseURL.String(), nil
}
