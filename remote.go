package pasaportul

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/MereleDulci/jsonapi"
	"github.com/cristalhq/jwt/v5"
	"io"
	"net/http"
)

func MakeRemote() *Remote {
	return &Remote{
		host: "https://pasaportul.mereledulci.md",
	}
}

type Remote struct {
	host string
}

// WithHostname replaces the base host to be used for authentication requests. Useful for testing.
func (r *Remote) WithHostname(host string) *Remote {
	r.host = host
	return r
}

func (r *Remote) Host() string {
	return r.host
}

// Trim cuts the token part from the Bearer header it usually comes with
func (pc *Remote) Trim(bearer string) string {
	bearerPrefixLen := len("Bearer ")
	if len(bearer) <= bearerPrefixLen {
		return ""
	}

	if bearer[:bearerPrefixLen] == "Bearer " {
		return bearer[bearerPrefixLen:]
	}

	return bearer
}

func (r *Remote) Validate(ctx context.Context, token string) (TokenClaims, error) {

	payload, err := jsonapi.Marshal([]ValdiationRequest{{
		ID:    "1",
		Token: r.Trim(token),
	}})
	if err != nil {
		return TokenClaims{}, fmt.Errorf("marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.host+"/v1/token-validations", bytes.NewBuffer(payload))
	if err != nil {
		return TokenClaims{}, fmt.Errorf("building request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("pasaportul request: %w", err)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("reading response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return TokenClaims{}, errors.New("validation failed")
	}

	validationResponse := make([]ValidationResponse, 0)
	if err := jsonapi.Unmarshal(buf, &validationResponse); err != nil {
		return TokenClaims{}, fmt.Errorf("parsing response: %w", err)
	}
	if len(validationResponse) < 1 {
		return TokenClaims{}, errors.New("no requested tokens are valid")
	}

	return validationResponse[0].Claims, nil
}

func (r *Remote) ParseNoVerify(token string) (TokenClaims, error) {
	parsed, err := jwt.ParseNoVerify([]byte(token))
	if err != nil {
		return TokenClaims{}, fmt.Errorf("parsing token: %w", err)
	}
	registered := &jwt.RegisteredClaims{}
	if err := parsed.DecodeClaims(registered); err != nil {
		return TokenClaims{}, fmt.Errorf("decoding claims: %w", err)
	}

	return TokenClaims{*registered, ExtraClaims{}}, err
}

func (r *Remote) IssueSingleUseToken(ctx context.Context, requestDetails IssueSingleUseTokenPayload) (*SingleUseToken, error) {

	payload, err := jsonapi.Marshal(requestDetails)

	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.host+"/v1/create-single-use-token", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("composing request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pasaportul request: %w", err)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	singleUseToken := &SingleUseToken{}
	if err := jsonapi.Unmarshal(buf, singleUseToken); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return singleUseToken, nil
}

func (r *Remote) ConsumeSingleUseToken(ctx context.Context, id string, code string) (TokenClaims, error) {

	payload, err := jsonapi.Marshal(ConsumeSingleUseTokenPayload{
		ID:   id,
		Code: code,
	})
	if err != nil {
		return TokenClaims{}, fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.host+"/v1/consume-single-use-token", bytes.NewBuffer(payload))
	if err != nil {
		return TokenClaims{}, fmt.Errorf("composing request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("pasaportul request: %w", err)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("reading response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return TokenClaims{}, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	consumedToken := &ValidationResponse{}
	if err := jsonapi.Unmarshal(buf, consumedToken); err != nil {
		return TokenClaims{}, fmt.Errorf("unmarshaling response: %w", err)
	}

	return consumedToken.Claims, nil
}
