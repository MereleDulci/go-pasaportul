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

func (r *Remote) Validate(ctx context.Context, token string) (*jwt.RegisteredClaims, error) {

	payload, err := jsonapi.Marshal([]ValdiationRequest{{
		ID:    "1",
		Token: r.Trim(token),
	}})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.host+"/v1/token-validations", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("validation failed")
	}

	validationResponse := make([]ValidationResponse, 0)
	if err := jsonapi.Unmarshal(buf, &validationResponse); err != nil {
		fmt.Println("error unmarhsaling", err)
		return nil, err
	}
	if len(validationResponse) < 1 {
		return nil, errors.New("no requested tokens are valid")
	}

	return &validationResponse[0].Claims, nil
}

func (r *Remote) ParseNoVerify(token string) (*jwt.RegisteredClaims, error) {
	parsed, err := jwt.ParseNoVerify([]byte(token))
	if err != nil {
		return nil, err
	}
	out := &jwt.RegisteredClaims{}
	if err := parsed.DecodeClaims(out); err != nil {
		return nil, err
	}

	return out, err
}
