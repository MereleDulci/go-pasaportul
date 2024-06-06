package pasaportul

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/MereleDulci/jsonapi"
	"github.com/cristalhq/jwt/v5"
	"io"
	"net/http"
	"os"
	"slices"
	"time"
)

func MakeLocal(clientId string, clientSecret string, publicKeyPath string) (*Local, error) {

	pubKeyFile, err := os.Open(publicKeyPath)
	if err != nil {
		return nil, err
	}

	pemContent, err := io.ReadAll(pubKeyFile)
	if err != nil {
		return nil, err
	}

	if err := pubKeyFile.Close(); err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemContent)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid pem block type")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	verifier, err := jwt.NewVerifierEdDSA(pub.(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}

	return &Local{
		Remote:       MakeRemote(),
		clientId:     clientId,
		clientSecret: clientSecret,
		verifier:     verifier,
	}, nil
}

type Local struct {
	*Remote
	clientId     string
	clientSecret string
	verifier     jwt.Verifier
}

func (pc *Local) WithHostname(host string) *Local {
	pc.Remote.WithHostname(host)
	return pc
}

// Host returns the current base host used for authentication requests.
func (pc *Local) Host() string {
	return pc.Remote.host
}

// Validate Validates token locally using configured key and parses registered claims from it. Returns nil if validation fails.
func (pc *Local) Validate(ctx context.Context, bearer string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	err := jwt.ParseClaims([]byte(pc.Trim(bearer)), pc.verifier, claims)
	if err != nil {
		return nil, err
	}

	if !claims.IsValidAt(time.Now().UTC()) {
		return nil, errors.New("token is not valid at a given time")
	}

	if slices.Contains(claims.Audience, pc.clientId) == false {
		return nil, errors.New("invalid audience")
	}

	return claims, nil
}

func (pc *Local) PasswordLogin(ctx context.Context, username, password string) (*AccessToken, error) {
	pasaportulJson, err := json.Marshal(map[string]string{
		"client_id":     pc.clientId,
		"client_secret": pc.clientSecret,
		"grant_type":    "password",
		"username":      username,
		"password":      password,
	})
	if err != nil {
		return nil, err
	}

	pasaportulPayload := bytes.NewBuffer(pasaportulJson)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pc.host+"/v1/authenticate", pasaportulPayload)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken{}
	if err := jsonapi.Unmarshal(resBytes, accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (pc *Local) ClientCredentialsLogin(ctx context.Context) (*AccessToken, error) {
	pasaportulJson, err := json.Marshal(map[string]string{
		"client_id":     pc.clientId,
		"client_secret": pc.clientSecret,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return nil, err
	}

	pasaportulPayload := bytes.NewBuffer(pasaportulJson)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pc.host+"/v1/authenticate", pasaportulPayload)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken{}
	if err := jsonapi.Unmarshal(resBytes, accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}
