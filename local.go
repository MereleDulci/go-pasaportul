package pasaportul

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
		return nil, fmt.Errorf("opening public key: %w", err)
	}

	pemContent, err := io.ReadAll(pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	if err := pubKeyFile.Close(); err != nil {
		return nil, fmt.Errorf("closing public key: %w", err)
	}

	block, _ := pem.Decode(pemContent)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid pem block type")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	verifier, err := jwt.NewVerifierEdDSA(pub.(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("creating elliptic verifier: %w", err)
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
func (pc *Local) Validate(ctx context.Context, bearer string) (TokenClaims, error) {
	registered := &jwt.RegisteredClaims{}
	err := jwt.ParseClaims([]byte(pc.Trim(bearer)), pc.verifier, registered)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("parsing claims: %w", err)
	}

	if !registered.IsValidAt(time.Now().UTC()) {
		return TokenClaims{}, errors.New("token is not valid at a given time")
	}

	if slices.Contains(registered.Audience, pc.clientId) == false {
		return TokenClaims{}, errors.New("invalid audience")
	}

	return TokenClaims{*registered, ExtraClaims{}}, nil
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
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	pasaportulPayload := bytes.NewBuffer(pasaportulJson)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pc.host+"/v1/authenticate", pasaportulPayload)
	if err != nil {
		return nil, fmt.Errorf("composing request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pasaportul request: %w", err)
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	accessToken := &AccessToken{}
	if err := jsonapi.Unmarshal(resBytes, accessToken); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
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
		return nil, fmt.Errorf("marshalling payload: %w", err)
	}

	pasaportulPayload := bytes.NewBuffer(pasaportulJson)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pc.host+"/v1/authenticate", pasaportulPayload)
	if err != nil {
		return nil, fmt.Errorf("composing request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pasaportul request: %w", err)
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	accessToken := &AccessToken{}
	if err := jsonapi.Unmarshal(resBytes, accessToken); err != nil {
		return nil, fmt.Errorf("unmarshaling responsee: %w", err)
	}

	return accessToken, nil
}
