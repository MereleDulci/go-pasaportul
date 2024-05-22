package pasaportul

import (
	"fmt"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"github.com/MereleDulci/jsonapi"
	"github.com/cristalhq/jwt/v5"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"
)

type Authorizer interface {
	Host() string
	PasswordLogin(ctx context.Context, username string, password string) (*AccessToken, error)
	ClientCredentialsLogin(context.Context) (*AccessToken, error)
}

type Validator interface {
	Host() string
	Trim(string) string
	Validate(ctx context.Context, token string) (*jwt.RegisteredClaims, error)
}

type UserManager interface {
	CreateUserAccount(ctx context.Context, account *UserAccount) (string, error)
}

type Remote struct {
	host string
}

type Local struct {
	*Remote
	clientId     string
	clientSecret string
	verifier     jwt.Verifier
}

type UserManagement struct {
	authorizer   Authorizer
	accessToken  string
	refreshToken string
}

type ValdiationRequest struct {
	ID   string `jsonapi:"primary,token-validations"`
	Token string `jsonapi:"attr,token"`
}

type ValidationResponse struct {
	ID                   string `jsonapi:"primary,token-validation-results"`
	Claims jwt.RegisteredClaims `jsonapi:"attr,claims"`
}

type AccessToken struct {
	ID          string        `jsonapi:"primary,access-tokens"`
	Token       string        `jsonapi:"attr,token"`
	Account     *UserAccount  `jsonapi:"relation,account"`
	RefreshedBy *RefreshToken `jsonapi:"relation,refreshedBy"`
	IssuedAt    time.Time     `jsonapi:"attr,issuedAt,rfc3339"`
	ExpiresAt   time.Time     `jsonapi:"attr,expiresAt,rfc3339"`
}

type RefreshToken struct {
	ID         string       `jsonapi:"primary,refresh-tokens"`
	Token      string       `jsonapi:"attr,token"`
	Account    *UserAccount `jsonapi:"relation,account"`
	IssuedAt   time.Time    `jsonapi:"attr,issuedAt,rfc3339"`
	ExpiresAt  time.Time    `jsonapi:"attr,expiresAt,rfc3339"`
	ConsumedAt *time.Time   `jsonapi:"attr,consumedAt,rfc3339"`
}

type UserAccount struct {
	ID       string `jsonapi:"primary,user-accounts"`
	Username string `jsonapi:"attr,username"`
	Password string `jsonapi:"attr,password"`
}

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
	if block.Type != "PUBLIC KEY" {
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
		Remote: MakeRemote(),
		clientId:     clientId,
		clientSecret: clientSecret,
		verifier:     verifier,
	}, nil
}

func MakeUserManager(authClient Authorizer) *UserManagement {
	return &UserManagement{
		authorizer: authClient,
	}
}

func MakeRemote() *Remote {
	return &Remote{
		host: "https://pasaportul.mereledulci.md",
	}
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
	if err != nil  {
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

func (um *UserManagement) CreateUserAccount(ctx context.Context, account *UserAccount) (string, error) {
	if err := um.ensureAccessToken(ctx); err != nil {
		return "", err
	}

	raw, err := jsonapi.Marshal([]*UserAccount{account})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, um.authorizer.Host()+"/v1/user-accounts", bytes.NewBuffer(raw))
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "Bearer "+um.accessToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	switch res.StatusCode {
	case http.StatusConflict:
		return "", errors.New("account already exists")
	case http.StatusCreated:
		break
	default:
		return "", errors.New("failed to create account")
	}

	buf, err := io.ReadAll(res.Body)

	if err != nil {
		return "", err
	}

	created, err := jsonapi.UnmarshalManyAsType(buf, reflect.TypeOf(new(UserAccount)))
	if err != nil {
		return "", err
	}

	if len(created) == 0 {
		return "", errors.New("failed to create account")
	}

	return created[0].(*UserAccount).ID, nil
}

func (um *UserManagement) ensureAccessToken(ctx context.Context) error {
	if um.accessToken != "" {
		t, err := jwt.ParseNoVerify([]byte(um.accessToken))
		if err != nil {
			return err
		}
		claims := &jwt.RegisteredClaims{}
		if err := t.DecodeClaims(claims); err != nil {
			return err
		}
		if claims.IsValidAt(time.Now().Add(time.Second * 30)) {
			return nil
		}
	}

	accessToken, err := um.authorizer.ClientCredentialsLogin(ctx)
	if err != nil {
		return err
	}

	um.accessToken = accessToken.Token
	um.refreshToken = accessToken.RefreshedBy.Token

	return nil
}

// WithHostname replaces the base host to be used for authentication requests. Useful for testing.
func (r *Remote) WithHostname( host string) *Remote {
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

func (r *Remote) Validate(ctx context.Context, token string) (*jwt.RegisteredClaims, error){

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