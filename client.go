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
	"reflect"
	"time"
)

type Authorizer interface {
	Host() string
	Trim(token string) string
	TokenClaims(token string) *jwt.RegisteredClaims
	PasswordLogin(username, password string) (*AccessToken, error)
	ClientCredentialsLogin() (*AccessToken, error)
}

type UserManager interface {
	CreateUserAccount(ctx context.Context, account *UserAccount) (string, error)
}

type Client struct {
	clientId     string
	clientSecret string
	verifier     jwt.Verifier
	host         string
}

type UserManagement struct {
	authorizer   Authorizer
	accessToken  string
	refreshToken string
}

type AccessToken struct {
	ID          string        `jsonapi:"primary,access-tokens"`
	Token       string        `jsonapi:"attr,token"`
	Account     *UserAccount  `jsonapi:"relation,account"`
	RefreshedBy *RefreshToken `jsonapi:"relation,refreshedBy"`
	IssuedAt    time.Time     `jsonapi:"attr,issuedAt,rfc3339"`
	ExpiresAt   time.Time     `jsonapi:"attr,expiresAt,rfc3339"`
	UsedAt      *time.Time    `jsonapi:"attr,usedAt,rfc3339"`
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

func MakeClient(clientId string, clientSecret string, publicKeyPath string) (*Client, error) {

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

	return &Client{
		clientId:     clientId,
		clientSecret: clientSecret,
		verifier:     verifier,
		host:         "https://pasaportul.mereledulci.md",
	}, nil
}

func MakeUserManager(authClient Authorizer) *UserManagement {
	return &UserManagement{
		authorizer: authClient,
	}
}

// WithHostname replaces the base host to be used for authentication requests. Useful for testing.
func (pc *Client) WithHostname(host string) *Client {
	pc.host = host
	return pc
}

// Host returns the current base host used for authentication requests.
func (pc *Client) Host() string {
	return pc.host
}

// Trim cuts the token part from the Bearer header it usually comes with
func (pc *Client) Trim(bearer string) string {
	bearerPrefixLen := len("Bearer ")
	if bearer[:bearerPrefixLen] == "Bearer " {
		return bearer[bearerPrefixLen:]
	}

	return bearer
}

// TokenClaims Validates token and parses registered claims from it. Returns nil if validation fails.
func (pc *Client) TokenClaims(bearer string) *jwt.RegisteredClaims {
	claims := &jwt.RegisteredClaims{}
	err := jwt.ParseClaims([]byte(pc.Trim(bearer)), pc.verifier, claims)
	if err != nil {
		return nil
	}

	return claims
}

func (pc *Client) PasswordLogin(username, password string) (*AccessToken, error) {
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
	res, err := http.Post(pc.host+"/v1/authenticate", "application/json", pasaportulPayload)
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

func (pc *Client) ClientCredentialsLogin() (*AccessToken, error) {
	pasaportulJson, err := json.Marshal(map[string]string{
		"client_id":     pc.clientId,
		"client_secret": pc.clientSecret,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return nil, err
	}

	pasaportulPayload := bytes.NewBuffer(pasaportulJson)
	res, err := http.Post(pc.host+"/v1/authenticate", "application/json", pasaportulPayload)
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
	if err := um.ensureAccessToken(); err != nil {
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

	if res.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(res.Body)
		fmt.Println(string(buf))
		return "", errors.New("failed to create account")
	}

	buf, err := io.ReadAll(res.Body)
	fmt.Println(string(buf))

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

func (um *UserManagement) ensureAccessToken() error {
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

	accessToken, err := um.authorizer.ClientCredentialsLogin()
	if err != nil {
		return err
	}

	um.accessToken = accessToken.Token
	um.refreshToken = accessToken.RefreshedBy.Token

	return nil
}
