package pasaportul

import (
	"context"
	"github.com/cristalhq/jwt/v5"
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
	ParseNoVerify(token string) (*jwt.RegisteredClaims, error)
}

type UserManager interface {
	CreateUserAccount(ctx context.Context, account *UserAccount) (string, error)
}

type ValdiationRequest struct {
	ID    string `jsonapi:"primary,token-validations"`
	Token string `jsonapi:"attr,token"`
}

type ValidationResponse struct {
	ID     string               `jsonapi:"primary,token-validation-results"`
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
