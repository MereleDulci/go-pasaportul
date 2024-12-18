package pasaportul

import (
	"context"
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
	Validate(ctx context.Context, token string) (TokenClaims, error)
	ParseNoVerify(token string) (TokenClaims, error)
}

type UserManager interface {
	CreateUserAccount(ctx context.Context, account *UserAccount) (string, error)
	InitPasswordReset(ctx context.Context, username string) (VerifiedAccountAction, error)
}

type ValdiationRequest struct {
	ID    string `jsonapi:"primary,token-validations"`
	Token string `jsonapi:"attr,token"`
}

type ValidationResponse struct {
	ID     string      `jsonapi:"primary,token-validation-results"`
	Claims TokenClaims `jsonapi:"attr,claims"`
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

type OneTimePassword struct {
	ID        string     `jsonapi:"primary,one-time-passwords"`
	Code      string     `jsonapi:"attr,code"`
	IssuedAt  time.Time  `jsonapi:"attr,issuedAt,rfc3339"`
	ExpiresAt time.Time  `jsonapi:"attr,expiresAt,rfc3339"`
	UsedAt    *time.Time `jsonapi:"attr,used,rfc3339"`
}

type UserAccount struct {
	ID         string       `jsonapi:"primary,user-accounts"`
	Username   string       `jsonapi:"attr,username"`
	Password   string       `jsonapi:"attr,password"`
	ClientApps []*ClientApp `jsonapi:"relation,clientApps"`
}

type ActionPayloadItem struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type VerifiedAccountAction struct {
	ID               string              `jsonapi:"primary,verified-account-actions"`
	Account          *UserAccount        `jsonapi:"relation,account"`
	OTP              *OneTimePassword    `jsonapi:"relation,otp"`
	Username         string              `jsonapi:"attr,username"`
	Action           string              `jsonapi:"attr,action"`
	VerificationCode string              `jsonapi:"attr,verificationCode,omitempty"`
	ActionPayload    []ActionPayloadItem `jsonapi:"attr,actionPayload,omitEmpty"`
	RequestedAt      time.Time           `jsonapi:"attr,createdAt" bson:"createdAt"`
	ExecutedAt       time.Time           `jsonapi:"attr,executedAt" bson:"executedAt"`
}

type SingleUseToken struct {
	ID         string                 `jsonapi:"primary,single-use-tokens"`
	Code       string                 `jsonapi:"attr,code"`
	Audience   []string               `jsonapi:"attr,audience"`
	Claims     map[string]interface{} `jsonapi:"attr,claims"`
	Account    *UserAccount           `jsonapi:"relation,account"`
	IssuedAt   time.Time              `jsonapi:"attr,issuedAt"`
	NotBefore  time.Time              `jsonapi:"attr,notBefore"`
	ExpiresAt  time.Time              `jsonapi:"attr,expiresAt"`
	ConsumedAt *time.Time             `jsonapi:"attr,consumedAt"`
}

type IssueSingleUseTokenPayload struct {
	ID         string                 `jsonapi:"primary,issue-single-use-tokens"`
	From       string                 `jsonapi:"attr,from"`
	NotBefore  *time.Time             `jsonapi:"attr,notBefore"`
	ValidUntil *time.Time             `jsonapi:"attr,validUntil"`
	Claims     map[string]interface{} `jsonapi:"attr,claims"`
}

type ConsumeSingleUseTokenPayload struct {
	ID   string `jsonapi:"primary,consume-single-use-tokens"`
	Code string `jsonapi:"attr,code"`
}

type ClientApp struct {
	ID string `jsonapi:"primary,client-apps"`
}
