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
	"reflect"
	"time"
)

type UserManagement struct {
	authorizer   Authorizer
	accessToken  string
	refreshToken string
}

func MakeUserManager(authClient Authorizer) *UserManagement {
	return &UserManagement{
		authorizer: authClient,
	}
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

func (um *UserManagement) InitPasswordReset(ctx context.Context, username string) (VerifiedAccountAction, error) {
	if err := um.ensureAccessToken(ctx); err != nil {
		return VerifiedAccountAction{}, err
	}

	raw, err := jsonapi.Marshal([]VerifiedAccountAction{{
		Username: username,
		Action:   "reset-password",
	}})
	if err != nil {
		return VerifiedAccountAction{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, um.authorizer.Host()+"/v1/verified-account-actions", bytes.NewBuffer(raw))
	if err != nil {
		return VerifiedAccountAction{}, err
	}

	req.Header.Add("Authorization", "Bearer "+um.accessToken)
	req.URL.Query().Add("include", "otp")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return VerifiedAccountAction{}, err
	}

	if res.StatusCode != http.StatusCreated {
		return VerifiedAccountAction{}, fmt.Errorf("failed to initiate password reset: %v", res.StatusCode)
	}

	buf, err := io.ReadAll(res.Body)

	if err != nil {
		return VerifiedAccountAction{}, err
	}

	created := make([]*VerifiedAccountAction, 0)
	if err := jsonapi.Unmarshal(buf, &created); err != nil {
		return VerifiedAccountAction{}, err
	}
	if len(created) == 0 {
		return VerifiedAccountAction{}, errors.New("failed to initiate password reset")
	}

	return *created[0], nil
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
