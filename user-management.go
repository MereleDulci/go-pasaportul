package pasaportul

import (
	"bytes"
	"context"
	"encoding/json"
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

func (um *UserManagement) tryRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := um.ensureAccessToken(ctx); err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+um.accessToken)

	fmt.Println(um.accessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return res, err
}

func (um *UserManagement) CreateUserAccount(ctx context.Context, account *UserAccount) (string, error) {
	raw, err := jsonapi.Marshal([]*UserAccount{account})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, um.authorizer.Host()+"/v1/user-accounts", bytes.NewBuffer(raw))
	if err != nil {
		return "", err
	}

	res, err := um.tryRequest(ctx, req)

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

	req.URL.Query().Add("include", "otp")

	res, err := um.tryRequest(ctx, req)

	if err != nil {
		return VerifiedAccountAction{}, err
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return VerifiedAccountAction{}, err
	}

	if res.StatusCode != http.StatusCreated {
		fmt.Println(string(buf))
		return VerifiedAccountAction{}, fmt.Errorf("failed to initiate password reset: %v", res.StatusCode)
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

func (um *UserManagement) ChangeUsername(ctx context.Context, id string, newUsername string) error {
	raw, err := json.Marshal([]jsonapi.PatchOp{
		{Op: "replace", Path: "/username", Value: newUsername},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, um.authorizer.Host()+"/v1/user-accounts/"+id, bytes.NewBuffer(raw))
	if err != nil {
		return err
	}

	res, err := um.tryRequest(ctx, req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update account: %v", res.StatusCode)
	}

	return nil

}

func (um *UserManagement) ChangePassword(ctx context.Context, username string, newPassword string) error {
	verifiedAction, err := um.InitPasswordReset(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to initiate password reset: %w", err)
	}

	raw, err := json.Marshal([]jsonapi.PatchOp{
		{Op: "replace", Path: "/verificationCode", Value: verifiedAction.OTP.Code},
		{Op: "replace", Path: "/actionPayload", Value: []ActionPayloadItem{{Key: "password", Value: newPassword}}},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, um.authorizer.Host()+"/v1/verified-account-actions/"+verifiedAction.ID, bytes.NewBuffer(raw))
	if err != nil {
		return fmt.Errorf("composing request: %w", err)
	}

	res, err := um.tryRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK:
		return nil
	default:
		buf, _ := io.ReadAll(res.Body)
		return fmt.Errorf("failed to change password: %v, response: %s", res.StatusCode, string(buf))
	}
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
		if claims.IsValidAt(time.Now().Add(time.Minute * 10)) {
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
