package pasaportul

import (
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v5"
	"maps"
)

type ExtraClaims struct {
	values map[string]interface{}
}

func (ec ExtraClaims) MarshalJSON() ([]byte, error) {
	if ec.values == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(ec.values)
}

func (ec *ExtraClaims) UnmarshalJSON(data []byte) error {
	ec.values = make(map[string]interface{})
	return json.Unmarshal(data, &ec.values)
}

type TokenClaims struct {
	jwt.RegisteredClaims
	ExtraClaims
}

func (tc TokenClaims) MarshalJSON() ([]byte, error) {
	defaultClaimsStr, err := json.Marshal(tc.RegisteredClaims)
	if err != nil {
		return nil, fmt.Errorf("marshalling registered claims: %w", err)
	}
	decodedDefault := map[string]interface{}{}
	err = json.Unmarshal(defaultClaimsStr, &decodedDefault)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling registered claims: %w", err)
	}

	maps.Copy(decodedDefault, tc.ExtraClaims.values)
	return json.Marshal(decodedDefault)
}

func (tc *TokenClaims) UnmarshalJSON(data []byte) error {
	decodedRegistered := jwt.RegisteredClaims{}
	if err := json.Unmarshal(data, &decodedRegistered); err != nil {
		return fmt.Errorf("unmarshaling registered claims: %w", err)
	}

	decodedMap := map[string]interface{}{}
	if err := json.Unmarshal(data, &decodedMap); err != nil {
		return fmt.Errorf("unmarshaling custom claims: %w", err)

	}
	tc.RegisteredClaims = decodedRegistered
	tc.ExtraClaims.values = decodedMap

	return nil
}
