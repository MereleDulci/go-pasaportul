package pasaportul

import (
	"encoding/json"
	"fmt"
	"github.com/cristalhq/jwt/v5"
	"reflect"
	"testing"
)

func TestExtraClaims_MarshalJSON(t *testing.T) {
	t.Run("should encode to valid empty json map", func(t *testing.T) {
		extras := ExtraClaims{}

		raw, err := json.Marshal(extras)
		if err != nil {
			t.Fatal(err)
		}

		if string(raw) != "{}" {
			t.Fatalf("expected empty object, got %v", raw)
		}
	})

	t.Run("should correctly encode string value", func(t *testing.T) {
		extras := ExtraClaims{
			values: map[string]interface{}{
				"key": "value",
			},
		}

		raw, err := json.Marshal(&extras)
		if err != nil {
			t.Fatal(err)
		}

		if string(raw) != `{"key":"value"}` {
			t.Fatalf("expected {\"key\":\"value\"}, got %s", string(raw))
		}
	})

	t.Run("should correctly encode numbers", func(t *testing.T) {
		extras := ExtraClaims{
			values: map[string]interface{}{
				"key": 1,
			},
		}

		raw, err := json.Marshal(extras)
		if err != nil {
			t.Fatal(err)
		}

		if string(raw) != `{"key":1}` {
			t.Fatalf("expected {\"key\":1}, got %s", string(raw))
		}
	})
}

func TestExtraClaims_UnmarshalJSON(t *testing.T) {
	t.Run("should correctly decode empty object", func(t *testing.T) {
		input := "{}"

		extras := ExtraClaims{}
		err := json.Unmarshal([]byte(input), &extras)
		if err != nil {
			t.Fatal(err)
		}

		if len(extras.values) != 0 {
			t.Fatalf("expected empty map, got %v", extras.values)
		}
	})

	t.Run("should correctly decode string value", func(t *testing.T) {
		input := `{"key":"value"}`

		extras := ExtraClaims{}
		err := json.Unmarshal([]byte(input), &extras)
		if err != nil {
			t.Fatal(err)
		}

		if len(extras.values) != 1 {
			t.Fatalf("expected 1 key, got %v", extras.values)
		}

		if extras.values["key"] != "value" {
			t.Fatalf("expected value, got %v", extras.values["key"])
		}
	})

	t.Run("should correctly decode number value", func(t *testing.T) {
		input := `{"key":1}`

		extras := ExtraClaims{}
		err := json.Unmarshal([]byte(input), &extras)
		if err != nil {
			t.Fatal(err)
		}

		if len(extras.values) != 1 {
			t.Fatalf("expected 1 key, got %v", extras.values)
		}

		if extras.values["key"] != float64(1) {
			t.Fatalf("expected 1, got %v %v", extras.values["key"], reflect.TypeOf(extras.values["key"]))
		}
	})
}

func TestTokenClaims_MarshalJSON(t *testing.T) {
	t.Run("should correctly compose registered and custom claims", func(t *testing.T) {
		tok := TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID: "1",
			},
			ExtraClaims: ExtraClaims{
				values: map[string]interface{}{
					"str":   "value",
					"float": 1,
				},
			},
		}

		raw, err := json.Marshal(tok)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(string(raw))

	})
}

func TestTokenClaims_RegisteredClaims(t *testing.T) {
	t.Run("should expose access to the underlying registered claims methods", func(t *testing.T) {
		tok := TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:      "1",
				Subject: "subj",
			},
		}

		if tok.IsSubject("subj") != true {
			t.Fatalf("expected true, got false")
		}
	})
}
