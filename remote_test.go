package pasaportul

import (
	"github.com/MereleDulci/jsonapi"
	"testing"
)

func TestRemote_IssueSingleUseToken(t *testing.T) {

	t.Run("response unmarshal", func(t *testing.T) {
		input := `{"data":{"attributes":{"audience":["665c29c2054c21dcad8e913c"],"claims":{"document_id":"6668c858a691cfb3350aca0a"},"code":"271c8d4ba766","consumedAt":null,"expiresAt":"2024-06-15T09:43:55+01:00","issuedAt":"2024-06-15T08:43:55+01:00","notBefore":"2024-06-15T08:43:55+01:00"},"id":"666d463b8d85cd7955a6c35b","relationships":{"account":{"data":{"id":"665ebe22c6abd536331746d3","type":"user-accounts"}}},"type":"single-use-tokens"},"included":[{"attributes":{"metadata":null,"username":""},"id":"665ebe22c6abd536331746d3","relationships":{"serviceAccount":{"data":null}},"type":"user-accounts"}]}`

		out := SingleUseToken{}
		err := jsonapi.Unmarshal([]byte(input), &out)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if out.ID != "666d463b8d85cd7955a6c35b" {
			t.Errorf("unexpected parsed ID: %v", out.ID)
		}
		if out.Code != "271c8d4ba766" {
			t.Errorf("unexpected parsed Code: %v", out.Code)
		}
	})
}
