package jwk

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRFC7517ExampleSets(t *testing.T) {
	// Test vectors from Appendix A of RFC 7517
	cases := []struct {
		jwks   string
		params []Params
	}{
		{
			jwks: `{"keys":
				[
					{"kty":"oct",
					"alg":"A128KW",
					"k":"GawgguFyGrWKav7AX4VKUg"},

					{"kty":"oct",
					"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
					"kid":"HMAC key used in JWS spec Appendix A.1 example"}
				]
			}`,
			params: []Params{
				Params{KeyType: TypeOCT, Algorithm: "A128KW"},
				Params{KeyType: TypeOCT, KeyID: "HMAC key used in JWS spec Appendix A.1 example"},
			},
		},
	}

	for _, c := range cases {
		var jwks Set
		err := json.Unmarshal([]byte(c.jwks), &jwks)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		if len(jwks.Keys) != len(c.params) {
			t.Fatalf("set length mismatch")
		}
		for i, params := range c.params {
			switch key := jwks.Keys[i].(type) {
			case *OctetSequenceKey:
				if key.KeyType != params.KeyType {
					t.Fatalf("key type mismatch: want %s, got %s", key.KeyType, params.KeyType)
				}
				if params.Algorithm != "" && key.Algorithm != params.Algorithm {
					t.Fatalf("key algorithm mismatch: want %s, got %s", key.Algorithm, params.Algorithm)
				}
				if params.KeyID != "" && key.KeyID != params.KeyID {
					t.Fatalf("key ID mismatch: want %s, got %s", key.KeyID, params.KeyID)
				}
			default:
				t.Error("unsupported key type:", reflect.TypeOf(jwks.Keys[i]))
			}
		}
	}
}
