package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

var rsaTestKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func TestRSAPublicKey(t *testing.T) {
	key, err := NewRSAPublicKey(&rsaTestKey.PublicKey, &Params{KeyID: "foo"})
	if err != nil {
		t.Fatal("failed to create valid RSA public key:", err)
	}

	_, err = NewRSAPublicKey(&rsa.PublicKey{}, nil)
	if err == nil {
		t.Error("excepted error on creating invalid RSA public key (empty crypto key)")
	}

	_, err = NewRSAPublicKey(&rsaTestKey.PublicKey, &Params{KeyType: "invalid"})
	if err == nil {
		t.Error("excepted error on creating invalid RSA public key (invalid params)")
	}

	_, err = ParseRSAPublicKey([]byte(`{"kty":"invalid"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid RSA public key (wrong type)")
	}

	_, err = ParseRSAPublicKey([]byte(`{"kty":"rsa", "e":"AQAB"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid RSA public key key (missing n)")
	}

	marshaled, err := json.Marshal(key)
	if err != nil {
		t.Error("failed to marshal valid RSA public key:", err)
	}

	parsed, err := ParseRSAPublicKey(marshaled)
	if err != nil {
		t.Error("failed to unmarshal valid RSA public key:", err)
	}

	if key.CryptoKey().(*rsa.PublicKey).N.Cmp(parsed.CryptoKey().(*rsa.PublicKey).N) != 0 &&
		key.CryptoKey().(*rsa.PublicKey).E != parsed.CryptoKey().(*rsa.PublicKey).E {
		t.Error("round-trip of RSA public key gave different raw keys")
	}
}
