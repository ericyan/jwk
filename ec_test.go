package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

var ecdsaTestKeyP256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

func TestECDSAPublicKey(t *testing.T) {
	pub := &ecdsaTestKeyP256.PublicKey

	key, err := NewECDSAPublicKey(pub, &Params{KeyID: "foo"})
	if err != nil {
		t.Fatal("failed to create valid ECDSA public key:", err)
	}

	_, err = NewECDSAPublicKey(&ecdsa.PublicKey{}, nil)
	if err == nil {
		t.Error("excepted error on creating invalid ECDSA public key (empty crypto key)")
	}

	_, err = NewECDSAPublicKey(pub, &Params{KeyType: "invalid"})
	if err == nil {
		t.Error("excepted error on creating invalid ECDSA public key (invalid params)")
	}

	_, err = ParseECDSAPublicKey([]byte(`{"kty":"invalid"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid ECDSA public key (wrong type)")
	}

	_, err = ParseECDSAPublicKey([]byte(`{"kty":"ec", "crv":"P-256"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid ECDSA public key key (missing x, y)")
	}

	marshaled, err := json.Marshal(key)
	if err != nil {
		t.Error("failed to marshal valid ECDSA public key:", err)
	}

	parsed, err := ParseECDSAPublicKey(marshaled)
	if err != nil {
		t.Error("failed to unmarshal valid ECDSA public key:", err)
	}

	orgPub := key.CryptoKey().(*ecdsa.PublicKey)
	parsedPub := parsed.CryptoKey().(*ecdsa.PublicKey)
	if orgPub.Curve == parsedPub.Curve && orgPub.X.Cmp(parsedPub.X) != 0 && orgPub.Y.Cmp(parsedPub.Y) != 0 {
		t.Error("round-trip of RSA public key gave different raw keys")
	}
}
