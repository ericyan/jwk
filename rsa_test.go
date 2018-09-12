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

func TestRSAPrivateKey(t *testing.T) {
	key, err := NewRSAPrivateKey(rsaTestKey, &Params{KeyID: "foo"})
	if err != nil {
		t.Fatal("failed to create valid RSA private key:", err)
	}

	_, err = NewRSAPrivateKey(&rsa.PrivateKey{}, nil)
	if err == nil {
		t.Error("excepted error on creating invalid RSA private key (empty crypto key)")
	}

	_, err = NewRSAPrivateKey(rsaTestKey, &Params{KeyType: "invalid"})
	if err == nil {
		t.Error("excepted error on creating invalid RSA private key (invalid params)")
	}

	_, err = ParseRSAPrivateKey([]byte(`{"kty":"invalid"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid RSA private key (wrong type)")
	}

	_, err = ParseRSAPrivateKey([]byte(`{"kty":"rsa", "e":"AQAB","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid RSA public key key (missing n, d, q)")
	}

	marshaled, err := json.Marshal(key)
	if err != nil {
		t.Error("failed to marshal valid RSA private key:", err)
	}

	parsed, err := ParseRSAPrivateKey(marshaled)
	if err != nil {
		t.Error("failed to unmarshal valid RSA private key:", err)
	}

	orgPriv := key.CryptoKey().(*rsa.PrivateKey)
	parsedPriv := parsed.CryptoKey().(*rsa.PrivateKey)
	if orgPriv.PublicKey.N.Cmp(parsedPriv.PublicKey.N) != 0 && orgPriv.PublicKey.E != parsedPriv.PublicKey.E &&
		orgPriv.D.Cmp(parsedPriv.D) != 0 && orgPriv.Primes[0].Cmp(parsedPriv.Primes[0]) != 0 && orgPriv.Primes[1].Cmp(parsedPriv.Primes[1]) != 0 {
		t.Error("round-trip of RSA private key gave different raw keys")
	}
}
