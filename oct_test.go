package jwk

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOctetSequenceKey(t *testing.T) {
	key, err := NewOctetSequenceKey([]byte{1, 2, 3, 4}, &Params{KeyID: "foo"})
	if err != nil {
		t.Fatal("failed to create valid oct key:", err)
	}

	_, err = NewOctetSequenceKey([]byte{}, nil)
	if err == nil {
		t.Error("excepted error on creating invalid oct key (empty crypto key)")
	}

	_, err = NewOctetSequenceKey([]byte{1, 2, 3, 4}, &Params{KeyType: "invalid"})
	if err == nil {
		t.Error("excepted error on creating invalid oct key (invalid params)")
	}

	_, err = ParseOctetSequenceKey([]byte(`{"kty":"invalid"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid oct key (wrong type)")
	}

	_, err = ParseOctetSequenceKey([]byte(`{"kty":"oct"}`))
	if err == nil {
		t.Error("excepted error on parsing invalid oct key (missing k)")
	}

	marshaled, err := json.Marshal(key)
	if err != nil {
		t.Error("failed to marshal valid oct key:", err)
	}

	parsed, err := ParseOctetSequenceKey(marshaled)
	if err != nil {
		t.Error("failed to unmarshal valid oct key:", err)
	}

	if !bytes.Equal(key.CryptoKey().([]byte), parsed.CryptoKey().([]byte)) {
		t.Error("round-trip of oct key gave different raw keys")
	}
}
