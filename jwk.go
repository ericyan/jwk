package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON Web Key types defined in RFC7518, Section 6.
const (
	TypeEC  = "EC"
	TypeRSA = "RSA"
	TypeOCT = "oct"
)

// CryptoKey represents a cryptographic key using an unspecified algorithm.
type CryptoKey interface{}

// Params contains common JSON Web Key parameters.
type Params struct {
	KeyType   string   `json:"kty"`
	KeyUse    string   `json:"use,omitempty"`
	KeyOps    []string `json:"key_ops,omitempty"`
	Algorithm string   `json:"alg,omitempty"`
	KeyID     string   `json:"kid,omitempty"`
}

// ID returns the key ID parameter.
func (p *Params) ID() string {
	return p.KeyID
}

// Key represents a JSON Web Key.
type Key interface {
	ID() string
	CryptoKey() CryptoKey
}

// New creates a new Key.
func New(key CryptoKey, params *Params) (Key, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return NewRSAPublicKey(k, params)
	case []byte:
		return NewOctetSequenceKey(k, params)
	default:
		return nil, errors.New("jwk: unsupported crypto key")
	}
}

// Parse parses data as a JSON Web Key.
func Parse(data []byte) (Key, error) {
	var params Params
	err := json.Unmarshal(data, &params)
	if err != nil {
		return nil, err
	}

	switch params.KeyType {
	case TypeRSA:
		// FIXME: handle private keys as well
		return ParseRSAPublicKey(data)
	case TypeOCT:
		return ParseOctetSequenceKey(data)
	default:
		return nil, fmt.Errorf("jwk: unsupported key type '%s'", params.KeyType)
	}
}

// Set represents a JSON Web Key Set.
type Set struct {
	Keys []Key `json:"keys"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *Set) UnmarshalJSON(data []byte) error {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	keys := make([]Key, len(raw.Keys))
	for i, jwk := range raw.Keys {
		key, err := Parse(jwk)
		if err != nil {
			return err
		}

		keys[i] = key
	}

	s.Keys = keys
	return nil
}
