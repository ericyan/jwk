package jwk

import (
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
	case TypeOCT:
		return ParseOctetSequenceKey(data)
	default:
		return nil, fmt.Errorf("jwk: unsupported key type '%s'", params.KeyType)
	}
}
