package jwk

import (
	"encoding/json"
	"errors"

	"github.com/ericyan/jwk/internal/base64url"
)

// OctetSequenceKey represents an octet sequence key, which contains
// algorithm-specific parameters defined in RFC7518, Section 6.4.
//
// OctetSequenceKey implements the Key interface.
type OctetSequenceKey struct {
	*Params
	K *base64url.Value `json:"k"`
}

// NewOctetSequenceKey creates a new OctetSequenceKey.
func NewOctetSequenceKey(key []byte, params *Params) (*OctetSequenceKey, error) {
	if params == nil {
		params = &Params{KeyType: TypeOCT}
	}
	if params.KeyType == "" {
		params.KeyType = TypeOCT
	}

	if len(key) == 0 {
		return nil, errors.New("jwk: invalid crypto key, zero length")
	}
	if params.KeyType != TypeOCT {
		return nil, errors.New("jwk: invalid params, wrong key type")
	}

	return &OctetSequenceKey{params, base64url.NewValue(key)}, nil
}

// Parse parses the JSON Web Key as an octet sequence key.
func ParseOctetSequenceKey(jwk []byte) (*OctetSequenceKey, error) {
	key := new(OctetSequenceKey)
	err := json.Unmarshal(jwk, key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != TypeOCT {
		return nil, errors.New("jwk: invalid JWT, wrong type")
	}
	if key.K == nil {
		return nil, errors.New("jwk: invalid JWT, missing k")
	}

	return key, nil
}

// CryptoKey returns the underlying cryptographic key.
func (key *OctetSequenceKey) CryptoKey() CryptoKey {
	return key.K.Bytes()
}
