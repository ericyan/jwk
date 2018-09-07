package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"errors"

	"github.com/ericyan/jwk/internal/base64url"
)

// RSAPublicKey represents an RSA public key, which contains
// algorithm-specific parameters defined in RFC7518, Section 6.3.1.
//
// RSAPublicKey implements the Key interface.
type RSAPublicKey struct {
	*Params
	N *base64url.Value `json:"n"`
	E *base64url.Value `json:"e"`

	pub *rsa.PublicKey
}

// NewRSAPublicKey creates a new RSAPublicKey.
func NewRSAPublicKey(pub *rsa.PublicKey, params *Params) (*RSAPublicKey, error) {
	if params == nil {
		params = &Params{KeyType: TypeRSA}
	}
	if params.KeyType == "" {
		params.KeyType = TypeRSA
	}
	if params.KeyType != TypeRSA {
		return nil, errors.New("jwk: invalid params, wrong key type")
	}

	// Sanity checks for the public key
	if pub.N == nil || pub.E < 2 || pub.E > 1<<31-1 {
		return nil, errors.New("jwk: invalid crypto key")
	}

	return &RSAPublicKey{
		params,
		base64url.NewBigInt(pub.N),
		base64url.NewUint64(uint64(pub.E)),
		pub,
	}, nil
}

// ParseRSAPublicKey parses the JSON Web Key as an RSA public key.
func ParseRSAPublicKey(jwk []byte) (*RSAPublicKey, error) {
	key := new(RSAPublicKey)
	err := json.Unmarshal(jwk, key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != TypeRSA {
		return nil, errors.New("jwk: invalid JWT, wrong type")
	}
	if key.N == nil {
		return nil, errors.New("jwk: invalid JWT, missing N")
	}
	if key.E == nil {
		return nil, errors.New("jwk: invalid JWT, missing E")
	}

	key.pub = &rsa.PublicKey{
		N: key.N.BigInt(),
		E: int(key.E.Uint64()),
	}

	return key, nil
}

// CryptoKey returns the underlying cryptographic key.
func (key *RSAPublicKey) CryptoKey() CryptoKey {
	return key.pub
}
