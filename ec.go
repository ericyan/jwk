package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ericyan/jwk/internal/base64url"
)

// ECDSAPublicKey represents an ECDSA public key, which contains
// algorithm-specific parameters defined in RFC7518, Section 6.2.1.
//
// ECDSAPublicKey implements the Key interface.
type ECDSAPublicKey struct {
	*Params
	CRV string           `json:"crv"`
	X   *base64url.Value `json:"x"`
	Y   *base64url.Value `json:"y"`

	pub *ecdsa.PublicKey
}

// NewECDSAPublicKey creates a new ECDSAPublicKey.
func NewECDSAPublicKey(pub *ecdsa.PublicKey, params *Params) (*ECDSAPublicKey, error) {
	if params == nil {
		params = &Params{KeyType: TypeEC}
	}
	if params.KeyType == "" {
		params.KeyType = TypeEC
	}
	if params.KeyType != TypeEC {
		return nil, errors.New("jwk: invalid params, wrong key type")
	}

	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, errors.New("jwk: invalid crypto key")
	}

	var crv string
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, fmt.Errorf("jwk: unsupported elliptic curve")
	}

	return &ECDSAPublicKey{
		params,
		crv,
		base64url.NewBigInt(pub.X),
		base64url.NewBigInt(pub.Y),
		pub,
	}, nil
}

// ParseECDSAPublicKey parses the JSON Web Key as an ECDSA public key.
func ParseECDSAPublicKey(jwk []byte) (*ECDSAPublicKey, error) {
	key := new(ECDSAPublicKey)
	err := json.Unmarshal(jwk, key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != TypeEC {
		return nil, errors.New("jwk: invalid JWT, wrong type")
	}
	if key.X == nil {
		return nil, errors.New("jwk: invalid JWT, missing N")
	}
	if key.Y == nil {
		return nil, errors.New("jwk: invalid JWT, missing E")
	}

	var curve elliptic.Curve
	switch key.CRV {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwk: unsupported elliptic curve")
	}

	key.pub = &ecdsa.PublicKey{
		Curve: curve,
		X:     key.X.BigInt(),
		Y:     key.Y.BigInt(),
	}

	return key, nil
}

// CryptoKey returns the underlying cryptographic key.
func (key *ECDSAPublicKey) CryptoKey() CryptoKey {
	return key.pub
}

// ECDSAPrivateKey represents an ECDSA private key, which contains
// algorithm-specific parameters defined in RFC 7518, Section 6.2.2.
//
// ECDSAPrivate implements the Key interface.
type ECDSAPrivateKey struct {
	*ECDSAPublicKey
	D *base64url.Value `json:"d"`

	priv *ecdsa.PrivateKey
}

// NewECDSAPrivateKey creates a new ECDSAPrivate.
func NewECDSAPrivateKey(priv *ecdsa.PrivateKey, params *Params) (*ECDSAPrivateKey, error) {
	if priv == nil {
		return nil, errors.New("jwk: invalid crypto key")
	}

	pub, err := NewECDSAPublicKey(&priv.PublicKey, params)
	if err != nil {
		return nil, err
	}

	key := &ECDSAPrivateKey{
		ECDSAPublicKey: pub,
		D:              base64url.NewBigInt(priv.D),
		priv:           priv,
	}

	return key, nil
}

// ParseECDSAPrivateKey parses the JSON Web Key as an ECDSA private key.
func ParseECDSAPrivateKey(jwk []byte) (*ECDSAPrivateKey, error) {
	key := new(ECDSAPrivateKey)
	err := json.Unmarshal(jwk, key)
	if err != nil {
		return nil, err
	}

	if key.D == nil {
		return nil, errors.New("jwk: invalid JWT, missing D")
	}

	pub, err := ParseECDSAPublicKey(jwk)
	if err != nil {
		return nil, err
	}
	key.ECDSAPublicKey = pub

	priv := &ecdsa.PrivateKey{
		PublicKey: *key.ECDSAPublicKey.pub,
		D:         key.D.BigInt(),
	}
	key.priv = priv

	return key, nil
}

// CryptoKey returns the underlying cryptographic key.
func (key *ECDSAPrivateKey) CryptoKey() CryptoKey {
	return key.priv
}
