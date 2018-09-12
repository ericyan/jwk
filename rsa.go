package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"

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

// RSAPrivateKey represents an RSA private key, which contains
// algorithm-specific parameters defined in RFC7518, Section 6.3.2.
//
// RSAPrivate implements the Key interface.
type RSAPrivateKey struct {
	*RSAPublicKey
	D   *base64url.Value `json:"d"`
	P   *base64url.Value `json:"p"`
	Q   *base64url.Value `json:"q"`
	DP  *base64url.Value `json:"dp,omitempty"`
	DQ  *base64url.Value `json:"dq,omitempty"`
	QI  *base64url.Value `json:"qi,omitempty"`
	OTH *json.RawMessage `json:"oth,omitempty"` // multi-prime key not supported

	priv *rsa.PrivateKey
}

// NewRSAPrivateKey creates a new RSAPrivate.
func NewRSAPrivateKey(priv *rsa.PrivateKey, params *Params) (*RSAPrivateKey, error) {
	if priv == nil || priv.Validate() != nil {
		return nil, errors.New("jwk: invalid crypto key")
	}
	if len(priv.Primes) > 2 {
		return nil, errors.New("jwk: unsupported key: multi-prime RSA key")
	}

	pub, err := NewRSAPublicKey(&priv.PublicKey, params)
	if err != nil {
		return nil, err
	}

	key := &RSAPrivateKey{
		RSAPublicKey: pub,
		D:            base64url.NewBigInt(priv.D),
		P:            base64url.NewBigInt(priv.Primes[0]),
		Q:            base64url.NewBigInt(priv.Primes[1]),
		priv:         priv,
	}
	if priv.Precomputed.Dp != nil {
		key.DP = base64url.NewBigInt(priv.Precomputed.Dp)
	}
	if priv.Precomputed.Dq != nil {
		key.DQ = base64url.NewBigInt(priv.Precomputed.Dq)
	}
	if priv.Precomputed.Qinv != nil {
		key.QI = base64url.NewBigInt(priv.Precomputed.Qinv)
	}

	return key, nil
}

// ParseRSAPrivateKey parses the JSON Web Key as an RSA private key.
func ParseRSAPrivateKey(jwk []byte) (*RSAPrivateKey, error) {
	key := new(RSAPrivateKey)
	err := json.Unmarshal(jwk, key)
	if err != nil {
		return nil, err
	}

	if key.D == nil {
		return nil, errors.New("jwk: invalid JWT, missing D")
	}
	if key.P == nil {
		return nil, errors.New("jwk: invalid JWT, missing P")
	}
	if key.Q == nil {
		return nil, errors.New("jwk: invalid JWT, missing Q")
	}

	pub, err := ParseRSAPublicKey(jwk)
	if err != nil {
		return nil, err
	}
	key.RSAPublicKey = pub

	priv := &rsa.PrivateKey{
		PublicKey: *key.RSAPublicKey.pub,
		D:         key.D.BigInt(),
		Primes: []*big.Int{
			key.P.BigInt(),
			key.Q.BigInt(),
		},
	}
	if key.DP != nil {
		priv.Precomputed.Dp = key.DP.BigInt()
	}
	if key.DQ != nil {
		priv.Precomputed.Dq = key.DQ.BigInt()
	}
	if key.QI != nil {
		priv.Precomputed.Qinv = key.QI.BigInt()
	}

	if err := priv.Validate(); err != nil {
		return nil, err
	}
	key.priv = priv

	return key, nil
}

// CryptoKey returns the underlying cryptographic key.
func (key *RSAPrivateKey) CryptoKey() CryptoKey {
	return key.priv
}
