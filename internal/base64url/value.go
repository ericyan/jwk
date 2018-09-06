package base64url

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// A Value holds octets that can be serialized to a base64url-encoded
// string, without padding.
type Value struct {
	octets []byte
}

// NewValue creates a new Value.
func NewValue(data []byte) *Value {
	if data == nil {
		return nil
	}

	return &Value{data}
}

// NewBigInt creates a new Value representing an big.Int.
func NewBigInt(x *big.Int) *Value {
	return NewValue(x.Bytes())
}

// NewUint64 creates a new Value representing a uint64.
func NewUint64(x uint64) *Value {
	// Special case for 0, as big.Int use an empty byte slice (the zero
	// value to represent 0.
	if x == 0 {
		return &Value{[]byte{0}}
	}

	return NewBigInt(new(big.Int).SetUint64(x))
}

// Bytes returns the raw, unencoded octets.
func (val *Value) Bytes() []byte {
	return val.octets
}

// BigInt returns the value as a big.Int.
func (val *Value) BigInt() *big.Int {
	return new(big.Int).SetBytes(val.octets)
}

// Uint64 returns the value as a uint64.
func (val *Value) Uint64() uint64 {
	return val.BigInt().Uint64()
}

// MarshalJSON implements the json.Marshaler interface.
func (val *Value) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(val.octets))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (val *Value) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	octets, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	*val = Value{octets}
	return nil
}
